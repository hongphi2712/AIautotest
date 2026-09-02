//! One-off diagnostic: scans the full flow history in a COPY of the live
//! SQLite database through the production analysis pipeline (SecretScanner =
//! gitleaks CLI + built-in regex + CWE detector, merged with OverfetchingAnalyzer),
//! then re-scans to demonstrate cache warmth.
//!
//! Usage:
//!   cargo run --release -p api-tester-server --example db_secret_scan
//!   ... --path <substring> | --find <needle> | --tail <substring>
//!   ... --file <response-body-file>   (repeatable, e.g. replayed page dumps)

use std::path::PathBuf;
use std::time::Instant;

use api_tester_analysis::{OverfetchingAnalyzer, SecretScanner};
use api_tester_domain::{HttpFlow, HttpMethod};
use api_tester_storage::SqliteStore;

const DB_SOURCE: &str = "api-tester.db";
const SCAN_LIMIT: u64 = 5000;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let home = std::env::var("USERPROFILE").unwrap_or_default();
    let source = PathBuf::from(&home).join(".api-tester").join(DB_SOURCE);
    if !source.is_file() {
        return Err(format!("database not found: {}", source.display()).into());
    }

    // Work on a copy so the running server's database is never touched.
    let target_dir = std::env::temp_dir().join("opencode");
    std::fs::create_dir_all(&target_dir)?;
    let copy = target_dir.join("db_secret_scan_copy.db");
    std::fs::copy(&source, &copy)?;

    println!("DB: {} -> {}", source.display(), copy.display());

    let store = SqliteStore::open(&format!("sqlite://{}", copy.display())).await?;
    let total = store.flows().count().await?;
    let flows = store.flows().list_recent(SCAN_LIMIT).await?;
    println!(
        "flows in db: {total}, loaded: {} (limit {SCAN_LIMIT})",
        flows.len()
    );

    // Optional path substring filter: --path <substring> prints per-flow detail.
    let args: Vec<String> = std::env::args().collect();
    let arg_value = |flag: &str| {
        args.iter()
            .position(|arg| arg == flag)
            .and_then(|index| args.get(index + 1))
    };
    let path_filter = arg_value("--path");

    // --file <path> (repeatable): scan replayed response bodies as pseudo-flows
    // alongside DB history so freshly fetched pages join the same report.
    let mut flows = flows;
    for file_arg in args.windows(2).filter(|pair| pair[0] == "--file") {
        let path = PathBuf::from(&file_arg[1]);
        let Ok(content) = std::fs::read_to_string(&path) else {
            return Err(format!("cannot read --file {}", path.display()).into());
        };
        let label = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("unknown")
            .to_owned();
        println!(
            "extra file: {} -> [file] {label} ({} bytes)",
            path.display(),
            content.len()
        );
        flows.push(HttpFlow {
            method: HttpMethod::Get,
            path: format!("[file] {label}"),
            full_url: format!("[file] {label}"),
            response_body: Some(content),
            response_body_len: 0,
            content_type: "text/x-component".to_owned(),
            ..HttpFlow::default()
        });
    }

    // --find <needle>: locate a raw substring across every stored surface
    // (response body, both header maps, cookies) to answer "is X really absent?"
    // --tail <path-substring>: completeness check — captured length field vs
    // stored body length, plus the raw tail to see if the stream ends cleanly.
    if let Some(filter) = arg_value("--tail") {
        println!("\n=== TAIL CHECK for paths containing '{filter}' ===");
        for flow in &flows {
            if !flow.path.contains(filter.as_str()) {
                continue;
            }
            let Some(body) = flow.response_body.as_deref() else {
                println!("{} {} -> no body stored", flow.method.as_str(), flow.path);
                continue;
            };
            let mut tail_start = body.len().saturating_sub(200);
            while !body.is_char_boundary(tail_start) {
                tail_start += 1;
            }
            let tail = &body[tail_start..];
            let truncated_flag = flow.response_body_len != body.len();
            println!(
                "{} {} | captured_len={} stored_len={} mismatch={truncated_flag}",
                flow.method.as_str(),
                flow.path,
                flow.response_body_len,
                body.len()
            );
            println!("tail: ...{}...", tail.replace('\n', "\\n"));
        }
        return Ok(());
    }

    if let Some(needle) = arg_value("--find") {
        println!("\n=== FLOW SEARCH for '{needle}' ===");
        let mut hits = 0usize;
        for flow in &flows {
            let mut surfaces: Vec<(&str, usize)> = Vec::new();
            if let Some(body) = flow.response_body.as_deref() {
                let count = body.matches(needle.as_str()).count();
                if count > 0 {
                    surfaces.push(("body", count));
                }
            }
            for value in flow.request_headers.values() {
                let count = value.matches(needle.as_str()).count();
                if count > 0 {
                    surfaces.push(("req-header", count));
                }
            }
            for (_name, value) in flow.response_headers.iter() {
                let count = value.matches(needle.as_str()).count();
                if count > 0 {
                    surfaces.push(("res-header", count));
                }
            }
            let cookie_hits = flow
                .request_cookies
                .iter()
                .chain(flow.response_cookies.iter())
                .filter(|cookie| cookie.contains(needle.as_str()))
                .count();
            if cookie_hits > 0 {
                surfaces.push(("cookies", cookie_hits));
            }
            if !surfaces.is_empty() {
                hits += 1;
                println!("{} {} -> {:?}", flow.method.as_str(), flow.path, surfaces);
            }
        }
        println!("flows containing '{needle}': {hits}/{total}");
        return Ok(());
    }

    if let Some(filter) = path_filter {
        println!("\n=== DETAIL for paths containing '{filter}' ===");
        for flow in &flows {
            if !flow.path.contains(filter.as_str()) {
                continue;
            }
            let body = flow.response_body.as_deref().unwrap_or("");
            let result = SecretScanner::analyze(body);
            println!(
                "{} {} | status {} | {} bytes | ct '{}' | signals: {:?}",
                flow.method.as_str(),
                flow.path,
                flow.response_status,
                body.len(),
                if flow.content_type.is_empty() {
                    "<none>"
                } else {
                    &flow.content_type
                },
                result.summary_signals,
            );
        }
        // Deep-dive the largest matching body: keyword census + raw excerpts
        // so a silent miss (no signals but secrets present) is visible.
        if let Some(biggest) = flows
            .iter()
            .filter(|flow| flow.path.contains(filter.as_str()))
            .max_by_key(|flow| flow.response_body.as_deref().map_or(0, str::len))
        {
            let body = biggest.response_body.as_deref().unwrap_or("");
            println!(
                "\n=== DEEP-DIVE {} {} ({} bytes) ===",
                biggest.method.as_str(),
                biggest.path,
                body.len()
            );
            let lowered = body.to_lowercase();
            for keyword in [
                "eyJ",       // JWT first-segment prefix
                "\"token\"", // token fields
                "password",
                "secret",
                "api_key",
                "apikey",
                "bearer ",
                "\"email\"",
                "authorization",
            ] {
                let count = lowered.matches(keyword).count();
                if count > 0 {
                    println!("keyword {keyword:?}: {count} occurrence(s)");
                }
            }

            // Context around every 'password' occurrence — distinguishes real
            // credential leaks from harmless field names like hasPassword.
            println!("\n-- 'password' contexts --");
            let mut seen_contexts = Vec::new();
            let mut search_from = 0usize;
            while let Some(offset) = lowered[search_from..].find("password") {
                let position = search_from + offset;
                search_from = position + 8;
                let mut start = position.saturating_sub(50);
                let mut end = (position + 60).min(body.len());
                while !body.is_char_boundary(start) {
                    start -= 1;
                }
                while end < body.len() && !body.is_char_boundary(end) {
                    end += 1;
                }
                let context = body[start..end].replace('\n', "\\n");
                if !seen_contexts.iter().any(|seen: &String| {
                    seen.trim_matches(|c: char| c.is_alphanumeric() || c == '"')
                        == context.trim_matches(|c: char| c.is_alphanumeric() || c == '"')
                }) && seen_contexts.len() < 12
                {
                    seen_contexts.push(context.clone());
                    println!("  ...{context}...");
                }
            }

            // Production also runs the overfetching analyzer next to the
            // secret scanner; show its verdict for parity.
            let overfetch = api_tester_analysis::OverfetchingAnalyzer::analyze_with(
                body,
                Some(&biggest.content_type),
            );
            println!(
                "\noverfetching: suspicious={} signals={:?}",
                overfetch.is_suspicious, overfetch.detected_signals
            );
            if let Some(position) = lowered.find("eyJ") {
                let mut start = position.saturating_sub(60);
                let mut end = (position + 140).min(body.len());
                while !body.is_char_boundary(start) {
                    start -= 1;
                }
                while end < body.len() && !body.is_char_boundary(end) {
                    end += 1;
                }
                println!("\nexcerpt around first 'eyJ':");
                println!("{}", &body[start..end]);
            }
        }
        let _ = std::fs::remove_file(&copy);
        return Ok(());
    }

    let mut cold_start = Instant::now();
    let mut scanned = 0usize;
    let mut skipped_no_body = 0usize;
    let mut suspicious = 0usize;
    let mut signal_counts: std::collections::BTreeMap<String, usize> = Default::default();
    let mut gitleaks_hits: Vec<(String, String, String)> = Vec::new();
    let mut findings: Vec<(String, usize, Vec<String>)> = Vec::new();

    for flow in &flows {
        let Some(body) = flow.response_body.as_deref() else {
            skipped_no_body += 1;
            continue;
        };
        scanned += 1;

        // Production parity (serialization.rs): secret + overfetching signals
        // are merged into one summary per response.
        let security = SecretScanner::analyze(body);
        let overfetch = OverfetchingAnalyzer::analyze_with(body, Some(&flow.content_type));
        let mut merged = security.summary_signals.clone();
        merged.extend(overfetch.detected_signals.iter().cloned());
        merged.sort();
        merged.dedup();

        if !merged.is_empty() {
            suspicious += 1;
            let label = format!("{} {}", flow.method.as_str(), flow.path);
            for signal in &merged {
                *signal_counts.entry(signal.clone()).or_default() += 1;
            }
            for finding in &security.gitleaks_findings {
                gitleaks_hits.push((
                    label.clone(),
                    finding.rule_id.clone(),
                    format!("line {}", finding.start_line),
                ));
            }
            findings.push((label, body.len(), merged));
        }
    }
    let cold_elapsed = cold_start.elapsed();
    cold_start = Instant::now();

    // Warm pass: bodies are memoized; only the regex-side reruns.
    for flow in &flows {
        if let Some(body) = flow.response_body.as_deref() {
            let _ = OverfetchingAnalyzer::analyze_with(body, Some(&flow.content_type));
        }
    }
    let warm_elapsed = cold_start.elapsed();

    println!("\n=== FULL FLOW REPORT ===");
    println!("scanned: {scanned} (skipped no-body: {skipped_no_body})");
    println!("suspicious items: {suspicious}");
    println!("cold pass: {cold_elapsed:?} | warm pass: {warm_elapsed:?}");

    println!("\n-- signals by type --");
    for (signal, count) in &signal_counts {
        println!("{signal}: {count}");
    }

    println!("\n-- findings detail --");
    for (label, size, signals) in &findings {
        println!("{label} ({size}B)");
        for signal in signals {
            println!("   - {signal}");
        }
    }

    println!("\n-- gitleaks hits --");
    for (target, rule, line) in gitleaks_hits.iter().take(40) {
        println!("[{rule}] {target} ({line})");
    }
    if gitleaks_hits.len() > 40 {
        println!("... and {} more", gitleaks_hits.len() - 40);
    }

    let _ = std::fs::remove_file(&copy);
    Ok(())
}
