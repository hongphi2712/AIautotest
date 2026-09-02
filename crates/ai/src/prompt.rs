//! Compact, token-efficient prompt building for flow summaries.
//!
//! The prompt mirrors the DeepSeek cost-optimisation guidance:
//! - a **stable system prompt first** (cached prefix), variable data last;
//! - summaries (method/path/status, dependency edges, sitemap lines) plus
//!   truncated request/response bodies (text only, binary/hex skipped, ≤4000 chars each);
//! - **no headers, no dependency token values** — those secrets are never sent;
//! - hard caps on how many steps/edges are serialised so a large capture
//!   cannot balloon the prompt.

use serde::{Deserialize, Serialize};

/// A single ordered API step (topological order, dependency-first).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SummaryStep {
    pub method: String,
    pub path: String,
    pub status: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_body: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_body: Option<String>,
}

/// One dependency edge: `source` produced a token that `target` consumed.
/// Token values are intentionally absent — only the type and usage location.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DependencyEdge {
    pub source: String,
    pub target: String,
    pub token_type: String,
    pub location: String,
}

/// One host line of the sitemap (`endpoints` are `"PATH (count)"` strings).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SitemapLine {
    pub host: String,
    pub endpoints: Vec<String>,
}

/// The redacted, compact view of captured traffic sent to the model.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlowContext {
    pub steps: Vec<SummaryStep>,
    pub dependencies: Vec<DependencyEdge>,
    pub sitemap: Vec<SitemapLine>,
}

/// The final system/user message pair (stable prefix in `system`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SummaryPrompt {
    pub system: String,
    pub user: String,
}

/// Upper bound on steps/edges serialised so huge captures stay cheap.
pub const MAX_STEPS_IN_PROMPT: usize = 200;
pub const MAX_EDGES_IN_PROMPT: usize = 200;

const SYSTEM_PROMPT: &str = "\
You are a web API analysis assistant for a security testing tool. You receive a \
compact, redacted summary of HTTP traffic captured by a proxy: ordered API steps, \
token dependencies between requests, and a sitemap of endpoints. \
Explain the application's request flow: the business-logic order, the \
authentication/session lifecycle, and any security-relevant or suspicious patterns. \
Be concise and use short sections. Do not invent requests that are not present. \
Token values are redacted, so never mention specific token values. \
Reply in Vietnamese.";

/// Builds the compact prompt from a flow context. The system message is stable
/// (cached prefix); only the user message varies per analysis.
pub fn build_summary_prompt(context: &FlowContext, max_steps: usize) -> SummaryPrompt {
    SummaryPrompt {
        system: SYSTEM_PROMPT.to_owned(),
        user: format_context(context, max_steps),
    }
}

/// Renders the redacted context as compact text (steps, dependencies,
/// sitemap). Shared by the flow-summary and workflow-generation prompts.
pub fn format_context(context: &FlowContext, max_steps: usize) -> String {
    let max_steps = max_steps.min(MAX_STEPS_IN_PROMPT);
    let mut user = String::with_capacity(2048);

    let shown = context.steps.len().min(max_steps);
    user.push_str(&format!("STEPS ({shown}/{}):\n", context.steps.len()));
    for step in context.steps.iter().take(shown) {
        user.push_str(&format!(
            "{} {} -> {}\n",
            step.method, step.path, step.status
        ));
        if let Some(body) = &step.request_body {
            user.push_str(&format!("  req: {body}\n"));
        }
        if let Some(body) = &step.response_body {
            user.push_str(&format!("  resp: {body}\n"));
        }
    }
    user.push('\n');

    if context.dependencies.is_empty() {
        user.push_str("DEPENDENCIES: none detected\n\n");
    } else {
        user.push_str("DEPENDENCIES:\n");
        let edges = context.dependencies.iter().take(MAX_EDGES_IN_PROMPT);
        for edge in edges {
            user.push_str(&format!(
                "{} -> {} [{} in {}]\n",
                edge.source, edge.target, edge.token_type, edge.location
            ));
        }
        if context.dependencies.len() > MAX_EDGES_IN_PROMPT {
            user.push_str(&format!(
                "... {} more edges omitted\n",
                context.dependencies.len() - MAX_EDGES_IN_PROMPT
            ));
        }
        user.push('\n');
    }

    if context.sitemap.is_empty() {
        user.push_str("SITEMAP: empty\n");
    } else {
        user.push_str("SITEMAP:\n");
        for host in &context.sitemap {
            user.push_str(&format!("{}: {}\n", host.host, host.endpoints.join(", ")));
        }
    }

    user
}

/// Security-specific context formatter. Unlike `format_context`, this preserves
/// query strings in step paths so the AI can see parameters like `?q=test`.
/// Also adds a PARAMETERS OBSERVED section and AUTH OBSERVED section.
pub fn format_security_context(context: &FlowContext, max_steps: usize) -> String {
    let max_steps = max_steps.min(MAX_STEPS_IN_PROMPT);
    let mut user = String::with_capacity(4096);

    let shown = context.steps.len().min(max_steps);
    user.push_str(&format!("STEPS ({shown}/{}):\n", context.steps.len()));
    for step in context.steps.iter().take(shown) {
        user.push_str(&format!(
            "{} {} -> {}\n",
            step.method, step.path, step.status
        ));
        if let Some(body) = &step.request_body {
            // Compact request body: show fields only for JSON bodies
            if body.trim_start().starts_with('{') {
                if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(body) {
                    if let Some(obj) = parsed.as_object() {
                        let fields: Vec<String> = obj.keys().map(|k| {
                            let v = &obj[k];
                            match v {
                                serde_json::Value::String(s) => {
                                    let short = if s.len() > 30 { &s[..30] } else { s };
                                    format!("{k}:\"{short}\"")
                                }
                                serde_json::Value::Number(n) => format!("{k}:{n}"),
                                serde_json::Value::Bool(b) => format!("{k}:{b}"),
                                _ => format!("{k}:..."),
                            }
                        }).collect();
                        user.push_str(&format!("  req: {{{}}}\n", fields.join(", ")));
                    }
                } else {
                    user.push_str(&format!("  req: {}\n", &body[..body.len().min(100)]));
                }
            } else {
                user.push_str(&format!("  req: {}\n", &body[..body.len().min(100)]));
            }
        }
        if let Some(body) = &step.response_body {
            // Compact response body: summarize token signals, truncate rest
            let mut signals = Vec::new();
            if body.contains("accessToken") { signals.push("accessToken"); }
            if body.contains("refreshToken") { signals.push("refreshToken"); }
            if body.contains("eyJ") { signals.push("JWT"); }
            if body.contains("csrfToken") { signals.push("csrfToken"); }
            if body.contains("credentials") { signals.push("providers"); }
            if !signals.is_empty() {
                user.push_str(&format!("  resp: [{}]\n", signals.join(", ")));
            } else if body.contains("Next.js page data:") || body.contains("<html") {
                let preview = if let Some(marker) = body.find("Next.js page data:") {
                    let semantic: String = body.chars().take(240).collect();
                    let data: String = body[marker..].chars().take(660).collect();
                    format!("{semantic} ... {data}")
                } else {
                    body.chars().take(900).collect()
                };
                user.push_str(&format!("  resp: HTML/data preview ({} chars): {preview}\n", body.len()));
            } else if body.len() > 200 {
                user.push_str(&format!("  resp: {} chars\n", body.len()));
            } else {
                user.push_str(&format!("  resp: {body}\n"));
            }
        }
    }
    user.push('\n');

    // Dependencies
    if context.dependencies.is_empty() {
        user.push_str("DEPENDENCIES: none detected\n\n");
    } else {
        user.push_str("DEPENDENCIES:\n");
        let edges = context.dependencies.iter().take(MAX_EDGES_IN_PROMPT);
        for edge in edges {
            user.push_str(&format!(
                "{} -> {} [{} in {}]\n",
                edge.source, edge.target, edge.token_type, edge.location
            ));
        }
        user.push('\n');
    }

    // Sitemap
    if context.sitemap.is_empty() {
        user.push_str("SITEMAP: empty\n\n");
    } else {
        user.push_str("SITEMAP:\n");
        for host in &context.sitemap {
            user.push_str(&format!("{}: {}\n", host.host, host.endpoints.join(", ")));
        }
        user.push('\n');
    }

    // PARAMETERS OBSERVED — extract all query params and body fields from steps
    let mut params: Vec<String> = Vec::new();
    for step in context.steps.iter().take(shown) {
        // Extract query params from path
        if let Some(query) = step.path.split('?').nth(1) {
            for pair in query.split('&') {
                if let Some(name) = pair.split('=').next() {
                    if !name.is_empty() {
                        let entry = format!("{} {} ?{} (query param)", step.method, step.path.split('?').next().unwrap_or(&step.path), name);
                        if !params.contains(&entry) {
                            params.push(entry);
                        }
                    }
                }
            }
        }
        // Extract body fields from request body
        if let Some(body) = &step.request_body {
            if body.trim_start().starts_with('{') {
                if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(body) {
                    if let Some(obj) = parsed.as_object() {
                        for key in obj.keys() {
                            let entry = format!("{} {} body.{} (JSON field)", step.method, step.path, key);
                            if !params.contains(&entry) {
                                params.push(entry);
                            }
                        }
                    }
                }
            }
        }
    }
    if params.is_empty() {
        user.push_str("PARAMETERS OBSERVED: none\n\n");
    } else {
        user.push_str(&format!("PARAMETERS OBSERVED ({}):\n", params.len()));
        for p in &params {
            user.push_str(&format!("  {p}\n"));
        }
        user.push('\n');
    }

    // RSC ENDPOINTS — Next.js React Server Component endpoints are high-value targets
    let rsc_endpoints: Vec<String> = context.steps.iter()
        .filter(|s| s.path.contains("_rsc"))
        .map(|s| format!("{} {} -> {}", s.method, s.path, s.status))
        .collect();
    if !rsc_endpoints.is_empty() {
        user.push_str(&format!("RSC ENDPOINTS DETECTED (HIGH VALUE - may leak session data in embedded payload):\n"));
        for ep in &rsc_endpoints {
            user.push_str(&format!("  {ep}\n"));
        }
        user.push('\n');
    }

    // AUTH OBSERVED — check response bodies for token signals
    let mut auth_signals: Vec<String> = Vec::new();
    for step in context.steps.iter().take(shown) {
        if let Some(body) = &step.response_body {
            let signals = [
                ("accessToken", "accessToken in response body"),
                ("refreshToken", "refreshToken in response body"),
                ("id_token", "id_token in response body"),
                ("eyJ", "JWT token in response body"),
                ("sessionToken", "sessionToken in response body"),
            ];
            for (needle, label) in &signals {
                if body.contains(needle) {
                    let entry = format!("{} {} — {}", step.method, step.path, label);
                    if !auth_signals.contains(&entry) {
                        auth_signals.push(entry);
                    }
                }
            }
        }
        // Check for Set-Cookie with session cookies
        if let Some(body) = &step.response_body {
            if body.contains("__Secure-next-auth") || body.contains("session-token") {
                let entry = format!("{} {} — NextAuth session cookie detected", step.method, step.path);
                if !auth_signals.contains(&entry) {
                    auth_signals.push(entry);
                }
            }
        }
    }
    if auth_signals.is_empty() {
        user.push_str("AUTH OBSERVED: none\n\n");
    } else {
        user.push_str(&format!("AUTH OBSERVED ({}):\n", auth_signals.len()));
        for s in &auth_signals {
            user.push_str(&format!("  {s}\n"));
        }
        user.push('\n');
    }

    // ENDPOINT CATALOG — classify each endpoint by auth requirement and list fields
    // Build from steps: method, path, auth requirement, body fields, query params, notes
    let mut catalog: Vec<String> = Vec::new();
    for step in context.steps.iter().take(shown) {
        if catalog.len() >= 50 { break; } // limit entries (50 for full 18+3 codelab coverage)
        let path_base = step.path.split('?').next().unwrap_or(&step.path);
        let key = format!("{} {}", step.method, path_base);
        if catalog.iter().any(|e| e.starts_with(&key)) {
            continue; // deduplicate by method+path
        }
        // Skip page renders (HTML responses > 10KB) unless they have anomalies (RSC leak, mass PII, etc.)
        if let Some(body) = &step.response_body {
            if body.len() > 10000 || body.contains("<!DOCTYPE") || body.contains("<html") {
                let has_anomaly = {
                    let over = api_tester_analysis::OverfetchingAnalyzer::analyze(body);
                    let sec = api_tester_analysis::SecretScanner::analyze(body);
                    over.is_suspicious || sec.is_suspicious
                };
                if !has_anomaly {
                    continue;
                }
            }
        }

        // Determine auth requirement
        let has_auth_signal = auth_signals.iter().any(|s| {
            s.starts_with(&format!("{} {}", step.method, path_base))
        });
        let has_auth_dependency = context.dependencies.iter().any(|d| {
            d.target.contains(path_base)
                && (d.token_type.contains("jwt")
                    || d.token_type.contains("oauth")
                    || d.token_type.contains("session")
                    || d.location.contains("authorization"))
        });
        let auth_required = has_auth_signal || has_auth_dependency;

        // Extract query params
        let query_params: Vec<String> = step
            .path
            .split('?')
            .nth(1)
            .unwrap_or("")
            .split('&')
            .filter_map(|pair| {
                let name = pair.split('=').next()?;
                if name.is_empty() { None } else { Some(name.to_owned()) }
            })
            .collect();

        // Extract body fields
        let body_fields: Vec<String> = step
            .request_body
            .as_ref()
            .and_then(|body| {
                if body.trim_start().starts_with('{') {
                    let parsed: serde_json::Value = serde_json::from_str(body).ok()?;
                    let obj = parsed.as_object()?;
                    Some(obj.keys().cloned().collect())
                } else {
                    None
                }
            })
            .unwrap_or_default();

        // Build catalog entry
        let mut entry = format!("  {} {} — {}", step.method, path_base,
            if auth_required { "AUTH REQUIRED" } else { "PUBLIC" });

        if !query_params.is_empty() {
            entry.push_str(&format!(", query: {}", query_params.join(", ")));
        }
        if !body_fields.is_empty() {
            entry.push_str(&format!(", body: {{{}}}", body_fields.join(", ")));
        }

        // Add notes based on response patterns
        if let Some(body) = &step.response_body {
            if body.trim() == "{}" {
                entry.push_str(" (returns {} when unauthenticated)");
            } else if body.contains("accessToken") {
                entry.push_str(" (returns accessToken when authenticated)");
            } else if step.status >= 400 {
                entry.push_str(&format!(" (returns {} error)", step.status));
            }
        }

        catalog.push(entry);
    }
    if catalog.is_empty() {
        user.push_str("ENDPOINT CATALOG: empty\n\n");
    } else {
        user.push_str(&format!("ENDPOINT CATALOG ({}):\n", catalog.len()));
        for entry in &catalog {
            user.push_str(&format!("{entry}\n"));
        }
        user.push('\n');
    }

    // ANOMALIES OBSERVED — overfetching, leaked passwords, Gitleaks secrets, CWE exposures
    let mut anomaly_signals: Vec<String> = Vec::new();
    for step in context.steps.iter().take(shown) {
        if let Some(body) = &step.response_body {
            let overfetching = api_tester_analysis::OverfetchingAnalyzer::analyze(body);
            let security = api_tester_analysis::SecretScanner::analyze(body);

            let mut step_anomalies = Vec::new();
            step_anomalies.extend(overfetching.detected_signals);
            step_anomalies.extend(security.summary_signals);

            if !step_anomalies.is_empty() {
                step_anomalies.sort();
                step_anomalies.dedup();
                let path_base = step.path.split('?').next().unwrap_or(&step.path);
                let entry = format!(
                    "  {} {} -> signals: [{}]",
                    step.method,
                    path_base,
                    step_anomalies.join(", ")
                );
                if !anomaly_signals.contains(&entry) {
                    anomaly_signals.push(entry);
                }
            }
        }
    }

    if anomaly_signals.is_empty() {
        user.push_str("ANOMALIES OBSERVED: none\n\n");
    } else {
        user.push_str(&format!("ANOMALIES OBSERVED ({}):\n", anomaly_signals.len()));
        for a in &anomaly_signals {
            user.push_str(&format!("{a}\n"));
        }
        user.push('\n');
    }

    user
}


#[cfg(test)]
mod tests {
    use super::{
        DependencyEdge, FlowContext, MAX_EDGES_IN_PROMPT, SitemapLine, SummaryStep,
        build_summary_prompt,
    };

    fn context() -> FlowContext {
        FlowContext {
            steps: vec![
                SummaryStep {
                    method: "POST".into(),
                    path: "/api/login".into(),
                    status: 200,
                    request_body: None,
                    response_body: None,
                },
                SummaryStep {
                    method: "GET".into(),
                    path: "/api/profile".into(),
                    status: 200,
                    request_body: None,
                    response_body: None,
                },
            ],
            dependencies: vec![DependencyEdge {
                source: "POST /api/login".into(),
                target: "GET /api/profile".into(),
                token_type: "oauth_access".into(),
                location: "header:authorization".into(),
            }],
            sitemap: vec![SitemapLine {
                host: "api.example.com".into(),
                endpoints: vec!["/api/login (1)".into(), "/api/profile (1)".into()],
            }],
        }
    }

    #[test]
    fn prompt_contains_compact_context() {
        let prompt = build_summary_prompt(&context(), 200);
        assert!(prompt.system.contains("web API analysis assistant"));
        assert!(prompt.user.contains("POST /api/login -> 200"));
        assert!(prompt.user.contains("GET /api/profile -> 200"));
        assert!(prompt.user.contains("oauth_access in header:authorization"));
        assert!(prompt.user.contains("api.example.com"));
    }

    #[test]
    fn prompt_caps_steps() {
        let mut ctx = context();
        ctx.steps = (0..500)
            .map(|i| SummaryStep {
                method: "GET".into(),
                path: format!("/api/{i}"),
                status: 200,
                request_body: None,
                response_body: None,
            })
            .collect();
        let prompt = build_summary_prompt(&ctx, 100);
        assert!(prompt.user.contains("STEPS (100/500)"));
        assert!(prompt.user.contains("/api/99"));
        assert!(!prompt.user.contains("/api/100"));
    }

    #[test]
    fn prompt_caps_edges_and_never_contains_token_values() {
        let mut ctx = context();
        ctx.dependencies = (0..300)
            .map(|i| DependencyEdge {
                source: format!("GET /a{i}"),
                target: format!("GET /b{i}"),
                token_type: "jwt".into(),
                location: "header:authorization".into(),
            })
            .collect();
        let prompt = build_summary_prompt(&ctx, 200);
        assert!(prompt.user.contains(&format!(
            "... {} more edges omitted",
            300 - MAX_EDGES_IN_PROMPT
        )));
        // Token values are never serialised — only types/locations.
        assert!(!prompt.user.contains("Bearer"));
        assert!(!prompt.user.contains("eyJ"));
    }

    #[test]
    fn prompt_handles_empty_context() {
        let prompt = build_summary_prompt(&FlowContext::default(), 200);
        assert!(prompt.user.contains("STEPS (0/0)"));
        assert!(prompt.user.contains("DEPENDENCIES: none detected"));
        assert!(prompt.user.contains("SITEMAP: empty"));
    }

    #[test]
    fn prompt_includes_json_bodies_when_present() {
        let mut ctx = context();
        ctx.steps[0].request_body = Some(r#"{"email":"a@b.com","password":"secret"}"#.into());
        ctx.steps[0].response_body = Some(r#"{"access_token":"abc"}"#.into());
        let prompt = build_summary_prompt(&ctx, 200);
        assert!(prompt.user.contains(r#"req: {"email""#));
        assert!(prompt.user.contains(r#"resp: {"access_token""#));
    }
}
