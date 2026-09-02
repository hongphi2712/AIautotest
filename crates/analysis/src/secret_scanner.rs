use crate::cwe_detector::{CweDetector, CweFinding};
use crate::gitleaks_scanner::{GitleaksFinding, GitleaksScanner};
use regex::Regex;
use std::borrow::Cow;
use std::collections::{HashMap, VecDeque};
use std::hash::{Hash, Hasher};
use std::sync::{Arc, Mutex, OnceLock};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretFinding {
    pub secret_type: String,
    pub match_preview: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SecurityAnalysisResult {
    pub is_suspicious: bool,
    pub secret_findings: Vec<SecretFinding>,
    pub gitleaks_findings: Vec<GitleaksFinding>,
    pub cwe_findings: Vec<CweFinding>,
    pub summary_signals: Vec<String>,
}

pub struct SecretScanner;

struct SecretPattern {
    secret_type: &'static str,
    regex: &'static str,
}

static PATTERNS: &[SecretPattern] = &[
    SecretPattern {
        secret_type: "aws_access_key",
        regex: r"(?i)AKIA[0-9A-Z]{16}",
    },
    SecretPattern {
        secret_type: "openai_api_key",
        regex: r"sk-[a-zA-Z0-9_-]{32,}",
    },
    SecretPattern {
        secret_type: "google_api_key",
        regex: r"AIzaSy[a-zA-Z0-9_-]{33}",
    },
    SecretPattern {
        secret_type: "database_connection_url",
        regex: r"(?i)(mongodb(\+srv)?|postgres|postgresql|mysql)://[^\s<>&`'\x22]+",
    },
    SecretPattern {
        secret_type: "private_rsa_key",
        regex: r"-----BEGIN (RSA|EC|PRIVATE) KEY-----",
    },
    SecretPattern {
        secret_type: "jwt_token",
        regex: r"eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}",
    },
    SecretPattern {
        secret_type: "generic_db_password",
        regex: r"(?i)(?:DB_PASSWORD|DB_USER|password|passwd|pwd|secret)\s*[:=]\s*[^\s<>&`'\x22]{3,}",
    },
    SecretPattern {
        secret_type: "env_file_leak",
        regex: r"(?i)DB_NAME\s*=\s*\w+",
    },
];

static COMPILED_PATTERNS: OnceLock<Vec<(&'static str, Regex)>> = OnceLock::new();

/// Bodies are immutable once captured, so a full analysis result is memoized
/// per body hash. This keeps repeated scans (history polls, AI context builds,
/// verifier passes) from respawning the gitleaks CLI for unchanged bodies.
const SCAN_CACHE_CAPACITY: usize = 4096;

struct ScanCache {
    entries: HashMap<u64, Arc<SecurityAnalysisResult>>,
    order: VecDeque<u64>,
}

static SCAN_CACHE: OnceLock<Mutex<ScanCache>> = OnceLock::new();

fn scan_cache() -> &'static Mutex<ScanCache> {
    SCAN_CACHE.get_or_init(|| {
        Mutex::new(ScanCache {
            entries: HashMap::new(),
            order: VecDeque::new(),
        })
    })
}

fn body_hash(body: &str) -> u64 {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    body.hash(&mut hasher);
    hasher.finish()
}

fn cached_analysis(body: &str) -> Option<Arc<SecurityAnalysisResult>> {
    let key = body_hash(body);
    let cache = scan_cache().lock().ok()?;
    cache.entries.get(&key).cloned()
}

fn store_analysis(body: &str, result: Arc<SecurityAnalysisResult>) {
    let Ok(mut cache) = scan_cache().lock() else {
        return;
    };
    let key = body_hash(body);
    if cache.entries.contains_key(&key) {
        return;
    }
    while cache.entries.len() >= SCAN_CACHE_CAPACITY {
        let Some(evicted) = cache.order.pop_front() else {
            break;
        };
        cache.entries.remove(&evicted);
    }
    cache.entries.insert(key, result);
    cache.order.push_back(key);
}

impl SecretScanner {
    /// Comprehensive security analysis combining Gitleaks CLI, Built-in Regex, and CWE Detector.
    /// Results are memoized per unique body; empty bodies skip scanning entirely.
    pub fn analyze(body: &str) -> SecurityAnalysisResult {
        if body.trim().is_empty() {
            return SecurityAnalysisResult::default();
        }
        if let Some(hit) = cached_analysis(body) {
            return (*hit).clone();
        }
        let result = Self::analyze_uncached(body);
        store_analysis(body, Arc::new(result.clone()));
        result
    }

    fn analyze_uncached(body: &str) -> SecurityAnalysisResult {
        // 1. Gitleaks CLI scan (hundreds of international secret rules)
        let gitleaks_findings = GitleaksScanner::scan_pipe(body);

        // 2. Built-in Regex Scanner on full body (fast fallback)
        let mut secret_findings = Self::scan_regex(body);

        // 3. RSC-aware scan: extract individual chunks from Next.js
        //    self.__next_f.push() calls and scan each one separately.
        //    This catches secrets split across chunk boundaries (e.g. JWT
        //    tokens where accessToken appears in one push and the value
        //    in the next).
        if body.contains("self.__next_f") {
            let chunks = crate::rsc_chunks::extract_rsc_chunks(body);
            for chunk in &chunks {
                for f in Self::scan_regex(chunk) {
                    if !secret_findings.iter().any(|existing| {
                        existing.secret_type == f.secret_type
                            && existing.match_preview == f.match_preview
                    }) {
                        secret_findings.push(f);
                    }
                }
            }
        }

        // 4. CWE Detector (CWE-215, CWE-209, CWE-284)
        let cwe_findings = CweDetector::detect(body);

        // Summary signals for AI Prompt Context
        let mut summary_signals = Vec::new();
        for f in &gitleaks_findings {
            summary_signals.push(format!("gitleaks_leak:{}", f.rule_id));
        }

        for f in &secret_findings {
            summary_signals.push(format!("secret_leak:{}", f.secret_type));
        }

        for f in &cwe_findings {
            summary_signals.push(format!("cwe_leak:{}", f.cwe_id));
        }

        summary_signals.sort();
        summary_signals.dedup();
        let is_suspicious = !summary_signals.is_empty();

        SecurityAnalysisResult {
            is_suspicious,
            secret_findings,
            gitleaks_findings,
            cwe_findings,
            summary_signals,
        }
    }

    /// Scans HTTP response body using built-in Regex rules.
    pub fn scan_regex(body: &str) -> Vec<SecretFinding> {
        let compiled = COMPILED_PATTERNS.get_or_init(|| {
            PATTERNS
                .iter()
                .filter_map(|p| Regex::new(p.regex).ok().map(|r| (p.secret_type, r)))
                .collect()
        });

        let mut findings = Vec::new();
        // JSON-string-embedded bodies escape quotes/backslashes, which hides
        // secrets from the regexes. Only pay for the unescape pass when the
        // body actually contains a backslash; otherwise borrow it as-is.
        let unescaped: Cow<'_, str> = if body.contains('\\') {
            Cow::Owned(body.replace("\\\"", "\"").replace("\\\\", "\\"))
        } else {
            Cow::Borrowed(body)
        };

        for (secret_type, re) in compiled {
            for m in re.find_iter(&unescaped) {
                let preview = m.as_str();
                let sanitized_preview = if preview.len() > 30 {
                    format!("{}...", truncate_on_char_boundary(preview, 30))
                } else {
                    preview.to_string()
                };

                findings.push(SecretFinding {
                    secret_type: secret_type.to_string(),
                    match_preview: sanitized_preview,
                });
            }
        }

        findings.sort_by(|a, b| a.secret_type.cmp(&b.secret_type));
        findings.dedup();
        findings
    }
}

/// Byte-length truncation that never splits a multi-byte UTF-8 character
/// (slicing at an arbitrary byte index would panic).
fn truncate_on_char_boundary(text: &str, max_bytes: usize) -> &str {
    if text.len() <= max_bytes {
        return text;
    }
    let mut end = max_bytes;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detects_database_uri() {
        let body = r#"{"db": "mongodb+srv://admin:secret123@cluster0.mongodb.net/test"}"#;
        let result = SecretScanner::analyze(body);
        assert!(result.is_suspicious);
        assert!(result.summary_signals.iter().any(|s| s.contains("database_connection_url")));
    }

    #[test]
    fn test_detects_jwt_via_gitleaks() {
        let jwt_sample = r#"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6IjY4OGMyZTFkMGVhMDlhMTRiZjA4ZDhjYyIsImlhdCI6MTc4NzMwMTE0MSwiZXhwIjoxNzg3OTA1OTQxfQ.NGKma2iYv8tEATjT2GrsjinldlDlsSY2IVK-ehgFgKc"#;
        let result = SecretScanner::analyze(jwt_sample);
        assert!(result.is_suspicious);
        assert!(result.summary_signals.iter().any(|s| s.contains("gitleaks_leak:jwt") || s.contains("secret_leak:jwt_token")));
    }

    #[test]
    fn truncate_never_splits_multibyte_characters() {
        // Each 'é' is 2 bytes; byte index 30 falls inside a character.
        let text = "é".repeat(20);
        assert_eq!(truncate_on_char_boundary(&text, 30).chars().count(), 15);
        assert_eq!(truncate_on_char_boundary("short", 30), "short");
        assert_eq!(truncate_on_char_boundary("exact_30_chars_long_ok!!", 30).len(), 24);
    }

    #[test]
    fn multibyte_database_uri_does_not_panic() {
        // Non-ASCII bytes inside a matched database URL previously sliced at
        // an arbitrary byte offset and panicked.
        let body = "postgres://user:pássword-ünïcode-áéíóú-àèìòù-âêîôû@example.com/db";
        let result = SecretScanner::scan_regex(body);
        assert!(result
            .iter()
            .any(|f| f.secret_type == "database_connection_url"));
    }

    #[test]
    fn analyze_memoizes_per_body() {
        let body = r#"{"token": "sk-cachedbodyvalue1234567890abcdefghijklmnop"}"#;
        let first = SecretScanner::analyze(body);
        let second = SecretScanner::analyze(body);
        assert_eq!(first, second);
        // A mutated copy hashes differently; its preview must come from its
        // own body, proving there is no cross-key cache bleed.
        let other = SecretScanner::analyze(&body.replace("cached", "changed"));
        assert_eq!(
            first.secret_findings.len(),
            other.secret_findings.len()
        );
        assert_ne!(
            first.secret_findings[0].match_preview,
            other.secret_findings[0].match_preview
        );
    }

    #[test]
    fn empty_and_whitespace_bodies_skip_analysis() {
        assert!(!SecretScanner::analyze("").is_suspicious);
        assert!(!SecretScanner::analyze("   \n\t").is_suspicious);
    }

    #[test]
    fn detects_jwt_split_across_rsc_chunks() {
        // Simulate Next.js RSC where a JWT token is split across two push calls:
        // Push 1: "...\"accessToken\":\"eyJabc"
        // Push 2: ".eyJdef.ghijk\"
        let html = r#"<html><body>
<script>self.__next_f.push([1,"3:{\"accessToken\":\"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6IjY4OGMyZTFkMGVhMDlhMTRiZjA4ZDhjYyJ9.XYZsignature1234567890\"}\n"])</script>
</body></html>"#;
        let result = SecretScanner::analyze(html);
        assert!(
            result.is_suspicious,
            "must detect JWT in RSC chunks"
        );
        assert!(
            result.summary_signals.iter().any(|s| s.contains("secret_leak:jwt_token") || s.contains("gitleaks_leak")),
            "should have jwt_token signal: {:?}",
            result.summary_signals
        );
    }

    #[test]
    fn detects_sk_api_key_in_rsc_chunk() {
        let html = r#"<html><body>
<script>self.__next_f.push([1,"config:{\"api_key\":\"sk-proj-abc123def456ghi789jkl012mno345pqr\"}\n"])</script>
</body></html>"#;
        let result = SecretScanner::analyze(html);
        assert!(
            result.is_suspicious,
            "must detect OpenAI API key in RSC chunk"
        );
        assert!(
            result.secret_findings.iter().any(|f| f.secret_type == "openai_api_key"),
            "should find openai_api_key: {:?}",
            result.secret_findings
        );
    }

    #[test]
    fn test_real_contest_html_jwt_detection() {
        let contest_html_path = "../../contest.html";
        let Ok(content) = std::fs::read_to_string(contest_html_path)
            .or_else(|_| std::fs::read_to_string("contest.html"))
        else {
            return;
        };

        let result = SecretScanner::analyze(&content);
        println!("\n=== SECRET SCANNER RESULTS FOR contest.html ===");
        println!("is_suspicious: {}", result.is_suspicious);
        println!("summary_signals: {:?}", result.summary_signals);
        for f in &result.secret_findings {
            println!("  secret: {} = {}", f.secret_type, f.match_preview);
        }
        for g in &result.gitleaks_findings {
            println!("  gitleaks: {} at line {}", g.rule_id, g.start_line);
        }
        println!("===============================================\n");

        // contest.html has session data with user emails and potentially tokens
        // in RSC chunks — the scanner should find at least something suspicious
        assert!(
            result.is_suspicious,
            "contest.html must be detected as suspicious by secret scanner"
        );
    }

    #[test]
    fn test_full_security_report_json() {
        let report_path = "../../output/security_report.json";
        let Ok(content) = std::fs::read_to_string(report_path).or_else(|_| std::fs::read_to_string("output/security_report.json")) else {
            return;
        };

        let Ok(val) = serde_json::from_str::<serde_json::Value>(&content) else { return; };
        let Some(findings) = val.get("findings").and_then(|f| f.as_array()) else { return; };

        println!("\n=== FULL HTTP HISTORY SECURITY SCAN RESULTS ({}) ===", findings.len());
        for (idx, item) in findings.iter().enumerate() {
            let target = item.get("target").and_then(|t| t.as_str()).unwrap_or("unknown");
            let resp_body = item.get("response_body").and_then(|b| b.as_str()).unwrap_or("");

            let overfetching = crate::overfetching::OverfetchingAnalyzer::analyze(resp_body);
            let security = SecretScanner::analyze(resp_body);

            println!("\n[FINDING #{}] Target: {}", idx + 1, target);
            if overfetching.is_suspicious {
                println!("  -> Overfetching Signals: {:?}", overfetching.detected_signals);
                if !overfetching.exposed_passwords.is_empty() {
                    println!("  -> Leaked Passwords: {:?}", overfetching.exposed_passwords);
                }
            }
            if security.is_suspicious {
                println!("  -> Security Signals: {:?}", security.summary_signals);
                for g in &security.gitleaks_findings {
                    println!("     - Gitleaks [{}] at line {}", g.rule_id, g.start_line);
                }
                for c in &security.cwe_findings {
                    println!("     - [{}] {}: {}", c.cwe_id, c.title, c.evidence);
                }
            }
        }
        println!("=========================================================\n");
    }
}

