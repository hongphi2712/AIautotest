use std::sync::Arc;
use std::time::Duration;

use api_tester_domain::{Finding, ScopeConfig, ScopeFilter, Severity};
use api_tester_ports::HttpClient;
use api_tester_scanner::{
    BudgetTracker, HostRateLimiter, RequestExecutor, ScopeGuard,
    error::ScanError,
    scope_guard::require_allowlist,
};
use serde::Serialize;
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;

use crate::types::{ConfirmationRequest, ConfirmationResponse, SecurityTest, SecurityTestPlan};

// ---------------------------------------------------------------------------
// Configuration for one security execution run.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct SecurityRunConfig {
    /// Per-request timeout in seconds (incl. retries).
    pub timeout_secs: u64,
    /// Hard cap on HTTP requests sent (incl. retries).
    pub max_requests: u64,
    /// Per-host request rate cap (requests/sec, 0 = unlimited).
    pub per_host_requests_per_sec: u32,
    /// Optional wall-clock budget for the whole run.
    pub duration_budget_secs: Option<u64>,
    /// Retries per request before it is considered failed.
    pub retry_limit: u32,
    /// Own scope copy — separate from the proxy capture scope.
    pub scope: ScopeConfig,
    /// Auth cookies from captured traffic (e.g. session token, next-auth).
    pub auth_cookies: std::collections::BTreeMap<String, String>,
    /// Auth headers from captured traffic (e.g. Authorization: Bearer ...).
    pub auth_headers: Vec<(String, String)>,
}

// ---------------------------------------------------------------------------
// Outcome
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StopReason {
    Completed,
    Cancelled,
    BudgetExhausted,
    DurationExceeded,
    ScopeViolation,
}

#[derive(Debug, Serialize)]
pub struct SecurityRunOutcome {
    pub findings: Vec<SecurityFinding>,
    pub requests_sent: u64,
    pub skipped: usize,
    pub stop_reason: StopReason,
}

// ---------------------------------------------------------------------------
// Per-test event for real-time WS progress
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub struct SecurityEvent {
    pub test_id: String,
    pub flaw: String,
    pub target: String,
    pub status: u16,
    pub passed: bool,
    pub has_finding: bool,
    pub skipped: bool,
    pub evidence: String,
    pub potential: bool,
    #[serde(default)]
    pub needs_confirmation: bool,
}

// ---------------------------------------------------------------------------
// Finding (serialised for report + DB)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub struct SecurityFinding {
    pub test_id: String,
    pub flaw: String,
    pub target: String,
    pub severity: Severity,
    pub passed: bool,
    pub evidence: String,
    pub status: u16,
    pub finding: Option<Finding>,
    pub potential: bool,
    pub verdict: String,
    pub explanation: String,
    pub risk: String,
    pub fix_suggestion: String,
    pub payload_sent: String,
    pub request_url: String,
    pub request_method: String,
    pub response_body: String,
    pub request_headers: String,
    pub response_headers: String,
    pub cookies: String,
    pub is_html_page: bool,
    pub location: String,
}

// ---------------------------------------------------------------------------
// Helpers (unchanged semantics, moved to top level)
// ---------------------------------------------------------------------------

fn severity_from_str(s: &str) -> Severity {
    match s {
        "Critical" => Severity::Critical,
        "High" => Severity::High,
        "Warning" => Severity::Warning,
        "Info" => Severity::Info,
        _ => Severity::Warning,
    }
}

fn join_url(base: &str, path: &str) -> String {
    let base = base.trim_end_matches('/');
    if path.starts_with('/') {
        format!("{base}{path}")
    } else {
        format!("{base}/{path}")
    }
}

fn host_path(url_str: &str) -> (String, String) {
    if let Ok(url) = url::Url::parse(url_str) {
        return (
            url.host_str().unwrap_or_default().to_owned(),
            url.path().to_owned(),
        );
    }
    match url_str.split_once('/') {
        Some((host, path)) => (host.to_owned(), format!("/{path}")),
        None => (url_str.to_owned(), "/".to_owned()),
    }
}

fn mutate_target(test: &SecurityTest, base_url: &str) -> api_tester_ports::HttpRequest {
    let mut path = test.target.path.clone();
    let method = test.target.method.to_uppercase();
    let mut headers: Vec<(String, String)> = Vec::new();
    let mut body: Option<Vec<u8>> = None;

    // If AI supplied a concrete payload, use it with the declared location.
    if let Some(payload) = test.payload.as_deref().filter(|p| !p.trim().is_empty()) {
        let loc = test.location.as_deref().unwrap_or("").trim();
        if loc.starts_with("query:") {
            let param = loc.split_once(':').map(|x| x.1).unwrap_or("q");
            let enc: String = url::form_urlencoded::byte_serialize(payload.as_bytes()).collect();
            let sep = if path.contains('?') { "&" } else { "?" };
            path.push_str(&format!("{sep}{param}={enc}"));
        } else if loc == "query" {
            let enc: String = url::form_urlencoded::byte_serialize(payload.as_bytes()).collect();
            let sep = if path.contains('?') { "&" } else { "?" };
            path.push_str(&format!("{sep}payload={enc}"));
        } else if loc.starts_with("body:") {
            let field = loc.split_once(':').map(|x| x.1).unwrap_or("");
            let json_body = if field.is_empty() {
                payload.to_string()
            } else {
                // Try to parse payload as JSON object/array for nosql/mass_assignment, else as string
                if let Ok(val) = serde_json::from_str::<serde_json::Value>(payload) {
                    if val.is_object() || val.is_array() {
                        serde_json::json!({ field: val }).to_string()
                    } else {
                        serde_json::json!({ field: payload }).to_string()
                    }
                } else {
                    serde_json::json!({ field: payload }).to_string()
                }
            };
            body = Some(json_body.into_bytes());
            headers.push(("Content-Type".to_string(), "application/json".to_string()));
        } else if loc == "body" {
            body = Some(payload.as_bytes().to_vec());
            if payload.trim().starts_with('{') {
                headers.push(("Content-Type".to_string(), "application/json".to_string()));
            }
        } else if loc == "path" {
            let base = path.split('?').next().unwrap_or(&path).trim_end_matches('/');
            let last_slash = base.rfind('/').unwrap_or(0);
            let prefix = &base[..=last_slash];
            // Don't double-encode slashes in path payloads (e.g. "GET /api/users" already contains /)
            let enc = if payload.contains('/') {
                payload.to_string()
            } else {
                url::form_urlencoded::byte_serialize(payload.as_bytes()).collect()
            };
            let query = path.split_once('?').map(|x| x.1).map(|q| format!("?{q}")).unwrap_or_default();
            path = format!("{prefix}{enc}{query}");
        } else if loc.starts_with("header:") {
            let name = loc.split_once(':').map(|x| x.1).unwrap_or("X-Payload");
            headers.push((name.to_string(), payload.to_string()));
        } else if loc.starts_with("cookie:") {
            let name = loc.split_once(':').map(|x| x.1).unwrap_or("session");
            headers.push(("Cookie".to_string(), format!("{name}={payload}")));
        } else {
            // Fallback: treat as query
            let enc: String = url::form_urlencoded::byte_serialize(payload.as_bytes()).collect();
            let sep = if path.contains('?') { "&" } else { "?" };
            path.push_str(&format!("{sep}payload={enc}"));
        }
        return api_tester_ports::HttpRequest {
            method,
            url: join_url(base_url, &path),
            headers,
            body,
        };
    }

    // Fallback to hardcoded minimal payloads when AI didn't supply one
    match test.flaw.as_str() {
        "xss" => {
            let payload = "<script>alert(1)</script>";
            if path.contains('?') {
                path.push_str(&format!("&x={payload}"));
            } else {
                path.push_str(&format!("?x={payload}"));
            }
        }
        "sqli" => {
            let payload = "'%20OR%201=1--";
            if path.contains('?') {
                path.push_str(&format!("&q={payload}"));
            } else {
                path.push_str(&format!("?q={payload}"));
            }
        }
        "idor" => {
            if let Some(last) = path.chars().last() {
                let flipped = if last == 'a' { 'b' } else { 'a' };
                path.pop();
                path.push(flipped);
            }
        }
        "open_redirect" => {
            if path.contains("callbackUrl") || path.contains("redirect") {
            } else if path.contains('?') {
                path.push_str("&callbackUrl=https://evil.com");
            } else {
                path.push_str("?callbackUrl=https://evil.com");
            }
        }
        "csrf" => {}
        _ => {}
    }
    api_tester_ports::HttpRequest {
        method,
        url: join_url(base_url, &path),
        headers,
        body,
    }
}

fn check_oracle(oracle: &crate::types::Oracle, status: u16, body: &str) -> bool {
    if let Some(expected) = oracle.expect_status {
        if status != expected {
            return false;
        }
    }
    if let Some(needle) = &oracle.expect_contains {
        if !body.contains(needle) {
            return false;
        }
    }
    true
}

fn remediation_for(flaw: &str) -> String {
    match flaw {
        "xss" => "Sanitize user input and use Content-Security-Policy headers".into(),
        "sqli" => "Use parameterized queries / prepared statements".into(),
        "idor" => "Validate object ownership before granting access".into(),
        "jwt_exposure" => "Never expose JWT tokens in response bodies; use HttpOnly cookies".into(),
        "auth_bypass" => "Enforce authentication checks on all state-changing endpoints".into(),
        "csrf" => "Use CSRF tokens or SameSite cookie attribute".into(),
        "open_redirect" => "Validate redirect URLs against a whitelist".into(),
        "rate_limit" => "Implement rate limiting and account lockout on login endpoints".into(),
        "rsc_data_leakage" => "RSC endpoint leaks session data in embedded payload. Sanitize server-side data to exclude tokens/PII from RSC payloads. Review getServerSideProps data filtering.".into(),
        "secret_leak" => "Investigate exposed secrets. Rotate compromised credentials. Remove secrets from response bodies.".into(),
        _ => String::new(),
    }
}

fn verdict_str(flaw: &str, passed: bool, potential: bool, status: u16) -> String {
    if flaw == "csrf" && (status == 200 || status == 201) {
        return "CSRF — Endpoint chấp nhận POST không CSRF token".into();
    }
    if potential {
        if flaw == "idor" {
            "IDOR — Cần verify thủ công".into()
        } else {
            format!("Lỗ hổng {} có thể có", flaw_name(flaw))
        }
    } else if passed {
        "An toàn — test passed".into()
    } else {
        "An toàn — không phát hiện vấn đề".into()
    }
}

fn flaw_name(flaw: &str) -> &'static str {
    match flaw {
        "jwt_exposure" => "Leak JWT Token",
        "idor" => "IDOR — Truy cập resource người khác",
        "auth_bypass" => "Auth Bypass — Bỏ qua xác thực",
        "sqli" => "SQL Injection",
        "xss" => "XSS — Cross-Site Scripting",
        "csrf" => "CSRF — Cross-Site Request Forgery",
        "open_redirect" => "Open Redirect",
        "rate_limit" => "Thiếu Rate Limiting",
        _ => "Unknown",
    }
}

/// Detect likely false positives based on response characteristics.
/// Returns true if the finding is likely a false positive.
fn is_likely_false_positive(flaw: &str, status: u16, body: &str, test_path: &str) -> bool {
    match flaw {
        // jwt_exposure: 4xx for unauth request = endpoint is protected
        "jwt_exposure" => status >= 400 && status < 500,

        // sqli: normal data pattern with no SQL errors, or validation error
        "sqli" => {
            // 422 = validation error, not SQL injection
            status == 422
            // Normal data pattern
            || ((body.contains("\"data\":[") || body.contains("\"data\": ["))
                && !body.to_lowercase().contains("error")
                && !body.to_lowercase().contains("syntax")
                && !body.to_lowercase().contains("sql"))
        }

        // xss: JSON API does not render HTML unless payload reflected
        "xss" => {
            let trimmed = body.trim();
            let isJson = trimmed.starts_with('{') || trimmed.starts_with('[');
            // Only suppress if JSON and no HTML reflection
            isJson && !(body.contains("<script") || body.contains("<svg") || body.contains("onload") || body.contains("javascript:"))
        }

        // open_redirect: 500 is server error, not redirect
        "open_redirect" => status == 500,

        // auth_bypass: 200 with empty body = correct behavior
        "auth_bypass" => {
            status == 200 && (body.trim() == "{}" || body.trim() == "")
        }

        // jwt_exposure: 200 with empty body = correct behavior
        // (endpoint returns empty when not authenticated)
        // Already handled by status >= 400 check above for 4xx cases
        // For 200 with empty body, this is NOT jwt_exposure

        // rate_limit: testing wrong endpoint type
        "rate_limit" => {
            // CSRF endpoint only accepts POST, testing GET is invalid
            (test_path.contains("csrf") && status == 400)
            // Testing rate limit on non-login endpoint
            || (!test_path.contains("callback") && !test_path.contains("login") && !test_path.contains("signin"))
        }

        _ => false,
    }
}

fn explain_status(flaw: &str, status: u16, body: &str) -> String {
    match flaw {
        "jwt_exposure" => {
            if body.contains("accessToken") || body.contains("eyJ") {
                "Endpoint trả token trong response body — có thể bị leak".into()
            } else {
                "Endpoint trả {} khi chưa auth — token chỉ lộ khi authenticated".into()
            }
        }
        "idor" => {
            if status == 200 {
                "Server trả 200 — data trả về thành công, KHÔNG kiểm tra quyền truy cập".into()
            } else if status == 403 {
                "Server trả 403 — kiểm tra quyền đúng, từ chối truy cập".into()
            } else {
                format!("Server trả {status} — cần kiểm tra thêm")
            }
        }
        "auth_bypass" => {
            if status == 401 || status == 403 {
                format!("Server trả {status} — endpoint kiểm tra auth đúng")
            } else if status == 422 {
                "Server trả 422 — Validation error (thiếu field, KHÔNG PHẢI vì thiếu auth)".into()
            } else if status == 200 || status == 201 {
                "Server chấp nhận request KHÔNG cần auth — CÓ THỂ có lỗ hổng".into()
            } else {
                format!("Server trả {status} — cần kiểm tra thêm")
            }
        }
        "sqli" => {
            if status == 500 {
                "Server trả 500 — có thể có lỗi SQL".into()
            } else if body.contains("error") || body.contains("syntax") {
                "Response chứa thông báo lỗi SQL".into()
            } else {
                "Server xử lý query bình thường — không trigger lỗi SQL".into()
            }
        }
        "xss" => {
            if body.contains("<svg") || body.contains("<script") {
                "Payload XSS được reflect trong response".into()
            } else {
                "Payload XSS không được reflect — endpoint escape input".into()
            }
        }
        "csrf" => {
            if status == 200 || status == 201 {
                "Server chấp nhận POST không cần CSRF token".into()
            } else if status == 403 {
                "Server từ chối POST không có CSRF token — đúng behavior".into()
            } else {
                format!("Server trả {status}")
            }
        }
        "rate_limit" => {
            if status == 429 {
                "Server trả 429 — rate limiting hoạt động".into()
            } else {
                "Server KHÔNG trả 429 — không có rate limiting".into()
            }
        }
        "open_redirect" => {
            if body.contains("evil.com") || body.contains("location") {
                "Redirect URL được accept".into()
            } else {
                "Redirect URL không được accept hoặc endpoint không redirect".into()
            }
        }
        _ => format!("Server trả {status}"),
    }
}

fn explain_risk(flaw: &str) -> String {
    match flaw {
        "jwt_exposure" => "Token bị lộ cho kẻ tấn công, có thể giả mạo người dùng".into(),
        "idor" => "Kẻ tấn công xem/sửa dữ liệu của người dùng khác".into(),
        "auth_bypass" => "Kẻ tấn công thực hiện thay đổi mà không cần đăng nhập".into(),
        "sqli" => "Kẻ tấn công truy cập hoặc sửa database".into(),
        "xss" => "Kẻ tấn công đánh cắp session cookie của người dùng".into(),
        "csrf" => "Kẻ tấn công gửi request thay người dùng".into(),
        "rate_limit" => "Kẻ tấn công brute-force password hoặc spam request".into(),
        "open_redirect" => "Kẻ tấn công redirect người dùng sang trang độc hại".into(),
        _ => "Cần kiểm tra thêm".into(),
    }
}

fn format_request_headers(request: &api_tester_ports::HttpRequest) -> String {
    let mut headers = String::new();
    for (name, value) in &request.headers {
        let lower = name.to_lowercase();
        if lower == "cookie" || lower == "authorization" {
            continue; // cookies handled separately, auth redacted
        }
        headers.push_str(&format!("{}: {}\n", name, value));
    }
    if headers.is_empty() {
        "(không có header tùy chỉnh)".into()
    } else {
        headers.trim_end().to_string()
    }
}

/// Full response headers for the evidence viewer (nothing redacted — this is
/// the observed response the verdict is based on).
fn format_response_headers(headers: &[(String, String)]) -> String {
    if headers.is_empty() {
        return "(không có header)".into();
    }
    headers
        .iter()
        .map(|(name, value)| format!("{}: {}", name, value))
        .collect::<Vec<_>>()
        .join("\n")
}

fn format_cookies(request: &api_tester_ports::HttpRequest) -> String {    for (name, value) in &request.headers {
        if name.to_lowercase() == "cookie" {
            // Truncate long cookie values for display
            if value.len() > 100 {
                return format!("{}... ({} chars total)", &value[..100], value.len());
            }
            return value.clone();
        }
    }
    "(không có cookie)".into()
}

// ---------------------------------------------------------------------------
// SecurityExecutor — uses scanner safety primitives
// ---------------------------------------------------------------------------

pub struct SecurityExecutor {
    executor: Arc<RequestExecutor>,
    budget: BudgetTracker,
    limiter: Option<HostRateLimiter>,
    guard: Arc<ScopeGuard>,
    cancel: CancellationToken,
    event_tx: Option<mpsc::Sender<SecurityEvent>>,
    config: SecurityRunConfig,
    /// Channel to send confirmation requests to the frontend via WS.
    confirmation_tx: Option<mpsc::Sender<ConfirmationRequest>>,
    /// Pending confirmation senders keyed by test_id.
    /// When a destructive test needs approval, a oneshot sender is stored here.
    /// The frontend calls POST /api/security/confirm which looks up the sender
    /// and sends the response, resolving the oneshot in the executor loop.
    pending_confirmations: Arc<tokio::sync::Mutex<std::collections::HashMap<String, oneshot::Sender<ConfirmationResponse>>>>,
    /// Run ID for confirmation requests.
    run_id: String,
}

impl SecurityExecutor {
    pub fn new(
        client: Arc<dyn HttpClient>,
        cancel: CancellationToken,
        config: SecurityRunConfig,
    ) -> Result<Self, ScanError> {
        Self::with_events(
            client,
            cancel,
            config,
            None,
            None,
            String::new(),
            Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
        )
    }

    pub fn with_events(
        client: Arc<dyn HttpClient>,
        cancel: CancellationToken,
        config: SecurityRunConfig,
        event_tx: Option<mpsc::Sender<SecurityEvent>>,
        confirmation_tx: Option<mpsc::Sender<ConfirmationRequest>>,
        run_id: String,
        pending_confirmations: Arc<tokio::sync::Mutex<std::collections::HashMap<String, oneshot::Sender<ConfirmationResponse>>>>,
    ) -> Result<Self, ScanError> {
        require_allowlist(&config.scope)?;
        let scope_filter =
            ScopeFilter::new(config.scope.clone()).map_err(|e| ScanError::InvalidScope(e.to_string()))?;
        Ok(Self {
            executor: Arc::new(RequestExecutor::new(
                client,
                config.retry_limit,
                config.timeout_secs,
            )),
            budget: BudgetTracker::new(
                config.max_requests,
                config.duration_budget_secs.map(Duration::from_secs),
            ),
            limiter: HostRateLimiter::new(config.per_host_requests_per_sec),
            guard: Arc::new(ScopeGuard::new(scope_filter)),
            cancel,
            event_tx,
            config,
            confirmation_tx,
            pending_confirmations,
            run_id,
        })
    }

    pub async fn execute(&self, plan: &SecurityTestPlan) -> SecurityRunOutcome {
        let mut findings = Vec::new();
        let mut skipped = 0usize;
        let mut requests_sent = 0u64;
        let mut stop_reason = StopReason::Completed;

        for test in plan.tests.iter() {
            if self.cancel.is_cancelled() {
                stop_reason = StopReason::Cancelled;
                break;
            }

            let request = mutate_target(test, &plan.base_url);
            let target_label = format!("{} {}", test.target.method, test.target.path);

            // Inject auth cookies/headers from captured traffic
            let mut request = request;
            if !self.config.auth_cookies.is_empty() {
                let cookie_str: String = self.config.auth_cookies
                    .iter()
                    .map(|(k, v)| format!("{k}={v}"))
                    .collect::<Vec<_>>()
                    .join("; ");
                // Remove existing Cookie header if any
                request.headers.retain(|(name, _)| !name.eq_ignore_ascii_case("cookie"));
                request.headers.push(("Cookie".to_string(), cookie_str));
            }
            for (name, value) in &self.config.auth_headers {
                // Remove existing header with same name
                request.headers.retain(|(n, _)| !n.eq_ignore_ascii_case(name));
                request.headers.push((name.clone(), value.clone()));
            }

            // Per-request scope check — BEFORE consuming budget so skipped
            // tests don't waste budget slots (mirrors scanner's guard-first order).
            let (host, path) = host_path(&request.url);
            if !self.guard.check(&host, &path) {
                skipped += 1;
                if let Some(tx) = &self.event_tx {
                    let _ = tx
                        .send(SecurityEvent {
                            test_id: test.id.clone(),
                            flaw: test.flaw.clone(),
                            target: target_label.clone(),
                            status: 0,
                            passed: false,
                            has_finding: false,
                            skipped: true,
                            evidence: "out of scope".into(),
                            potential: false,
                            needs_confirmation: false,
                        })
                        .await;
                }
                continue;
            }

            // === Confirmation gate for destructive tests ===
            if test.is_destructive() {
                if let Some(tx) = &self.confirmation_tx {
                    let (resp_tx, resp_rx) = oneshot::channel::<ConfirmationResponse>();

                    // Store response sender for REST endpoint to access
                    self.pending_confirmations.lock().await.insert(
                        test.id.clone(),
                        resp_tx,
                    );

                    // Send confirmation request to frontend via WS
                    let _ = tx.send(ConfirmationRequest {
                        run_id: self.run_id.clone(),
                        test_id: test.id.clone(),
                        flaw: test.flaw.clone(),
                        method: test.target.method.clone(),
                        path: test.target.path.clone(),
                        severity: test.severity.clone(),
                        payload_hint: test.payload_hint.clone(),
                    }).await;

                    // Emit needs_confirmation event
                    if let Some(event_tx) = &self.event_tx {
                        let _ = event_tx.send(SecurityEvent {
                            test_id: test.id.clone(),
                            flaw: test.flaw.clone(),
                            target: target_label.clone(),
                            status: 0,
                            passed: false,
                            has_finding: false,
                            skipped: false,
                            evidence: "awaiting user confirmation".into(),
                            potential: false,
                            needs_confirmation: true,
                        }).await;
                    }

                    // Wait for user response with timeout + cancellation
                    let approved = tokio::select! {
                        response = resp_rx => {
                            matches!(response, Ok(ConfirmationResponse { approved: true, .. }))
                        }
                        _ = tokio::time::sleep(Duration::from_secs(60)) => false,
                        _ = self.cancel.cancelled() => false,
                    };

                    // Cleanup
                    self.pending_confirmations.lock().await.remove(&test.id);

                    if !approved {
                        skipped += 1;
                        if let Some(event_tx) = &self.event_tx {
                            let _ = event_tx.send(SecurityEvent {
                                test_id: test.id.clone(),
                                flaw: test.flaw.clone(),
                                target: target_label.clone(),
                                status: 0,
                                passed: false,
                                has_finding: false,
                                skipped: true,
                                evidence: "skipped: confirmation not approved or timed out".into(),
                                potential: false,
                                needs_confirmation: false,
                            }).await;
                        }
                        continue;
                    }
                }
            }

            if !self.budget.try_take() {
                stop_reason = if self.budget.time_exceeded() {
                    StopReason::DurationExceeded
                } else {
                    StopReason::BudgetExhausted
                };
                break;
            }

            // Per-host rate limiting
            if let Some(limiter) = &self.limiter {
                limiter.until_ready(&host).await;
            }

            // Send with retry (RequestExecutor handles timeout + retry)
            requests_sent += 1;
            let result = self.executor.execute(request.clone()).await;

            let (status, body, response_headers, error) = match result {
                Ok(resp) => {
                    let body = String::from_utf8_lossy(&resp.body).into_owned();
                    let headers = format_response_headers(&resp.headers);
                    (resp.status, body, headers, None::<String>)
                }
                Err(ScanError::Transport(e)) => (0, String::new(), String::new(), Some(e.to_string())),
                Err(ScanError::Timeout) => (0, String::new(), String::new(), Some("timeout".into())),
                Err(e) => (0, String::new(), String::new(), Some(e.to_string())),
            };

            let passed = if error.is_some() {
                false
            } else {
                check_oracle(&test.oracle, status, &body)
            };
            // potential = oracle has expectations, no error, but oracle didn't match
            // (status differs from expected, or body doesn't contain expected string)
            let potential = error.is_none()
                && !passed
                && status != 0
                && (test.oracle.expect_status.is_some() || test.oracle.expect_contains.is_some());
            let evidence = if let Some(err) = error.as_ref() {
                format!("transport error: {err}")
            } else {
                // Truncate body_snippet at a natural boundary (> or space) to avoid mid-attribute cuts
                let snippet = if body.len() > 200 {
                    let raw = &body[..200];
                    // Find last '>' or ' ' to cut at a clean boundary
                    let cut = raw.rfind('>').or_else(|| raw.rfind(' ')).unwrap_or(150);
                    format!("{}…", &body[..cut + 1])
                } else {
                    body.clone()
                };
                format!(
                    "status={status}, body_len={}, snippet={}",
                    body.len(),
                    snippet
                )
            };
            let severity = severity_from_str(&test.severity);

            // Only emit a Finding when the oracle indicates a potential issue.
            // For jwt_exposure we flag when body contains token regardless of status.
            // For idor/auth_bypass we flag when status differs from expectation (potential issue).
            // For csrf: 200/201 for POST without CSRF token = always a finding.
            // UNIVERSAL: every response body also goes through the secret
            // scanner (gitleaks + regex + CWE + Livewire/RSC-aware signals) —
            // a leak in ANY response is a finding even when the per-test
            // oracle passes. Cached per body hash, so repeated bodies cost
            // nothing.
            let secret_scan = api_tester_analysis::SecretScanner::analyze(&body);
            let overfetch_scan = api_tester_analysis::OverfetchingAnalyzer::analyze(&body);
            let oracle_should_report = match test.flaw.as_str() {
                "jwt_exposure" => body.contains("accessToken") || body.contains("eyJ"),
                "idor" | "auth_bypass" => passed || potential,
                "csrf" => status == 200 || status == 201,
                "open_redirect" => body.contains("evil.com") || body.contains("callbackUrl") || body.contains("redirect"),
                _ => passed,
            };
            let scan_suspicious = secret_scan.is_suspicious || overfetch_scan.is_suspicious;
            let should_report = oracle_should_report || scan_suspicious;
            let mut evidence = evidence;

            // RSC endpoint detection: _rsc parameter indicates React Server Component
            // payload which may leak session data, tokens, or sensitive business data
            let is_rsc_endpoint = test.target.path.contains("_rsc");

            let skill_name = if scan_suspicious && is_rsc_endpoint {
                "rsc_data_leakage".to_owned()
            } else if scan_suspicious && !oracle_should_report {
                "secret_leak".to_owned()
            } else {
                test.flaw.clone()
            };

            if scan_suspicious {
                let mut signals: Vec<String> = secret_scan.summary_signals.clone();
                signals.extend(overfetch_scan.detected_signals.iter().cloned());
                signals.sort();
                signals.dedup();
                if !overfetch_scan.exposed_passwords.is_empty() {
                    signals.push(format!(
                        "exposed_values={:?}",
                        overfetch_scan.exposed_passwords
                    ));
                }
                evidence.push_str(&format!(" | secret-signals: {}", signals.join(", ")));
            }

            // RSC-specific evidence and severity boost
            if is_rsc_endpoint && scan_suspicious {
                evidence.push_str(&format!(
                    " | RSC endpoint detected: {} may leak session data in embedded payload",
                    test.target.path
                ));
            }
            let finding = if should_report {
                // Check for false positives before creating finding
                let is_fp = is_likely_false_positive(&test.flaw, status, &body, &test.target.path);
                if is_fp {
                    // Log but don't create finding for likely false positives
                    eprintln!("[security] likely false positive: {} on {} (status={})", test.flaw, test.target.path, status);
                    None
                } else {
                    // Use RSC-specific remediation for RSC data leakage findings
                    let remediation = if is_rsc_endpoint && scan_suspicious {
                        remediation_for("rsc_data_leakage")
                    } else {
                        remediation_for(&test.flaw)
                    };
                    Some(Finding {
                        id: uuid::Uuid::new_v4().to_string(),
                        title: format!("{} on {}", skill_name, target_label),
                        description: test.payload_hint.clone(),
                        severity: severity.clone(),
                        skill_name,
                        flow_id: test.id.clone(),
                        flow_path: test.target.path.clone(),
                        flow_method: test.target.method.clone(),
                        payload_value: test.payload.clone(),
                        payload_description: Some(test.payload_hint.clone()),
                        evidence: Some(evidence.clone()),
                        remediation,
                    })
                }
            } else {
                None
            };
            let is_html_page = body.len() > 10000
                || body.contains("<!DOCTYPE")
                || body.contains("<html");
            findings.push(SecurityFinding {
                test_id: test.id.clone(),
                flaw: test.flaw.clone(),
                target: target_label,
                severity,
                passed,
                evidence,
                status,
                finding,
                potential,
                verdict: verdict_str(&test.flaw, passed, potential, status),
                explanation: explain_status(&test.flaw, status, &body),
                risk: explain_risk(&test.flaw),
                fix_suggestion: remediation_for(&test.flaw),
                payload_sent: test.payload.clone().unwrap_or_default(),
                request_url: request.url.clone(),
                request_method: test.target.method.clone(),
                // Keep the complete response for Raw/Render views. AI context
                // applies its own redaction and size limit later.
                response_body: body,
                request_headers: format_request_headers(&request),
                response_headers,
                cookies: format_cookies(&request),
                is_html_page,
                location: test.location.clone().unwrap_or_default(),
            });

            // Send per-test event for real-time WS progress
            if let Some(tx) = &self.event_tx {
                let _ = tx
                    .send(SecurityEvent {
                        test_id: test.id.clone(),
                        flaw: test.flaw.clone(),
                        target: findings.last().unwrap().target.clone(),
                        status,
                        passed,
                        has_finding: findings.last().unwrap().finding.is_some(),
                        skipped: false,
                        evidence: findings.last().unwrap().evidence.clone(),
                        potential,
                        needs_confirmation: false,
                    })
                    .await;
            }
        }

        SecurityRunOutcome {
            findings,
            requests_sent,
            skipped,
            stop_reason,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Oracle, SecurityTest, SecurityTestPlan, Target};
    use api_tester_ports::HttpResponse;
    use api_tester_test_support::MockHttpClient;
    use std::sync::Arc;
    use tokio_util::sync::CancellationToken;

    fn ok(body: &str) -> HttpResponse {
        HttpResponse {
            status: 200,
            headers: vec![],
            body: body.as_bytes().to_vec(),
        }
    }

    fn default_config() -> SecurityRunConfig {
        SecurityRunConfig {
            timeout_secs: 5,
            max_requests: 10,
            per_host_requests_per_sec: 0,
            duration_budget_secs: None,
            retry_limit: 0,
            scope: ScopeConfig {
                include_hosts: vec!["fit\\.neu\\.edu\\.vn".into()],
                ..ScopeConfig::default()
            },
            auth_cookies: std::collections::BTreeMap::new(),
            auth_headers: Vec::new(),
        }
    }

    #[tokio::test]
    async fn detects_jwt_exposure() {
        let client = Arc::new(MockHttpClient::with_responses(vec![ok(
            r#"{"accessToken":"eyJabc"}"#,
        )]));
        let exec =
            SecurityExecutor::new(client, CancellationToken::new(), default_config()).unwrap();
        let plan = SecurityTestPlan {
            plan_id: "p".into(),
            base_url: "https://fit.neu.edu.vn".into(),
            tests: vec![SecurityTest {
                id: "t1".into(),
                flaw: "jwt_exposure".into(),
                target: Target {
                    method: "GET".into(),
                    path: "/codelab/api/auth/session".into(),
                },
                severity: "High".into(),
                payload_hint: "".into(),
                payload: None,
                location: None,
                oracle: Oracle {
                    expect_contains: Some("accessToken".into()),
                    expect_status: None,
                },
                requires_confirmation: false,
            }],
        };
        let outcome = exec.execute(&plan).await;
        assert_eq!(outcome.findings.len(), 1);
        assert!(outcome.findings[0].finding.is_some());
        assert_eq!(outcome.stop_reason, StopReason::Completed);
    }

    #[tokio::test]
    async fn budget_exhausted() {
        let client = Arc::new(MockHttpClient::with_responses(vec![
            ok("ok"); 3
        ]));
        let config = SecurityRunConfig {
            max_requests: 2,
            ..default_config()
        };
        let exec =
            SecurityExecutor::new(client, CancellationToken::new(), config).unwrap();
        let plan = SecurityTestPlan {
            plan_id: "p".into(),
            base_url: "https://fit.neu.edu.vn".into(),
            tests: vec![
                SecurityTest {
                    id: "t1".into(),
                    flaw: "xss".into(),
                    target: Target { method: "GET".into(), path: "/a".into() },
                    severity: "High".into(),
                    payload_hint: "".into(),
                    payload: Some("<x>".into()),
                    location: Some("query:x".into()),
                    oracle: Oracle::default(),
                    requires_confirmation: false,
                },
                SecurityTest {
                    id: "t2".into(),
                    flaw: "sqli".into(),
                    target: Target { method: "GET".into(), path: "/b".into() },
                    severity: "High".into(),
                    payload_hint: "".into(),
                    payload: Some("' OR 1=1".into()),
                    location: Some("query:q".into()),
                    oracle: Oracle::default(),
                    requires_confirmation: false,
                },
                SecurityTest {
                    id: "t3".into(),
                    flaw: "xss".into(),
                    target: Target { method: "GET".into(), path: "/c".into() },
                    severity: "High".into(),
                    payload_hint: "".into(),
                    payload: Some("<y>".into()),
                    location: Some("query:y".into()),
                    oracle: Oracle::default(),
                    requires_confirmation: false,
                },
            ],
        };
        let outcome = exec.execute(&plan).await;
        assert_eq!(outcome.requests_sent, 2);
        assert_eq!(outcome.stop_reason, StopReason::BudgetExhausted);
    }

    #[tokio::test]
    async fn scope_skip() {
        let client = Arc::new(MockHttpClient::with_responses(vec![ok("ok")]));
        let config = SecurityRunConfig {
            max_requests: 10,
            ..default_config()
        };
        let exec =
            SecurityExecutor::new(client, CancellationToken::new(), config).unwrap();
        let plan = SecurityTestPlan {
            plan_id: "p".into(),
            base_url: "https://evil.com".into(),
            tests: vec![SecurityTest {
                id: "t1".into(),
                flaw: "xss".into(),
                target: Target { method: "GET".into(), path: "/x".into() },
                severity: "High".into(),
                payload_hint: "".into(),
                payload: Some("<x>".into()),
                location: Some("query:x".into()),
                oracle: Oracle::default(),
                requires_confirmation: false,
            }],
        };
        let outcome = exec.execute(&plan).await;
        assert_eq!(outcome.skipped, 1);
        assert_eq!(outcome.requests_sent, 0);
    }

    #[tokio::test]
    async fn injects_payload_in_query() {
        let client = Arc::new(MockHttpClient::with_responses(vec![ok("ok")]));
        let exec =
            SecurityExecutor::new(client, CancellationToken::new(), default_config()).unwrap();
        let plan = SecurityTestPlan {
            plan_id: "p".into(),
            base_url: "https://fit.neu.edu.vn".into(),
            tests: vec![SecurityTest {
                id: "t1".into(),
                flaw: "sqli".into(),
                target: Target { method: "GET".into(), path: "/api/tags".into() },
                severity: "High".into(),
                payload_hint: "sqli".into(),
                payload: Some("' OR 1=1 --".into()),
                location: Some("query:q".into()),
                oracle: Oracle {
                    expect_status: Some(404),
                    expect_contains: None,
                },
                requires_confirmation: false,
            }],
        };
        let outcome = exec.execute(&plan).await;
        assert_eq!(outcome.findings.len(), 1);
        assert!(outcome.findings[0].finding.is_none()); // oracle doesn't trigger (status 200 != 404)
        assert_eq!(outcome.requests_sent, 1);
    }

    #[tokio::test]
    async fn require_allowlist_rejects_empty() {
        let client = Arc::new(MockHttpClient::with_responses(vec![]));
        let config = SecurityRunConfig {
            scope: ScopeConfig::default(), // empty include_hosts
            ..default_config()
        };
        let result = SecurityExecutor::new(client, CancellationToken::new(), config);
        assert!(result.is_err());
    }
}
