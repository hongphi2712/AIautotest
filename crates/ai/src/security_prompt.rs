//! Security test plan prompt: turns a compact flow context into a structured
//! JSON plan of basic security checks (no free-form code). Uses the same
//! token-efficient, non-streaming, JSON-object response format as workflow
//! generation, with a bounded repair loop on the server.

use crate::prompt::{FlowContext, format_security_context};

const SECURITY_SYSTEM_PROMPT: &str = r#"You are a security testing planner. Given HTTP traffic and a base URL, produce ONE JSON object with this schema:
{"plan_id":"uuid","base_url":"url","tests":[{"id":"t1","flaw":"jwt_exposure|idor|auth_bypass|xss|sqli|csrf|open_redirect|rate_limit|excessive_data_exposure|secret_leak|cwe_debug_exposure","target":{"method":"GET","path":"/..."},"severity":"Critical|High|Medium|Low|Info","payload_hint":"description","payload":"concrete payload","location":"query:param_name|body:field_name|path|header:Header-Name|cookie:cookie_name","oracle":{"expect_status":403,"expect_contains":"text"},"requires_confirmation":false}]}

RULES (in priority order):
 - RULE #1 (MANDATORY): RSC ENDPOINTS — If "RSC ENDPOINTS DETECTED" appears in the traffic context, you MUST include at least ONE test for the most important RSC endpoint (e.g. /codelab/contests?_rsc=xxxx). Use flaw "secret_leak", severity "Critical", oracle: {"expect_status": 200, "expect_contains": "accessToken"}. Payload hint: "RSC endpoint may leak session data in embedded payload". This is non-negotiable — RSC endpoints are the #1 priority finding.
 - RULE #1b: SHOP COMMERCE — If ENDPOINT CATALOG contains /workshop/api/shop/*, generate ≥2 shop tests: (a) idor/bola GET /workshop/api/shop/orders/{id} via order_id path payload, (b) excessive_data_exposure GET /workshop/api/shop/products with oracle expect_status 200 expect_contains price/credit. Prefer GET, payload hint concrete Vietnamese.
 - RULE #1c: MASS EXPOSURE — If ANOMALIES OBSERVED contains mass_exposure|mass_pii_exposure|sensitive_payload_in_html|sensitive_in_collection|exposed_passwords_count, you MUST generate at least ONE excessive_data_exposure test for the affected endpoint (e.g. GET /community/api/v2/community/posts/recent?limit=30 or GET /workshop/api/shop/products) with oracle {"expect_status":200,"expect_contains":"email|price|credit"}. This covers overfetching.rs:194 mass_pii_exposure and overfetching.rs:245 sensitive_in_collection.
 - RULE #1d: CODELAB LEAK — If ENDPOINT CATALOG contains /codelab/contests and ANOMALIES contains rsc_long_text_chunk or problem, you MUST generate excessive_data_exposure for /codelab/contests?_rsc=10s8m and /codelab/contests?page=2&_rsc=3askl with oracle {"expect_status":200,"expect_contains":"contest|problem"}.
 - RULE #2: Output ONLY the raw JSON object, no commentary, markdown fences or extra text.
 - RULE #3: Generate 8-12 concise tests covering the most critical flaws (chia 2 plan: Plan A 8-12 SAFE, Plan B 8-12 DEFERRED+secret nếu cần 21). Keep payload_hint short under 12 words. Nếu cần 18+3, sinh 8-12/plan, không dồn 21 vào 1 plan để tránh AI ngu.
- RULE #4: payload must be CONCRETE (e.g. "' OR 1=1 --", "<svg onload=alert(1)>").
- RULE #5: CRITICAL: ALL tests MUST be non-destructive and read-only when possible. NEVER create tests that modify, delete, corrupt, or create data.
- RULE #6: For CSRF: Test by checking if CSRF token is present in forms/headers, NOT by actually submitting the form. Use GET to check for token, not POST to submit. If you must use POST, set "requires_confirmation": true.
- RULE #7: For auth_bypass: Send requests WITHOUT credentials and check response does NOT leak sensitive data. Do NOT attempt login.
- RULE #8: For rate_limit: Send only 2-3 requests to check for 429 response. Do NOT flood the endpoint.
- RULE #9: For sqli/xss: Use detection payloads that cause errors or reflections, NOT payloads that modify data.
- RULE #10: For idor: Test with different IDs to check access control, NOT to modify data.
- RULE #11: For jwt_exposure: flag endpoints that return tokens only when authenticated.
- RULE #12: For excessive_data_exposure: trigger when ANOMALIES OBSERVED indicates overfetching, leaked passwords, or excessive text chunks in summary endpoints.
- RULE #13: For secret_leak / cwe_debug_exposure: trigger when ANOMALIES OBSERVED lists gitleaks_leak, secret_leak, or cwe_leak.
- RULE #14: HTML/RSC PAGES ARE VALID TARGETS: when a rendered page endpoint shows exposed_passwords_count, mass_pii_exposure, api_payload_in_html, sensitive_payload_in_html, sensitive_in_collection, or long_text_field in ANOMALIES OBSERVED — create a GET test with flaw excessive_data_exposure or secret_leak.
 - RULE #15: NEVER target endpoints that change passwords, delete accounts, modify settings, or perform financial transactions without setting "requires_confirmation": true. For DEFERRED 6 labs (Ch6 DoS, Ch7 DELETE video, Ch9 balance, Ch10 update, Ch11 SSRF, Ch13 SQLi UPDATE) ALWAYS set requires_confirmation:true để auto gate 60s.
- RULE #16: Prefer GET requests. Only use POST/PUT/DELETE when absolutely necessary for detection, and only on non-destructive endpoints.
- RULE #17: For sqli/xss/csrf/open_redirect/rate_limit: identify the most relevant parameters from actual captured traffic.
- RULE #18: Only target hosts/paths visible in the provided traffic context. Never invent paths not present in the data.
- RULE #19: Reply in Vietnamese for payload_hint, English for JSON keys.
- RULE #20: RESPONSE ANALYSIS — DO NOT flag vulnerabilities based on these patterns:
  * 4xx status (400/401/403/404) for unauthenticated request = endpoint is PROTECTED → skip jwt_exposure test
  * 500 status = server error → skip open_redirect test (500 is not a redirect)
  * JSON content-type or body starts with {/[ = JSON API → skip xss test (JSON does not render HTML)
  * Response body matches normal data pattern {"data":[...]} with no SQL errors = skip sqli test
  * CSRF endpoint only accepts POST → skip any GET-based CSRF test
  * Rate limit test: if no 429 after 3 requests, report finding; if 429 received, report safe
- RULE #21: When generating tests, prefer tests that have clear oracle conditions (expect_status, expect_contains) over vague tests.
"#;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityPrompt {
    pub system: String,
    pub user: String,
}

pub fn build_security_prompt(
    base_url: &str,
    context: Option<&FlowContext>,
    repair_hint: Option<&str>,
) -> SecurityPrompt {
    let system = format!("{SECURITY_SYSTEM_PROMPT}\n");

    let mut user = String::with_capacity(8192);
    user.push_str(&format!("Base URL: {base_url}\n\n"));
    if let Some(ctx) = context {
        user.push_str("Captured traffic summary for reference (keep the Base URL above):\n");
        user.push_str(&format_security_context(ctx, 100));
        user.push('\n');
        // Check if RSC endpoints are present and add explicit instruction
        let has_rsc = ctx.steps.iter().any(|s| s.path.contains("_rsc"));
        if has_rsc {
            user.push_str("IMPORTANT: RSC endpoints detected in traffic above. You MUST include at least ONE test for an RSC endpoint (any path with _rsc parameter). Use flaw secret_leak, severity Critical, oracle expect_status 200, expect_contains accessToken. This is MANDATORY per RULE #1.\n\n");
        }
        let has_codelab_leak = ctx.steps.iter().any(|s| s.path.contains("10s8m") || s.path.contains("3askl"));
        if has_codelab_leak {
            user.push_str("IMPORTANT: CODELAB LEAK — /codelab/contests?_rsc=10s8m and /codelab/contests?page=2&_rsc=3askl leak contest/problem via RSC. You MUST include tests for those 2 with flaw excessive_data_exposure, oracle 200 contains contest|problem (see visible capture).\n\n");
        }
    } else {
        user.push_str("No traffic summary available. Generate tests based on common web vulnerabilities.\n\n");
    }
    if let Some(hint) = repair_hint {
        user.push_str("\nYour previous response was invalid. Fix ALL of these issues and return the corrected JSON only:\n");
        user.push_str(hint);
        user.push('\n');
    } else {
        user.push_str("Analyze the traffic above and respond with the security test plan JSON object only.");
    }
    SecurityPrompt { system, user }
}

#[cfg(test)]
mod tests {
    use super::build_security_prompt;
    use crate::prompt::FlowContext;

    #[test]
    fn prompt_contains_schema_and_base_url() {
        let p = build_security_prompt("https://api.example.com", None, None);
        assert!(p.system.contains("jwt_exposure"));
        assert!(p.user.contains("https://api.example.com"));
        assert!(p.user.contains("security test plan JSON object only"));
    }

    #[test]
    fn prompt_includes_context_and_repair() {
        let ctx = FlowContext::default();
        let p = build_security_prompt("https://a.b", Some(&ctx), Some("missing flaw"));
        assert!(p.user.contains("Captured traffic summary"));
        assert!(p.user.contains("previous response was invalid"));
        assert!(p.user.contains("missing flaw"));
    }

    #[test]
    fn prompt_enforces_minimum_tests() {
        let p = build_security_prompt("https://example.com", None, None);
        assert!(p.system.contains("8-12 concise tests"));

        assert!(p.system.contains("CONCRETE"));
    }

    #[test]
    fn prompt_has_trigger_rules() {
        let p = build_security_prompt("https://example.com", None, None);
        assert!(p.system.contains("payload_hint"));
        assert!(p.system.contains("jwt_exposure"));
    }
}
