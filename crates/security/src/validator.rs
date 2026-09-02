use std::collections::HashSet;

use crate::types::SecurityTestPlan;

const ALLOWED_FLAWS: &[&str] = &[
    "jwt_exposure",
    "idor",
    "bola",
    "auth_bypass",
    "xss",
    "sqli",
    "nosql",
    "csrf",
    "open_redirect",
    "rate_limit",
    "excessive_data_exposure",
    "secret_leak",
    "cwe_debug_exposure",
    "mass_assignment",
    "prompt_injection",
    "jwt_forge",
];

const ALLOWED_SEVERITIES: &[&str] = &["Critical", "High", "Medium", "Low", "Info"];

#[derive(Debug, Clone, Default)]
pub struct ValidationResult {
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

impl ValidationResult {
    pub fn is_valid(&self) -> bool {
        self.errors.is_empty()
    }
}

pub fn validate_plan(plan: &SecurityTestPlan) -> ValidationResult {
    let mut result = ValidationResult::default();
    if plan.base_url.trim().is_empty() {
        result.errors.push("base_url must not be empty".into());
    } else if url::Url::parse(&plan.base_url).is_err() {
        result
            .errors
            .push(format!("base_url is not a valid URL: {}", plan.base_url));
    }
    if plan.tests.is_empty() {
        result.errors.push("tests must not be empty".into());
    }
    if plan.tests.len() > 25 {
        result.errors.push("too many tests (max 25)".into());
    }
    let mut ids = HashSet::new();
    let mut seen_targets = HashSet::new();
    for test in &plan.tests {
        if test.id.trim().is_empty() {
            result.errors.push("test id must not be empty".into());
        } else if !ids.insert(test.id.as_str()) {
            result
                .errors
                .push(format!("duplicate test id: {}", test.id));
        }
        if !ALLOWED_FLAWS.contains(&test.flaw.as_str()) {
            result.errors.push(format!(
                "test {}: unknown flaw '{}' (allowed: {})",
                test.id,
                test.flaw,
                ALLOWED_FLAWS.join(", ")
            ));
        }
        if !ALLOWED_SEVERITIES.contains(&test.severity.as_str()) && !test.severity.is_empty() {
            result.warnings.push(format!(
                "test {}: unknown severity '{}'",
                test.id, test.severity
            ));
        }
        if test.target.method.trim().is_empty() {
            result
                .errors
                .push(format!("test {}: target method must not be empty", test.id));
        }
        if test.target.path.trim().is_empty() {
            result
                .errors
                .push(format!("test {}: target path must not be empty", test.id));
        } else if !test.target.path.starts_with('/') {
            result
                .errors
                .push(format!("test {}: target path must start with '/'", test.id));
        } else {
            const ALLOWED_PREFIXES: &[&str] = &[
                "/identity/",
                "/community/",
                "/workshop/",
                "/codelab/",
                "/genai/",
                "/api/",
                "/workshop/",
            ];
            let lower = test.target.path.to_ascii_lowercase();
            let generic_invent = matches!(
                lower.as_str(),
                "/" | "/.env" | "/debug" | "/admin" | "/redirect" | "/search"
            ) || lower.starts_with("/.env")
                || lower.starts_with("/debug")
                || lower.starts_with("/admin");
            if generic_invent
                || !ALLOWED_PREFIXES
                    .iter()
                    .any(|p| test.target.path.starts_with(p))
            {
                result.warnings.push(format!(
                    "test {}: path '{}' looks invented (not in known prefixes) — may be FP",
                    test.id, test.target.path
                ));
            }
        }
        let key = format!("{}:{}", test.flaw, test.target.path);
        if !seen_targets.insert(key) {
            result.warnings.push(format!(
                "test {}: duplicate (flaw,target) with another test",
                test.id
            ));
        }
        if test.oracle.expect_status.is_none() && test.oracle.expect_contains.is_none() {
            result.warnings.push(format!(
                "test {}: oracle has neither expect_status nor expect_contains",
                test.id
            ));
        }
        // Payload is recommended for active flaws; warn if missing so AI can be repaired.
        if matches!(
            test.flaw.as_str(),
            "xss" | "sqli" | "nosql" | "idor" | "bola" | "open_redirect" | "mass_assignment" | "prompt_injection"
        ) && test.payload.as_ref().map(|p| p.trim().is_empty()).unwrap_or(true)
        {
            result.warnings.push(format!(
                "test {}: payload should be set for flaw '{}' (e.g. sqli \"' OR 1=1 --\", xss \"<svg onload=alert(1)>\")",
                test.id, test.flaw
            ));
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::validate_plan;
    use crate::types::{Oracle, SecurityTest, SecurityTestPlan, Target};

    fn valid_plan() -> SecurityTestPlan {
        SecurityTestPlan {
            plan_id: "p1".into(),
            base_url: "https://fit.neu.edu.vn".into(),
            tests: vec![SecurityTest {
                id: "t1".into(),
                flaw: "idor".into(),
                target: Target {
                    method: "GET".into(),
                    path: "/codelab/subjects/nhap-mon".into(),
                },
                severity: "High".into(),
                payload_hint: "".into(),
                payload: Some("6a17cbd5c8032287c4b7962f".into()),
                location: Some("path".into()),
                oracle: Oracle {
                    expect_status: Some(403),
                    expect_contains: None,
                },
                requires_confirmation: false,
            }],
        }
    }

    #[test]
    fn valid_passes() {
        assert!(validate_plan(&valid_plan()).is_valid());
    }

    #[test]
    fn rejects_unknown_flaw_and_duplicate_id() {
        let mut plan = valid_plan();
        plan.tests.push(SecurityTest {
            id: "t1".into(),
            flaw: "unknown".into(),
            target: Target {
                method: "GET".into(),
                path: "/x".into(),
            },
            severity: "".into(),
            payload_hint: "".into(),
            payload: None,
            location: None,
            oracle: Oracle::default(),
            requires_confirmation: false,
        });
        let r = validate_plan(&plan);
        assert!(r.errors.iter().any(|e| e.contains("unknown flaw")));
        assert!(r.errors.iter().any(|e| e.contains("duplicate test id")));
    }
}
