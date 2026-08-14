use api_tester_domain::{Finding, Severity};
use api_tester_ports::HttpResponse;
use uuid::Uuid;

use crate::mutation_engine::Mutation;

/// Detects signals in a scan response: payload reflection, SQL error
/// patterns and unexpected 5xx responses.
pub struct ResponseVerifier;

const SQL_ERROR_PATTERNS: &[&str] = &[
    "sql syntax",
    "sqlstate",
    "syntax error",
    "unclosed quotation mark",
    "mysql_fetch",
    "you have an error in your sql",
];

impl ResponseVerifier {
    pub fn verify(&self, mutation: &Mutation, response: &HttpResponse) -> Option<Finding> {
        let body = String::from_utf8_lossy(&response.body);
        let severity = self.classify(mutation, response.status, &body)?;

        let evidence: String = body
            .chars()
            .take(300)
            .map(|ch| if ch == '\n' { ' ' } else { ch })
            .collect();
        Some(Finding {
            id: Uuid::new_v4().to_string(),
            title: format!(
                "{} signal for parameter `{}`",
                mutation.payload.skill_name, mutation.param.name
            ),
            description: format!(
                "Payload `{}` injected into {} produced status {} and a response signal.",
                mutation.payload.value, mutation.param.name, response.status
            ),
            severity,
            skill_name: mutation.payload.skill_name.clone(),
            flow_id: String::new(),
            flow_path: String::new(),
            flow_method: String::new(),
            payload_value: Some(mutation.payload.value.clone()),
            payload_description: Some(mutation.payload.description.clone()),
            evidence: Some(evidence),
            remediation: String::new(),
        })
    }

    fn classify(&self, mutation: &Mutation, status: u16, body: &str) -> Option<Severity> {
        let reflected =
            !mutation.payload.value.is_empty() && body.contains(mutation.payload.value.as_str());
        if reflected {
            return Some(
                if matches!(mutation.payload.skill_name.as_str(), "sqli" | "xss") {
                    Severity::High
                } else {
                    Severity::Warning
                },
            );
        }
        let body_lower = body.to_ascii_lowercase();
        if mutation.payload.skill_name == "sqli" {
            if SQL_ERROR_PATTERNS
                .iter()
                .any(|pattern| body_lower.contains(pattern))
            {
                return Some(Severity::Warning);
            }
            if status >= 500 {
                return Some(Severity::Warning);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::ResponseVerifier;
    use crate::mutation_engine::{Mutation, MutationEngine};
    use crate::payload_source::BuiltinPayloadSource;
    use api_tester_domain::{AnalyzedParam, HttpFlow, HttpMethod, InjectionLocation, ParamType};
    use api_tester_ports::{HttpRequest, HttpResponse};
    use serde_json::json;
    use std::sync::Arc;

    fn sqli_mutation() -> Mutation {
        let flow = HttpFlow::new(HttpMethod::Get, "127.0.0.1", "/api/x");
        let mut request = HttpRequest {
            method: "GET".to_owned(),
            url: "http://127.0.0.1/api/x?q=test".to_owned(),
            headers: vec![],
            body: None,
        };
        request.url = "http://127.0.0.1/api/x?q=%27%20OR%201=1--".to_owned();
        let source = Arc::new(BuiltinPayloadSource);
        let engine = MutationEngine::new(source, 10);
        let params = vec![AnalyzedParam {
            name: "q".to_owned(),
            param_type: ParamType::String,
            location: InjectionLocation::Query,
            sample_value: Some(json!("test")),
            enum_values: vec![],
        }];
        engine
            .mutations_for(&flow, &params, &["sqli".to_owned()])
            .into_iter()
            .next()
            .unwrap()
    }

    #[test]
    fn reflection_is_high_for_sqli() {
        let mutation = sqli_mutation();
        let response = HttpResponse {
            status: 200,
            headers: vec![],
            body: format!("error near {}", mutation.payload.value).into_bytes(),
        };
        let finding = ResponseVerifier.verify(&mutation, &response).unwrap();
        assert_eq!(finding.severity, api_tester_domain::Severity::High);
        assert!(finding.payload_value.as_deref().is_some());
    }

    #[test]
    fn no_signal_yields_no_finding() {
        let mutation = sqli_mutation();
        let response = HttpResponse {
            status: 200,
            headers: vec![],
            body: b"{\"ok\":true}".to_vec(),
        };
        assert!(ResponseVerifier.verify(&mutation, &response).is_none());
    }

    #[test]
    fn sql_error_pattern_is_warning() {
        let mutation = sqli_mutation();
        let response = HttpResponse {
            status: 200,
            headers: vec![],
            body: b"you have an error in your SQL syntax".to_vec(),
        };
        let finding = ResponseVerifier.verify(&mutation, &response).unwrap();
        assert_eq!(finding.severity, api_tester_domain::Severity::Warning);
    }
}
