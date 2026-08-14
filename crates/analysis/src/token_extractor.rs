use std::collections::BTreeMap;

use api_tester_domain::{ExtractedToken, HttpFlow, TokenType};
use regex::Regex;
use serde_json::Value;

const JWT_PATTERN: &str = r"eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}";

const AUTH_HEADER_KEYS: &[&str] = &["authorization", "x-api-key", "x-auth-token"];

const COOKIE_TOKEN_KEYS: &[&str] = &["session", "sessionid", "jwt", "csrf", "csrftoken", "token"];

fn token_json_keys() -> BTreeMap<&'static str, TokenType> {
    BTreeMap::from([
        ("access_token", TokenType::OauthAccess),
        ("token", TokenType::OauthAccess),
        ("id_token", TokenType::Jwt),
        ("refresh_token", TokenType::OauthRefresh),
        ("csrf_token", TokenType::Csrf),
        ("csrf", TokenType::Csrf),
        ("api_key", TokenType::ApiKey),
        ("apiKey", TokenType::ApiKey),
    ])
}

/// Extracts tokens from a response body, headers and cookies, mirroring the
/// Python reference extractor.
pub struct TokenExtractor {
    jwt: Regex,
}

impl Default for TokenExtractor {
    fn default() -> Self {
        Self::new()
    }
}

impl TokenExtractor {
    pub fn new() -> Self {
        Self {
            jwt: Regex::new(JWT_PATTERN).expect("JWT pattern must be valid"),
        }
    }

    pub fn extract_from_flow(&self, flow: &HttpFlow) -> Vec<ExtractedToken> {
        let mut tokens = Vec::new();
        tokens.extend(self.extract_from_body(flow));
        tokens.extend(self.extract_from_headers(flow));
        tokens.extend(self.extract_from_cookies(flow));
        tokens
    }

    fn extract_from_body(&self, flow: &HttpFlow) -> Vec<ExtractedToken> {
        let Some(body) = flow.response_body.as_deref() else {
            return Vec::new();
        };

        let mut tokens = Vec::new();
        if let Ok(parsed) = serde_json::from_str::<Value>(body) {
            if parsed.is_object() {
                self.walk_json(&parsed, &flow.fingerprint(), "", &mut tokens);
            }
        }

        for capture in self.jwt.find_iter(body) {
            let value = capture.as_str().to_owned();
            if !tokens
                .iter()
                .any(|token: &ExtractedToken| token.value == value)
            {
                tokens.push(ExtractedToken {
                    token_type: TokenType::Jwt,
                    value,
                    source_flow_id: flow.fingerprint(),
                    location: "response_body".to_owned(),
                    json_path: None,
                    header_name: None,
                });
            }
        }

        tokens
    }

    fn walk_json(
        &self,
        obj: &Value,
        source_flow_id: &str,
        path_prefix: &str,
        out: &mut Vec<ExtractedToken>,
    ) {
        match obj {
            Value::Object(map) => {
                for (key, value) in map {
                    let path = if path_prefix.is_empty() {
                        format!("$.{key}")
                    } else {
                        format!("{path_prefix}.{key}")
                    };
                    if let Value::String(text) = value {
                        if text.len() > 5 {
                            if let Some(token_type) = token_json_keys().get(key.as_str()) {
                                out.push(ExtractedToken {
                                    token_type: token_type.clone(),
                                    value: text.clone(),
                                    source_flow_id: source_flow_id.to_owned(),
                                    location: "response_body".to_owned(),
                                    json_path: Some(path),
                                    header_name: None,
                                });
                            }
                        }
                    } else if value.is_object() || value.is_array() {
                        self.walk_json(value, source_flow_id, &path, out);
                    }
                }
            }
            Value::Array(items) => {
                for (index, item) in items.iter().enumerate() {
                    self.walk_json(
                        item,
                        source_flow_id,
                        &format!("{path_prefix}[{index}]"),
                        out,
                    );
                }
            }
            _ => {}
        }
    }

    fn extract_from_headers(&self, flow: &HttpFlow) -> Vec<ExtractedToken> {
        let mut tokens = Vec::new();
        for (name, value) in &flow.response_headers {
            let lower = name.to_ascii_lowercase();
            if AUTH_HEADER_KEYS.contains(&lower.as_str()) && !value.is_empty() {
                let token_type = if self.jwt.is_match(value) {
                    TokenType::Jwt
                } else {
                    TokenType::ApiKey
                };
                tokens.push(ExtractedToken {
                    token_type,
                    value: value.clone(),
                    source_flow_id: flow.fingerprint(),
                    location: "response_header".to_owned(),
                    json_path: None,
                    header_name: Some(name.clone()),
                });
            }
        }
        tokens
    }

    fn extract_from_cookies(&self, flow: &HttpFlow) -> Vec<ExtractedToken> {
        let values: BTreeMap<String, String> = if !flow.response_cookie_values.is_empty() {
            flow.response_cookie_values.clone()
        } else {
            // Python parity fallback: parse the raw Set-Cookie header when the
            // structured cookie map was not populated.
            let mut map = BTreeMap::new();
            if let Some(set_cookie) = flow
                .response_headers
                .iter()
                .find(|(name, _)| name.eq_ignore_ascii_case("set-cookie"))
                .map(|(_, value)| value)
            {
                for part in set_cookie.split(';') {
                    if let Some((key, value)) = part.split_once('=') {
                        map.insert(key.trim().to_owned(), value.trim().to_owned());
                    }
                }
            }
            map
        };

        let mut tokens = Vec::new();
        for (key, value) in &values {
            let lower = key.to_ascii_lowercase();
            if COOKIE_TOKEN_KEYS.contains(&lower.as_str()) && value.len() > 5 {
                let token_type = if self.jwt.is_match(value) {
                    TokenType::Jwt
                } else {
                    TokenType::SessionCookie
                };
                tokens.push(ExtractedToken {
                    token_type,
                    value: value.clone(),
                    source_flow_id: flow.fingerprint(),
                    location: "set_cookie".to_owned(),
                    json_path: None,
                    header_name: Some(key.clone()),
                });
            }
        }
        tokens
    }
}

#[cfg(test)]
mod tests {
    use super::TokenExtractor;
    use api_tester_domain::{HttpFlow, HttpMethod, TokenType};

    fn make_flow(
        body: Option<&str>,
        headers: Vec<(&str, &str)>,
        cookie_values: Vec<(&str, &str)>,
    ) -> HttpFlow {
        let mut flow = HttpFlow::new(HttpMethod::Post, "api.example.com", "/api/login");
        flow.full_url = "https://api.example.com/api/login".to_owned();
        flow.response_status = 200;
        flow.response_headers = headers
            .into_iter()
            .map(|(name, value)| (name.to_owned(), value.to_owned()))
            .collect();
        flow.response_cookie_values = cookie_values
            .into_iter()
            .map(|(name, value)| (name.to_owned(), value.to_owned()))
            .collect();
        flow.response_body = body.map(str::to_owned);
        flow
    }

    #[test]
    fn extract_oauth_access_token() {
        let flow = make_flow(Some(r#"{"access_token":"abc123token"}"#), vec![], vec![]);
        let tokens = TokenExtractor::new().extract_from_flow(&flow);
        assert!(
            tokens
                .iter()
                .any(|t| t.token_type == TokenType::OauthAccess && t.value == "abc123token")
        );
    }

    #[test]
    fn extract_jwt_from_body() {
        let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123";
        let flow = make_flow(Some(&format!(r#"{{"token":"{jwt}"}}"#)), vec![], vec![]);
        let tokens = TokenExtractor::new().extract_from_flow(&flow);
        assert!(tokens.iter().any(|t| t.value == jwt));
    }

    #[test]
    fn extract_jwt_raw_string() {
        let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123";
        let flow = make_flow(Some(&format!("plain text {jwt} here")), vec![], vec![]);
        let tokens = TokenExtractor::new().extract_from_flow(&flow);
        assert!(
            tokens
                .iter()
                .any(|t| t.token_type == TokenType::Jwt && t.value == jwt)
        );
    }

    #[test]
    fn nested_json_token() {
        let flow = make_flow(
            Some(r#"{"data":{"access_token":"nested_token_123"}}"#),
            vec![],
            vec![],
        );
        let tokens = TokenExtractor::new().extract_from_flow(&flow);
        assert!(tokens.iter().any(|t| t.value == "nested_token_123"));
    }

    #[test]
    fn csrf_token() {
        let flow = make_flow(Some(r#"{"csrf_token":"csrf_secret_123"}"#), vec![], vec![]);
        let tokens = TokenExtractor::new().extract_from_flow(&flow);
        assert!(
            tokens
                .iter()
                .any(|t| t.token_type == TokenType::Csrf && t.value == "csrf_secret_123")
        );
    }

    #[test]
    fn session_cookie() {
        let flow = make_flow(None, vec![], vec![("sessionid", "abc123def456")]);
        let tokens = TokenExtractor::new().extract_from_flow(&flow);
        assert!(
            tokens
                .iter()
                .any(|t| t.token_type == TokenType::SessionCookie && t.value == "abc123def456")
        );
    }

    #[test]
    fn session_cookie_falls_back_to_set_cookie_header() {
        let flow = make_flow(
            None,
            vec![("Set-Cookie", "sessionid=abc123def456; Path=/")],
            vec![],
        );
        let tokens = TokenExtractor::new().extract_from_flow(&flow);
        assert!(
            tokens
                .iter()
                .any(|t| t.token_type == TokenType::SessionCookie && t.value == "abc123def456")
        );
    }

    #[test]
    fn api_key_header() {
        let flow = make_flow(None, vec![("X-API-Key", "key_abc123")], vec![]);
        let tokens = TokenExtractor::new().extract_from_flow(&flow);
        assert!(
            tokens
                .iter()
                .any(|t| t.token_type == TokenType::ApiKey && t.value == "key_abc123")
        );
    }

    #[test]
    fn empty_body() {
        let flow = make_flow(None, vec![], vec![]);
        assert!(TokenExtractor::new().extract_from_flow(&flow).is_empty());
    }

    #[test]
    fn invalid_json() {
        let flow = make_flow(Some("not valid json"), vec![], vec![]);
        let tokens = TokenExtractor::new().extract_from_flow(&flow);
        assert!(tokens.is_empty());
    }

    #[test]
    fn multiple_tokens() {
        let flow = make_flow(
            Some(r#"{"access_token":"access_123","refresh_token":"refresh_456"}"#),
            vec![],
            vec![],
        );
        let tokens = TokenExtractor::new().extract_from_flow(&flow);
        let values: Vec<&str> = tokens.iter().map(|t| t.value.as_str()).collect();
        assert!(values.contains(&"access_123"));
        assert!(values.contains(&"refresh_456"));
    }
}
