use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use api_tester_ports::{HttpClient, HttpRequest};
use serde_json::Value;

use crate::error::AuthError;
use crate::model::LoginFlow;

const EXPIRED_PATTERNS: &[&str] = &[
    "token expired",
    "unauthorized",
    "login required",
    "invalid token",
];

/// Manages authentication: runs login flows and refreshes tokens when a
/// session looks expired. HTTP calls go through the `HttpClient` port so the
/// manager is testable without real network access.
pub struct AuthManager {
    login_flow: Mutex<Option<LoginFlow>>,
    current_tokens: Mutex<BTreeMap<String, String>>,
    client: Arc<dyn HttpClient>,
}

impl AuthManager {
    pub fn new(client: Arc<dyn HttpClient>) -> Self {
        Self {
            login_flow: Mutex::new(None),
            current_tokens: Mutex::new(BTreeMap::new()),
            client,
        }
    }

    pub fn set_login_flow(&self, flow: LoginFlow) {
        *self
            .login_flow
            .lock()
            .unwrap_or_else(|poison| poison.into_inner()) = Some(flow);
        self.current_tokens
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .clear();
    }

    pub fn has_login_flow(&self) -> bool {
        self.login_flow
            .lock()
            .map(|flow| flow.is_some())
            .unwrap_or(false)
    }

    pub fn is_session_expired(&self, status: u16, body: &str) -> bool {
        if status == 401 || status == 403 {
            return true;
        }
        let body_lower = body.to_ascii_lowercase();
        EXPIRED_PATTERNS
            .iter()
            .any(|pattern| body_lower.contains(pattern))
    }

    /// Runs the login flow, stores and returns the extracted tokens.
    pub async fn refresh_auth(&self) -> Result<BTreeMap<String, String>, AuthError> {
        let flow = self
            .login_flow
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .clone()
            .ok_or(AuthError::NoLoginFlow)?;

        let mut tokens = BTreeMap::new();
        for (index, step) in flow.steps.iter().enumerate() {
            // Python sends `json=step.body or None`: an empty object/dict is
            // falsy and means no body.
            let empty = step.body.is_null()
                || step
                    .body
                    .as_object()
                    .map(serde_json::Map::is_empty)
                    .unwrap_or(false);
            let body = if empty {
                None
            } else {
                Some(
                    serde_json::to_vec(&step.body)
                        .map_err(|error| AuthError::StepFailed(index, error.to_string()))?,
                )
            };
            let request = HttpRequest {
                method: step.method.clone(),
                url: format!("{}{}", flow.base_url.trim_end_matches('/'), step.path),
                headers: step.headers.clone(),
                body,
            };
            let response = self.client.send(request).await?;

            if let Some(key) = &step.extract_token {
                if let Ok(data) = serde_json::from_slice::<Value>(&response.body) {
                    if let Some(value) = data.get(key).and_then(Value::as_str) {
                        tokens.insert(key.clone(), value.to_owned());
                    }
                }
            }
        }

        *self
            .current_tokens
            .lock()
            .unwrap_or_else(|poison| poison.into_inner()) = tokens.clone();
        Ok(tokens)
    }

    /// Returns cached tokens or refreshes them when none are present.
    pub async fn ensure_auth(&self) -> Result<BTreeMap<String, String>, AuthError> {
        let empty = self
            .current_tokens
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .is_empty();
        if empty {
            self.refresh_auth().await
        } else {
            Ok(self
                .current_tokens
                .lock()
                .unwrap_or_else(|poison| poison.into_inner())
                .clone())
        }
    }

    pub fn get_token(&self, name: &str) -> Option<String> {
        self.current_tokens
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .get(name)
            .cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::AuthManager;
    use crate::model::LoginFlow;
    use api_tester_ports::HttpResponse;
    use api_tester_test_support::MockHttpClient;
    use serde_json::json;
    use std::sync::Arc;

    fn manager_with(flow: Option<LoginFlow>) -> AuthManager {
        let client: Arc<dyn api_tester_ports::HttpClient> = Arc::new(MockHttpClient::default());
        let manager = AuthManager::new(client);
        if let Some(flow) = flow {
            manager.set_login_flow(flow);
        }
        manager
    }

    #[test]
    fn is_session_expired_status() {
        let manager = manager_with(None);
        assert!(manager.is_session_expired(401, ""));
        assert!(manager.is_session_expired(403, "ok"));
    }

    #[test]
    fn is_session_expired_body() {
        let manager = manager_with(None);
        assert!(manager.is_session_expired(200, "token expired"));
        assert!(manager.is_session_expired(200, "Unauthorized access"));
    }

    #[test]
    fn not_expired() {
        let manager = manager_with(None);
        assert!(!manager.is_session_expired(200, "ok"));
    }

    #[test]
    fn has_login_flow() {
        let manager = manager_with(None);
        assert!(!manager.has_login_flow());

        let flow = LoginFlow {
            base_url: "https://api.example.com".to_owned(),
            steps: vec![],
        };
        manager.set_login_flow(flow);
        assert!(manager.has_login_flow());
    }

    #[test]
    fn get_token_default_none() {
        let manager = manager_with(None);
        assert_eq!(manager.get_token("access_token"), None);
    }

    #[tokio::test]
    async fn refresh_auth_no_flow_is_error() {
        let manager = manager_with(None);
        assert!(manager.refresh_auth().await.is_err());
    }

    #[tokio::test]
    async fn refresh_auth_extracts_token_from_steps() {
        let client = Arc::new(MockHttpClient::with_responses(vec![HttpResponse {
            status: 200,
            headers: vec![],
            body: serde_json::to_vec(&json!({"access_token": "token_xyz"})).unwrap(),
        }]));
        let manager = AuthManager::new(client);
        manager.set_login_flow(LoginFlow {
            base_url: "https://api.example.com".to_owned(),
            steps: vec![crate::model::LoginStep {
                method: "POST".to_owned(),
                path: "/api/login".to_owned(),
                body: json!({"username": "admin", "password": "pass"}),
                headers: vec![],
                extract_token: Some("access_token".to_owned()),
            }],
        });

        let tokens = manager.refresh_auth().await.unwrap();
        assert_eq!(
            tokens.get("access_token").map(String::as_str),
            Some("token_xyz")
        );
        assert_eq!(
            manager.get_token("access_token").as_deref(),
            Some("token_xyz")
        );
    }

    #[tokio::test]
    async fn ensure_auth_uses_cache() {
        let client = Arc::new(MockHttpClient::with_responses(vec![HttpResponse {
            status: 200,
            headers: vec![],
            body: serde_json::to_vec(&json!({"access_token": "token_abc"})).unwrap(),
        }]));
        let manager = AuthManager::new(client);
        manager.set_login_flow(LoginFlow {
            base_url: "https://api.example.com".to_owned(),
            steps: vec![crate::model::LoginStep {
                method: "POST".to_owned(),
                path: "/api/login".to_owned(),
                body: json!({}),
                headers: vec![],
                extract_token: Some("access_token".to_owned()),
            }],
        });

        let first = manager.ensure_auth().await.unwrap();
        let second = manager.ensure_auth().await.unwrap();
        assert_eq!(
            first.get("access_token").map(String::as_str),
            Some("token_abc")
        );
        assert_eq!(second, first);
    }
}
