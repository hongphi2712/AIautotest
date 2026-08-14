use serde::{Deserialize, Serialize};
use serde_json::Value;

fn default_method() -> String {
    "POST".to_owned()
}

/// One step of a login flow.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LoginStep {
    #[serde(default = "default_method")]
    pub method: String,
    pub path: String,
    #[serde(default)]
    pub body: Value,
    #[serde(default)]
    pub headers: Vec<(String, String)>,
    /// JSON key to extract from the response, e.g. "access_token".
    #[serde(default)]
    pub extract_token: Option<String>,
}

impl Default for LoginStep {
    fn default() -> Self {
        Self {
            method: default_method(),
            path: String::new(),
            body: Value::Object(Default::default()),
            headers: Vec::new(),
            extract_token: None,
        }
    }
}

/// A sequence of steps used to authenticate.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LoginFlow {
    pub base_url: String,
    #[serde(default)]
    pub steps: Vec<LoginStep>,
}

#[cfg(test)]
mod tests {
    use super::{LoginFlow, LoginStep};
    use serde_json::json;

    #[test]
    fn login_flow_round_trips_as_json() {
        let flow = LoginFlow {
            base_url: "https://api.example.com".to_owned(),
            steps: vec![LoginStep {
                method: "POST".to_owned(),
                path: "/api/login".to_owned(),
                body: json!({"username": "admin"}),
                headers: vec![("Content-Type".to_owned(), "application/json".to_owned())],
                extract_token: Some("access_token".to_owned()),
            }],
        };
        let json = serde_json::to_string(&flow).unwrap();
        let decoded: LoginFlow = serde_json::from_str(&json).unwrap();
        assert_eq!(flow, decoded);
    }
}
