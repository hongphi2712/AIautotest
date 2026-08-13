use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

pub type HeaderMap = BTreeMap<String, String>;

fn new_id() -> String {
    Uuid::new_v4().to_string()
}

fn now_utc() -> DateTime<Utc> {
    Utc::now()
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum HttpMethod {
    #[serde(rename = "GET")]
    Get,
    #[serde(rename = "POST")]
    Post,
    #[serde(rename = "PUT")]
    Put,
    #[serde(rename = "DELETE")]
    Delete,
    #[serde(rename = "PATCH")]
    Patch,
    #[serde(rename = "OPTIONS")]
    Options,
    #[serde(rename = "HEAD")]
    Head,
}

impl HttpMethod {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
            Self::Put => "PUT",
            Self::Delete => "DELETE",
            Self::Patch => "PATCH",
            Self::Options => "OPTIONS",
            Self::Head => "HEAD",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HttpFlow {
    #[serde(default = "new_id")]
    pub id: String,
    #[serde(default)]
    pub session_id: String,
    #[serde(default = "now_utc")]
    pub timestamp: DateTime<Utc>,
    pub method: HttpMethod,
    #[serde(default)]
    pub host: String,
    #[serde(default)]
    pub ip: String,
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub full_url: String,
    #[serde(default)]
    pub request_headers: HeaderMap,
    #[serde(default)]
    pub request_body: Option<String>,
    #[serde(default)]
    pub request_cookies: Vec<String>,
    #[serde(default)]
    pub request_cookie_values: BTreeMap<String, String>,
    #[serde(default)]
    pub response_status: u16,
    #[serde(default)]
    pub response_headers: HeaderMap,
    #[serde(default)]
    pub response_body: Option<String>,
    #[serde(default)]
    pub response_cookies: Vec<String>,
    #[serde(default)]
    pub response_cookie_values: BTreeMap<String, String>,
    #[serde(default)]
    pub content_type: String,
}

impl HttpFlow {
    pub fn new(method: HttpMethod, host: impl Into<String>, path: impl Into<String>) -> Self {
        let host = host.into();
        let path = path.into();
        Self {
            full_url: path.clone(),
            method,
            host,
            path,
            ..Self::default()
        }
    }

    pub fn fingerprint(&self) -> String {
        let body_hash = md5::compute(self.request_body.as_deref().unwrap_or_default().as_bytes());
        format!(
            "HttpMethod.{}:{}:{body_hash:x}",
            self.method.as_str(),
            self.path
        )
    }

    pub fn has_json_response(&self) -> bool {
        self.content_type.contains("application/json")
    }

    pub fn has_json_body(&self) -> bool {
        self.request_headers
            .get("Content-Type")
            .is_some_and(|value| value.contains("application/json"))
    }

    pub fn json_body(&self) -> Option<Value> {
        if !self.has_json_body() {
            return None;
        }
        serde_json::from_str(self.request_body.as_deref()?).ok()
    }

    pub fn json_response(&self) -> Option<Value> {
        if !self.has_json_response() {
            return None;
        }
        serde_json::from_str(self.response_body.as_deref()?).ok()
    }

    /// Approximate in-memory footprint used by capture buffers to bound memory.
    pub fn size_bytes(&self) -> usize {
        let mut total = 256usize;
        total = total.saturating_add(self.session_id.len());
        total = total.saturating_add(self.host.len());
        total = total.saturating_add(self.ip.len());
        total = total.saturating_add(self.path.len());
        total = total.saturating_add(self.full_url.len());
        total = total.saturating_add(self.content_type.len());
        total = total.saturating_add(self.request_body.as_deref().map_or(0, str::len));
        total = total.saturating_add(self.response_body.as_deref().map_or(0, str::len));
        for (key, value) in self
            .request_headers
            .iter()
            .chain(self.response_headers.iter())
        {
            total = total.saturating_add(key.len()).saturating_add(value.len());
        }
        for (key, value) in self
            .request_cookie_values
            .iter()
            .chain(self.response_cookie_values.iter())
        {
            total = total.saturating_add(key.len()).saturating_add(value.len());
        }
        total
    }
}

impl Default for HttpFlow {
    fn default() -> Self {
        Self {
            id: new_id(),
            session_id: String::new(),
            timestamp: now_utc(),
            method: HttpMethod::Get,
            host: String::new(),
            ip: String::new(),
            path: String::new(),
            full_url: String::new(),
            request_headers: HeaderMap::new(),
            request_body: None,
            request_cookies: Vec::new(),
            request_cookie_values: BTreeMap::new(),
            response_status: 0,
            response_headers: HeaderMap::new(),
            response_body: None,
            response_cookies: Vec::new(),
            response_cookie_values: BTreeMap::new(),
            content_type: String::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{HttpFlow, HttpMethod};

    #[test]
    fn fingerprint_is_deterministic() {
        let mut first = HttpFlow::new(HttpMethod::Post, "example.com", "/login");
        first.request_body = Some("{\"user\":\"admin\"}".to_owned());
        let second = first.clone();

        assert_eq!(first.fingerprint(), second.fingerprint());
        assert!(first.fingerprint().starts_with("HttpMethod.POST:/login:"));
    }

    #[test]
    fn size_bytes_reflects_bodies() {
        let mut flow = HttpFlow::new(HttpMethod::Post, "example.com", "/big");
        flow.request_body = Some("x".repeat(1_000));
        flow.response_body = Some("y".repeat(2_000));
        assert!(flow.size_bytes() >= 3_000);
    }
}
