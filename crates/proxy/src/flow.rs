use std::collections::BTreeMap;
use std::sync::Arc;

use api_tester_domain::{HttpFlow, HttpMethod};
use api_tester_ports::{CaptureSink, PortError};

use crate::http::cookies::{cookie_names, cookie_values};
use crate::http::decode::{content_encoding, decode_body};
use crate::http::parse::Header;

/// Captures a request/response pair into an `HttpFlow` and pushes it through
/// the `CaptureSink` port. Bodies are decoded and capped at the configured
/// limit before storage.
pub struct FlowBuilder {
    session_id: String,
    sink: Arc<dyn CaptureSink>,
    max_body_bytes: usize,
}

pub struct FlowParts<'a> {
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub method: HttpMethod,
    pub host: &'a str,
    pub ip: &'a str,
    pub scheme: &'a str,
    pub path: &'a str,
    pub request_headers: &'a http::HeaderMap,
    pub request_body: Option<&'a [u8]>,
    pub status: u16,
    pub response_headers: &'a http::HeaderMap,
    pub response_body: Option<&'a [u8]>,
}

impl FlowBuilder {
    pub fn new(
        session_id: impl Into<String>,
        sink: Arc<dyn CaptureSink>,
        max_body_bytes: usize,
    ) -> Self {
        Self {
            session_id: session_id.into(),
            sink,
            max_body_bytes,
        }
    }

    pub async fn capture(&self, parts: FlowParts<'_>) -> Result<(), PortError> {
        let request_header_vec = headers_to_vec(parts.request_headers);
        let response_header_vec = headers_to_vec(parts.response_headers);

        let encoding = content_encoding(&response_header_vec);
        let decoded_body = parts
            .response_body
            .map(|body| decode_body(body, &encoding, self.max_body_bytes));
        let response_body = decoded_body.as_deref().map(decoded_to_string);
        let response_body_len = decoded_body.map_or(0, |body| body.len());
        let request_body = parts
            .request_body
            .map(|body| String::from_utf8_lossy(body).into_owned());

        let content_type = parts
            .response_headers
            .get("content-type")
            .map(|value| value.to_str().unwrap_or_default().to_owned())
            .unwrap_or_default();

        let flow = HttpFlow {
            id: default_flow_id(),
            session_id: self.session_id.clone(),
            timestamp: parts.timestamp,
            method: parts.method,
            host: parts.host.to_owned(),
            ip: parts.ip.to_owned(),
            path: parts.path.to_owned(),
            full_url: format!("{}://{}{}", parts.scheme, parts.host, parts.path),
            request_headers: headers_to_map(&request_header_vec),
            request_body,
            request_cookies: cookie_names(&request_header_vec, false),
            request_cookie_values: cookie_values(&request_header_vec, false),
            response_status: parts.status,
            response_headers: headers_to_map(&response_header_vec),
            response_body,
            response_body_len,
            response_cookies: cookie_names(&response_header_vec, true),
            response_cookie_values: cookie_values(&response_header_vec, true),
            content_type,
        };

        self.sink.push(flow).await
    }
}

fn default_flow_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

/// Converts a decoded body into a `String`, reusing the buffer allocation
/// when the bytes are valid UTF-8 (avoids one full-body copy per response).
fn decoded_to_string(decoded: &[u8]) -> String {
    match String::from_utf8(decoded.to_vec()) {
        Ok(text) => text,
        Err(error) => String::from_utf8_lossy(error.as_bytes()).into_owned(),
    }
}

fn headers_to_vec(headers: &http::HeaderMap) -> Vec<Header> {
    let mut out = Vec::new();
    for name in headers.keys() {
        for value in headers.get_all(name) {
            out.push(Header {
                name: name.as_str().to_owned(),
                value: String::from_utf8_lossy(value.as_bytes()).into_owned(),
            });
        }
    }
    out
}

fn headers_to_map(headers: &[Header]) -> BTreeMap<String, String> {
    let mut multi: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for header in headers {
        multi
            .entry(header.name.clone())
            .or_default()
            .push(header.value.clone());
    }
    multi
        .into_iter()
        .map(|(name, values)| (name, values.join(", ")))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::headers_to_map;
    use crate::http::parse::Header;

    #[test]
    fn duplicate_header_values_are_joined() {
        let headers = vec![
            Header::new("set-cookie", "a=1; Path=/"),
            Header::new("set-cookie", "b=2; Path=/"),
        ];
        let map = headers_to_map(&headers);
        assert_eq!(
            map.get("set-cookie").map(String::as_str),
            Some("a=1; Path=/, b=2; Path=/")
        );
    }

    #[test]
    fn distinct_headers_are_preserved() {
        let headers = vec![
            Header::new("Content-Type", "application/json"),
            Header::new("X-Trace", "abc"),
        ];
        let map = headers_to_map(&headers);
        assert_eq!(
            map.get("Content-Type").map(String::as_str),
            Some("application/json")
        );
        assert_eq!(map.get("X-Trace").map(String::as_str), Some("abc"));
    }
}
