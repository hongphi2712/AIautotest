use api_tester_ports::{HttpClient, HttpRequest, HttpResponse, PortError};
use async_trait::async_trait;
use std::error::Error as _;

/// Real HTTP client used by the Repeater (and later the auth/scanner real
/// execution). Accepts self-signed certificates so local HTTPS targets work
/// out of the box.
pub struct ReqwestHttpClient {
    client: reqwest::Client,
}

/// Surfaces the underlying cause of a reqwest failure instead of the generic
/// `error sending request for url (...)` wrapper: walks the source chain and
/// reports timeouts distinctly.
fn reqwest_error_message(error: &reqwest::Error) -> String {
    if error.is_timeout() {
        return "request timed out".to_owned();
    }
    let mut message = error.to_string();
    let mut source = error.source();
    let mut depth = 0;
    while let Some(cause) = source {
        if depth >= 2 {
            break;
        }
        let cause_text = cause.to_string();
        if cause_text != message {
            message.push_str(": ");
            message.push_str(&cause_text);
        }
        source = cause.source();
        depth += 1;
    }
    message
}

impl ReqwestHttpClient {
    pub fn new() -> Result<Self, String> {
        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .build()
            .map_err(|error| error.to_string())?;
        Ok(Self { client })
    }
}

#[async_trait]
impl HttpClient for ReqwestHttpClient {
    async fn send(&self, request: HttpRequest) -> Result<HttpResponse, PortError> {
        let method = reqwest::Method::from_bytes(request.method.as_bytes())
            .map_err(|error| PortError::Permanent(error.to_string()))?;
        let mut builder = self.client.request(method, &request.url);
        for (name, value) in &request.headers {
            builder = builder.header(name, value);
        }
        let response = builder
            .body(request.body.unwrap_or_default())
            .send()
            .await
            .map_err(|error| PortError::Transient(reqwest_error_message(&error)))?;
        let status = response.status().as_u16();
        let headers = response
            .headers()
            .iter()
            .map(|(name, value)| {
                (
                    name.as_str().to_owned(),
                    String::from_utf8_lossy(value.as_bytes()).into_owned(),
                )
            })
            .collect::<Vec<_>>();
        let body = response
            .bytes()
            .await
            .map_err(|error| PortError::Transient(error.to_string()))?
            .to_vec();
        Ok(HttpResponse {
            status,
            headers,
            body,
        })
    }
}
