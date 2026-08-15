use api_tester_ports::{HttpClient, HttpRequest, HttpResponse, PortError};
use async_trait::async_trait;

/// Real HTTP client used by the Repeater (and later the auth/scanner real
/// execution). Accepts self-signed certificates so local HTTPS targets work
/// out of the box.
pub struct ReqwestHttpClient {
    client: reqwest::Client,
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
            .map_err(|error| PortError::Transient(error.to_string()))?;
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
