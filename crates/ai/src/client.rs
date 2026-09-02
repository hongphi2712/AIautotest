//! DeepSeek chat-completions client over the `HttpClient` port.
//!
//! Non-streaming single call with a `max_tokens` output cap and a bounded
//! timeout, so a runaway or misconfigured call cannot burn unbounded tokens.
//! The API key is held server-side and never returned to the UI.

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use api_tester_ports::{HttpClient, HttpRequest};
use serde_json::json;

/// Errors surfaced to the caller (and ultimately the UI as messages).
#[derive(Debug)]
pub enum AiClientError {
    /// No API key configured.
    NotConfigured,
    /// Transport/timing failure talking to the provider.
    Request(String),
    /// The provider returned a non-success status or an unparseable payload.
    Response(String),
}

impl fmt::Display for AiClientError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotConfigured => write!(formatter, "AI not configured (missing API key)"),
            Self::Request(message) => write!(formatter, "AI request failed: {message}"),
            Self::Response(message) => write!(formatter, "AI provider error: {message}"),
        }
    }
}

impl std::error::Error for AiClientError {}

/// A minimal OpenAI-compatible chat-completions client (DeepSeek).
pub struct DeepSeekClient {
    http: Arc<dyn HttpClient>,
    base_url: String,
    model: String,
    api_key: String,
    max_tokens: u32,
    timeout: Duration,
}

impl DeepSeekClient {
    pub fn new(
        http: Arc<dyn HttpClient>,
        base_url: impl Into<String>,
        model: impl Into<String>,
        api_key: impl Into<String>,
        max_tokens: u32,
        timeout: Duration,
    ) -> Self {
        Self {
            http,
            base_url: base_url.into(),
            model: model.into(),
            api_key: api_key.into(),
            max_tokens: max_tokens.max(1),
            timeout,
        }
    }

    /// Sends a system/user message pair and returns the assistant's text.
    pub async fn chat(&self, system: &str, user: &str) -> Result<String, AiClientError> {
        self.completions(system, user, false).await
    }

    /// Sends a system/user message pair and requests a strict JSON object
    /// response (`response_format: json_object`), used by the workflow
    /// generator so the model returns a machine-parseable payload.
    pub async fn chat_json(&self, system: &str, user: &str) -> Result<String, AiClientError> {
        self.completions(system, user, true).await
    }

    async fn completions(
        &self,
        system: &str,
        user: &str,
        json_mode: bool,
    ) -> Result<String, AiClientError> {
        if self.api_key.is_empty() {
            return Err(AiClientError::NotConfigured);
        }
        let url = format!("{}/chat/completions", self.base_url.trim_end_matches('/'));
        let mut payload = json!({
            "model": self.model,
            "messages": [
                { "role": "system", "content": system },
                { "role": "user", "content": user },
            ],
            "stream": false,
        });
        if self.max_tokens > 0 {
            payload["max_tokens"] = json!(self.max_tokens);
        }
        if json_mode && !self.model.contains("ox-alpha") && !self.model.contains("ling") {
            payload["response_format"] = json!({ "type": "json_object" });
        }


        let body = serde_json::to_vec(&payload).map_err(|error| {
            AiClientError::Request(format!("could not encode request: {error}"))
        })?;

        let request = HttpRequest {
            method: "POST".to_owned(),
            url,
            headers: vec![
                (
                    "Authorization".to_owned(),
                    format!("Bearer {}", self.api_key),
                ),
                ("Content-Type".to_owned(), "application/json".to_owned()),
            ],
            body: Some(body),
        };

        let response = tokio::time::timeout(self.timeout, self.http.send(request))
            .await
            .map_err(|_| AiClientError::Request("request timed out".to_owned()))?
            .map_err(|error| AiClientError::Request(error.to_string()))?;

        if response.status != 200 {
            let text = String::from_utf8_lossy(&response.body).into_owned();
            return Err(AiClientError::Response(format!(
                "HTTP {}: {}",
                response.status,
                text.chars().take(500).collect::<String>()
            )));
        }

        let parsed: serde_json::Value = serde_json::from_slice(&response.body)
            .map_err(|error| AiClientError::Response(format!("invalid JSON from AI provider: {error}")))?;

        let choices = parsed["choices"].as_array();
        if choices.map_or(true, |c| c.is_empty()) {
            let err_msg = parsed["error"]["message"]
                .as_str()
                .unwrap_or("empty choices array returned");
            return Err(AiClientError::Response(format!("AI provider error: {err_msg}")));
        }

        let message = &parsed["choices"][0]["message"];
        let content = message["content"].as_str().unwrap_or("").trim();
        let reasoning = message["reasoning_content"].as_str().unwrap_or("").trim();

        if !content.is_empty() {
            Ok(content.to_owned())
        } else if !reasoning.is_empty() {
            Ok(reasoning.to_owned())
        } else {
            let finish_reason = parsed["choices"][0]["finish_reason"].as_str().unwrap_or("unknown");
            Err(AiClientError::Response(format!(
                "AI model returned empty response text (finish_reason: '{finish_reason}'). Try increasing max_tokens or checking model status."
            )))
        }
    }
}


#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use api_tester_ports::HttpResponse;
    use api_tester_test_support::MockHttpClient;

    use super::{AiClientError, DeepSeekClient};

    fn client_with(responses: Vec<HttpResponse>) -> DeepSeekClient {
        DeepSeekClient::new(
            Arc::new(MockHttpClient::with_responses(responses)),
            "https://api.deepseek.com",
            "deepseek-v4-flash",
            "sk-test",
            1000,
            std::time::Duration::from_secs(5),
        )
    }

    fn ok_response(body: &str) -> HttpResponse {
        HttpResponse {
            status: 200,
            headers: vec![("content-type".to_owned(), "application/json".to_owned())],
            body: body.as_bytes().to_vec(),
        }
    }

    #[tokio::test]
    async fn parses_assistant_content() {
        let client = client_with(vec![ok_response(
            r#"{"choices":[{"message":{"role":"assistant","content":"Flow summary here"}}]}"#,
        )]);
        let output = client
            .chat("system", "user")
            .await
            .expect("chat should succeed");
        assert_eq!(output, "Flow summary here");
    }

    #[tokio::test]
    async fn non_200_returns_response_error() {
        let client = client_with(vec![HttpResponse {
            status: 401,
            headers: Vec::new(),
            body: br#"{"error":{"message":"invalid api key"}}"#.to_vec(),
        }]);
        let error = client.chat("system", "user").await.unwrap_err();
        assert!(matches!(error, AiClientError::Response(_)));
        assert!(error.to_string().contains("401"));
    }

    #[tokio::test]
    async fn missing_content_is_an_error() {
        let client = client_with(vec![ok_response(r#"{"choices":[]}"#)]);
        assert!(client.chat("system", "user").await.is_err());
    }

    #[tokio::test]
    async fn empty_key_is_not_configured() {
        let client = DeepSeekClient::new(
            Arc::new(MockHttpClient::with_responses(vec![])),
            "https://api.deepseek.com",
            "deepseek-v4-flash",
            "",
            1000,
            std::time::Duration::from_secs(5),
        );
        let error = client.chat("system", "user").await.unwrap_err();
        assert!(matches!(error, AiClientError::NotConfigured));
    }

    #[tokio::test]
    async fn unparseable_body_is_reported() {
        let client = client_with(vec![ok_response("not-json")]);
        let error = client.chat("system", "user").await.unwrap_err();
        assert!(matches!(error, AiClientError::Response(_)));
    }
}
