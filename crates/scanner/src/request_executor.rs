use std::sync::Arc;
use std::time::Duration;

use api_tester_ports::{HttpClient, HttpRequest, HttpResponse};

use crate::error::ScanError;

/// Sends requests through the `HttpClient` port with a timeout and bounded
/// retries for transient failures.
pub struct RequestExecutor {
    client: Arc<dyn HttpClient>,
    retry_limit: u32,
    timeout: Duration,
}

impl RequestExecutor {
    pub fn new(client: Arc<dyn HttpClient>, retry_limit: u32, timeout_secs: u64) -> Self {
        Self {
            client,
            retry_limit,
            timeout: Duration::from_secs(timeout_secs.max(1)),
        }
    }

    pub async fn execute(&self, request: HttpRequest) -> Result<HttpResponse, ScanError> {
        let mut attempt = 0u32;
        loop {
            match tokio::time::timeout(self.timeout, self.client.send(request.clone())).await {
                Ok(Ok(response)) => return Ok(response),
                Ok(Err(error)) => {
                    attempt += 1;
                    if attempt > self.retry_limit {
                        return Err(ScanError::Transport(error));
                    }
                }
                Err(_) => {
                    attempt += 1;
                    if attempt > self.retry_limit {
                        return Err(ScanError::Timeout);
                    }
                }
            }
            tokio::time::sleep(Duration::from_millis(50 * u64::from(attempt))).await;
        }
    }
}
