use async_trait::async_trait;
use thiserror::Error;

pub use api_tester_domain::{DomainEvent, HttpFlow, ScanJob, Session};

#[derive(Debug, Error, Clone)]
pub enum PortError {
    #[error("resource not found: {0}")]
    NotFound(String),
    #[error("transient failure, safe to retry: {0}")]
    Transient(String),
    #[error("permanent failure: {0}")]
    Permanent(String),
}

#[async_trait]
pub trait FlowRepository: Send + Sync {
    async fn save(&self, flow: &HttpFlow) -> Result<(), PortError>;
    async fn get_by_id(&self, flow_id: &str) -> Result<Option<HttpFlow>, PortError>;
    async fn list_by_session(&self, session_id: &str) -> Result<Vec<HttpFlow>, PortError>;

    async fn save_batch(&self, flows: &[HttpFlow]) -> Result<(), PortError> {
        for flow in flows {
            self.save(flow).await?;
        }
        Ok(())
    }
}

#[async_trait]
pub trait SessionRepository: Send + Sync {
    async fn save(&self, session: &Session) -> Result<(), PortError>;
    async fn get_by_id(&self, session_id: &str) -> Result<Option<Session>, PortError>;
}

#[async_trait]
pub trait EventPublisher: Send + Sync {
    async fn publish(&self, event: DomainEvent) -> Result<(), PortError>;
}

/// Boundary between the proxy and the capture pipeline. Implemented by
/// adapters that push flows into the bounded buffer and event bus.
#[async_trait]
pub trait CaptureSink: Send + Sync {
    async fn push(&self, flow: HttpFlow) -> Result<(), PortError>;
}

#[async_trait]
pub trait ScanExecutor: Send + Sync {
    async fn submit(&self, job: ScanJob) -> Result<String, PortError>;
    async fn cancel(&self, job_id: &str) -> Result<(), PortError>;
}

/// An outbound HTTP request used by the auth flow and (later) the scanner.
#[derive(Debug, Clone)]
pub struct HttpRequest {
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<Vec<u8>>,
}

/// An HTTP response returned by the `HttpClient` port.
#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// Boundary for outbound HTTP execution. Implemented by adapters (reqwest,
/// hyper) so feature crates like auth and scanner never depend on a concrete
/// HTTP client and stay testable with in-memory mocks.
#[async_trait]
pub trait HttpClient: Send + Sync {
    async fn send(&self, request: HttpRequest) -> Result<HttpResponse, PortError>;
}
