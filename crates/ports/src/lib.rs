use async_trait::async_trait;
use thiserror::Error;

pub use api_tester_domain::{
    DomainEvent, HttpFlow, ScanJob, SecurityPlan, SecurityRun, Session, SitemapAnnotation,
    WorkflowRun, WorkflowVersion,
};

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
    /// Deletes every stored flow. Used by the UI's "Clear log" action.
    async fn clear_all(&self) -> Result<(), PortError>;

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
    async fn delete(&self, session_id: &str) -> Result<(), PortError>;
    async fn clear_all(&self) -> Result<(), PortError>;
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

/// Persistence for AI-generated workflows and their runs.
#[async_trait]
pub trait WorkflowRepository: Send + Sync {
    async fn save_version(&self, version: &WorkflowVersion) -> Result<(), PortError>;
    async fn get_version(&self, id: &str) -> Result<Option<WorkflowVersion>, PortError>;
    async fn list_versions(&self) -> Result<Vec<WorkflowVersion>, PortError>;
    async fn save_run(&self, run: &WorkflowRun) -> Result<(), PortError>;
    async fn update_run(
        &self,
        run_id: &str,
        status: &str,
        finished_at: Option<chrono::DateTime<chrono::Utc>>,
        results_json: &str,
    ) -> Result<(), PortError>;
    async fn get_run(&self, run_id: &str) -> Result<Option<WorkflowRun>, PortError>;
    async fn list_runs(&self, version_id: &str) -> Result<Vec<WorkflowRun>, PortError>;
}

/// Persistence for AI-generated security test plans and runs.
#[async_trait]
pub trait SecurityRepository: Send + Sync {
    async fn save_plan(&self, plan: &SecurityPlan) -> Result<(), PortError>;
    async fn get_plan(&self, id: &str) -> Result<Option<SecurityPlan>, PortError>;
    async fn list_plans(&self) -> Result<Vec<SecurityPlan>, PortError>;
    async fn save_run(&self, run: &SecurityRun) -> Result<(), PortError>;
    async fn update_run(
        &self,
        run_id: &str,
        status: &str,
        finished_at: Option<chrono::DateTime<chrono::Utc>>,
        findings_json: &str,
    ) -> Result<(), PortError>;
    async fn get_run(&self, run_id: &str) -> Result<Option<SecurityRun>, PortError>;
    async fn list_runs(&self, plan_id: &str) -> Result<Vec<SecurityRun>, PortError>;
}

/// Persistence for sitemap annotations (comment + highlight color), keyed by
/// `{scheme}://{host}{path}` without query string.
#[async_trait]
pub trait AnnotationRepository: Send + Sync {
    async fn upsert(&self, annotation: &SitemapAnnotation) -> Result<(), PortError>;
    async fn delete(&self, key: &str) -> Result<(), PortError>;
    async fn list_all(&self) -> Result<Vec<SitemapAnnotation>, PortError>;
}
