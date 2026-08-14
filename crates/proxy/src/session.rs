use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use api_tester_domain::Session;
use api_tester_ports::{PortError, SessionRepository};

/// How often the in-memory flow counter is flushed to the repository. A
/// small write per captured flow would add latency on the hot path, so the
/// counter is persisted periodically and once at stop.
const SESSION_PERSIST_EVERY: u64 = 256;

/// Tracks the single active capture session. Created when the proxy starts,
/// closed when it stops. `flow_count` is incremented as flows are captured
/// and persisted periodically plus once on stop.
pub struct ActiveSession {
    session: Session,
    repository: Arc<dyn SessionRepository>,
    flow_count: AtomicU64,
}

impl ActiveSession {
    pub async fn start(
        repository: Arc<dyn SessionRepository>,
        name: impl Into<String>,
        target_host: impl Into<String>,
    ) -> Result<Self, PortError> {
        let session = Session {
            name: name.into(),
            target_host: target_host.into(),
            ..Session::default()
        };
        repository.save(&session).await?;
        Ok(Self {
            session,
            repository,
            flow_count: AtomicU64::new(0),
        })
    }

    pub fn id(&self) -> &str {
        &self.session.id
    }

    pub fn target_host(&self) -> &str {
        &self.session.target_host
    }

    /// Records one captured flow and periodically persists the running
    /// count so a crash does not lose all progress.
    pub async fn record_flow(&self) -> Result<(), PortError> {
        let count = self.flow_count.fetch_add(1, Ordering::Relaxed) + 1;
        if count % SESSION_PERSIST_EVERY == 0 {
            self.persist().await?;
        }
        Ok(())
    }

    async fn persist(&self) -> Result<(), PortError> {
        let mut session = self.session.clone();
        session.flow_count = self.flow_count.load(Ordering::Relaxed);
        self.repository.save(&session).await
    }

    pub async fn stop(&self) -> Result<(), PortError> {
        let mut session = self.session.clone();
        session.flow_count = self.flow_count.load(Ordering::Relaxed);
        session.end_time = Some(chrono::Utc::now());
        self.repository.save(&session).await
    }
}
