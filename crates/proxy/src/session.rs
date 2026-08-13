use std::sync::Arc;

use api_tester_domain::Session;
use api_tester_ports::{PortError, SessionRepository};

/// Tracks the single active capture session. Created when the proxy starts,
/// closed when it stops. `flow_count` is computed on demand from the flows
/// table instead of being persisted on every captured flow.
pub struct ActiveSession {
    session: Session,
    repository: Arc<dyn SessionRepository>,
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
        })
    }

    pub fn id(&self) -> &str {
        &self.session.id
    }

    pub fn target_host(&self) -> &str {
        &self.session.target_host
    }

    pub async fn stop(&self) -> Result<(), PortError> {
        let mut session = self.session.clone();
        session.end_time = Some(chrono::Utc::now());
        self.repository.save(&session).await
    }
}
