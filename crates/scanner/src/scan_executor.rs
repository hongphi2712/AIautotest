use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use api_tester_domain::{DomainEvent, ScanJob};
use api_tester_ports::{EventPublisher, FlowRepository, PortError, ScanExecutor};
use async_trait::async_trait;
use tokio_util::sync::CancellationToken;

use crate::scheduler::ScanScheduler;

/// Adapter that implements the `ScanExecutor` port by resolving the flows of
/// a session, spawning the scheduler and keeping per-job cancellation
/// tokens.
pub struct TokioScanExecutor {
    flow_repository: Arc<dyn FlowRepository>,
    scheduler: Arc<ScanScheduler>,
    events: Option<Arc<dyn EventPublisher>>,
    running: Arc<Mutex<BTreeMap<String, CancellationToken>>>,
}

impl TokioScanExecutor {
    pub fn new(
        flow_repository: Arc<dyn FlowRepository>,
        scheduler: Arc<ScanScheduler>,
        events: Option<Arc<dyn EventPublisher>>,
    ) -> Self {
        Self {
            flow_repository,
            scheduler,
            events,
            running: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }
}

#[async_trait]
impl ScanExecutor for TokioScanExecutor {
    async fn submit(&self, job: ScanJob) -> Result<String, PortError> {
        let flows = match job.session_id.as_deref() {
            Some(session_id) => self.flow_repository.list_by_session(session_id).await?,
            None => Vec::new(),
        };

        let job_id = job.id.clone();
        let closure_job_id = job_id.clone();
        let cancel = CancellationToken::new();
        self.running
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .insert(job_id.clone(), cancel.clone());

        let scheduler = self.scheduler.clone();
        let events = self.events.clone();
        let running = self.running.clone();
        let session_id = job.session_id.clone();
        tokio::spawn(async move {
            let result = scheduler.run(&flows, &job, cancel.clone()).await;
            if let Some(events) = events {
                let findings = result.as_ref().map(|run| run.findings.len()).unwrap_or(0);
                let _ = events
                    .publish(DomainEvent::scan_completed(
                        &closure_job_id,
                        session_id.as_deref(),
                        findings,
                    ))
                    .await;
            }
            running
                .lock()
                .unwrap_or_else(|poison| poison.into_inner())
                .remove(&closure_job_id);
        });

        Ok(job_id)
    }

    async fn cancel(&self, job_id: &str) -> Result<(), PortError> {
        if let Some(token) = self
            .running
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .get(job_id)
        {
            token.cancel();
        }
        Ok(())
    }
}
