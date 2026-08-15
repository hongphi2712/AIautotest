use std::sync::Arc;

use api_tester_capture::RingBuffer;
use api_tester_domain::{DomainEvent, HttpFlow};
use api_tester_events::EventBus;
use api_tester_ports::{CaptureSink, EventPublisher, FlowRepository, PortError};
use api_tester_storage::SqliteStore;
use async_trait::async_trait;

/// Capture sink that feeds the dashboard ring buffer, persists to SQLite and
/// publishes capture events. The proxy captures through this sink.
///
/// Memory strategy: the FULL flow (bodies + headers) is persisted to SQLite
/// first; only a stripped metadata copy is kept in the in-memory ring buffer so
/// long captures never hold bodies in RAM. Detail views load the full flow from
/// SQLite on demand.
pub struct DashboardSink {
    buffer: Arc<RingBuffer<HttpFlow>>,
    store: Arc<tokio::sync::Mutex<Option<SqliteStore>>>,
    events: Arc<EventBus>,
}

impl DashboardSink {
    pub fn new(
        buffer: Arc<RingBuffer<HttpFlow>>,
        store: Arc<tokio::sync::Mutex<Option<SqliteStore>>>,
        events: Arc<EventBus>,
    ) -> Self {
        Self {
            buffer,
            store,
            events,
        }
    }
}

/// Strips bodies and headers from a flow, keeping only the summary metadata
/// needed by the dashboard table (and `response_body_len` for the Length column).
fn strip_flow(flow: &HttpFlow) -> HttpFlow {
    let mut summary = flow.clone();
    summary.request_headers.clear();
    summary.request_body = None;
    summary.response_headers.clear();
    summary.response_body = None;
    summary
}

#[async_trait]
impl CaptureSink for DashboardSink {
    async fn push(&self, flow: HttpFlow) -> Result<(), PortError> {
        // Persist first so `flow_detail` can always load the full body.
        if let Some(store) = self.store.lock().await.as_ref() {
            let _ = store.flows().save(&flow).await;
        }
        self.buffer.push(strip_flow(&flow));
        let _ = self.events.publish(DomainEvent::flow_captured(&flow)).await;
        Ok(())
    }
}
