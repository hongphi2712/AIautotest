use std::sync::Arc;

use api_tester_capture::RingBuffer;
use api_tester_domain::{DomainEvent, HttpFlow};
use api_tester_events::EventBus;
use api_tester_ports::{CaptureSink, EventPublisher, FlowRepository, PortError};
use api_tester_storage::SqliteStore;
use async_trait::async_trait;
use serde_json::json;

use crate::serialization::FlowSummary;

/// Capture sink that feeds the dashboard ring buffer, persists to SQLite,
/// publishes capture events and pushes the new flow over the WebSocket so the
/// browser UI updates in real time. The proxy captures through this sink.
///
/// Memory strategy: the FULL flow (bodies + headers) is persisted to SQLite
/// first; only a stripped metadata copy is kept in the in-memory ring buffer so
/// long captures never hold bodies in RAM. Detail views load the full flow from
/// SQLite on demand.
pub struct DashboardSink {
    buffer: Arc<RingBuffer<HttpFlow>>,
    store: Arc<tokio::sync::Mutex<Option<SqliteStore>>>,
    events: Arc<EventBus>,
    ws_tx: Arc<tokio::sync::broadcast::Sender<String>>,
}

impl DashboardSink {
    pub fn new(
        buffer: Arc<RingBuffer<HttpFlow>>,
        store: Arc<tokio::sync::Mutex<Option<SqliteStore>>>,
        events: Arc<EventBus>,
        ws_tx: Arc<tokio::sync::broadcast::Sender<String>>,
    ) -> Self {
        Self {
            buffer,
            store,
            events,
            ws_tx,
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
        if let Ok(text) = serde_json::to_string(&json!({
            "type": "flow",
            "flow": FlowSummary::from(&flow),
        })) {
            let _ = self.ws_tx.send(text);
        }
        Ok(())
    }
}
