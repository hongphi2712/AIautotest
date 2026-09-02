use std::sync::Arc;

use api_tester_capture::RingBuffer;
use api_tester_domain::{DomainEvent, HttpFlow};
use api_tester_events::EventBus;
use api_tester_ports::{CaptureSink, EventPublisher, FlowRepository, PortError, SessionRepository};
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
            // Thorough: bump session flow_count for both orphan and supplied sessions
            // (supplied path previously left flow_count 0, so dropdown showed 0)
            if !flow.session_id.trim().is_empty() {
                let sid = flow.session_id.clone();
                let store_clone = self.store.clone();
                tokio::spawn(async move {
                    if let Some(s) = store_clone.lock().await.as_ref() {
                        if let Ok(Some(mut sess)) = s.sessions().get_by_id(&sid).await {
                            sess.flow_count = sess.flow_count.saturating_add(1);
                            let _ = s.sessions().save(&sess).await;
                        }
                    }
                });
            }
        }
        self.buffer.push(strip_flow(&flow));
        let _ = self.events.publish(DomainEvent::flow_captured(&flow)).await;
        // FlowSummary::from runs gitleaks CLI + regex analysis over the full
        // body. Keep this capture hot path responsive by doing that work on
        // the blocking pool instead of a tokio worker thread.
        let summary = match tokio::task::spawn_blocking(move || FlowSummary::from(&flow)).await {
            Ok(summary) => Some(summary),
            Err(error) => {
                eprintln!("[dashboard] flow summary task failed: {error}");
                None
            }
        };
        if let Some(summary) = summary {
            if let Ok(text) = serde_json::to_string(&json!({
                "type": "flow",
                "flow": summary,
            })) {
                let _ = self.ws_tx.send(text);
            }
        }
        Ok(())
    }
}
