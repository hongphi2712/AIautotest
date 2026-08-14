use std::sync::Arc;

use api_tester_capture::RingBuffer;
use api_tester_domain::{DomainEvent, HttpFlow};
use api_tester_events::EventBus;
use api_tester_ports::{CaptureSink, EventPublisher, FlowRepository, PortError};
use api_tester_storage::SqliteStore;
use async_trait::async_trait;

/// Capture sink that feeds the dashboard ring buffer, persists to SQLite and
/// publishes capture events. The proxy captures through this sink.
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

#[async_trait]
impl CaptureSink for DashboardSink {
    async fn push(&self, flow: HttpFlow) -> Result<(), PortError> {
        self.buffer.push(flow.clone());
        if let Some(store) = self.store.lock().await.as_ref() {
            let _ = store.flows().save(&flow).await;
        }
        let _ = self.events.publish(DomainEvent::flow_captured(&flow)).await;
        Ok(())
    }
}
