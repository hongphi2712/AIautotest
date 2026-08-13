use api_tester_domain::DomainEvent;
use api_tester_ports::{EventPublisher, PortError};
use async_trait::async_trait;
use tokio::sync::broadcast;

pub struct EventBus {
    tx: broadcast::Sender<DomainEvent>,
}

impl EventBus {
    pub fn new(capacity: usize) -> Self {
        let (tx, _) = broadcast::channel(capacity.max(1));
        Self { tx }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<DomainEvent> {
        self.tx.subscribe()
    }

    pub fn receiver_count(&self) -> usize {
        self.tx.receiver_count()
    }
}

#[async_trait]
impl EventPublisher for EventBus {
    async fn publish(&self, event: DomainEvent) -> Result<(), PortError> {
        // broadcast send never blocks producers; lagging receivers miss events by design
        let _ = self.tx.send(event);
        Ok(())
    }
}
