use std::sync::Arc;

use api_tester_domain::{DomainEvent, HttpFlow};
use api_tester_ports::{EventPublisher, FlowRepository, PortError};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ApplicationError {
    #[error(transparent)]
    Port(#[from] PortError),
}

pub struct CaptureApplication {
    flow_repository: Arc<dyn FlowRepository>,
    event_publisher: Arc<dyn EventPublisher>,
}

impl CaptureApplication {
    pub fn new(
        flow_repository: Arc<dyn FlowRepository>,
        event_publisher: Arc<dyn EventPublisher>,
    ) -> Self {
        Self {
            flow_repository,
            event_publisher,
        }
    }

    pub async fn capture_flow(&self, flow: HttpFlow) -> Result<(), ApplicationError> {
        self.flow_repository.save(&flow).await?;
        self.event_publisher
            .publish(DomainEvent::flow_captured(&flow))
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use api_tester_domain::{DomainEvent, HttpFlow, HttpMethod};
    use api_tester_ports::FlowRepository;
    use api_tester_test_support::{InMemoryFlowRepository, RecordingEventPublisher};

    use super::CaptureApplication;

    #[tokio::test]
    async fn capture_use_case_persists_and_publishes() {
        let repository = Arc::new(InMemoryFlowRepository::default());
        let events = Arc::new(RecordingEventPublisher::default());
        let application = CaptureApplication::new(repository.clone(), events.clone());
        let flow = HttpFlow::new(HttpMethod::Get, "example.com", "/health");

        application.capture_flow(flow.clone()).await.unwrap();

        assert_eq!(
            repository.get_by_id(&flow.id).await.unwrap(),
            Some(flow.clone())
        );
        assert_eq!(
            events.events(),
            vec![DomainEvent::FlowCaptured {
                flow_id: flow.id,
                session_id: flow.session_id,
            }]
        );
    }
}
