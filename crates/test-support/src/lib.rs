use std::collections::BTreeMap;
use std::sync::Mutex;

use api_tester_domain::{DomainEvent, HttpFlow, Session};
use api_tester_ports::{EventPublisher, FlowRepository, PortError, SessionRepository};
use async_trait::async_trait;

#[derive(Default)]
pub struct InMemoryFlowRepository {
    flows: Mutex<BTreeMap<String, HttpFlow>>,
}

#[async_trait]
impl FlowRepository for InMemoryFlowRepository {
    async fn save(&self, flow: &HttpFlow) -> Result<(), PortError> {
        self.flows
            .lock()
            .map_err(|_| PortError::Permanent("flow repository mutex poisoned".to_owned()))?
            .insert(flow.id.clone(), flow.clone());
        Ok(())
    }

    async fn get_by_id(&self, flow_id: &str) -> Result<Option<HttpFlow>, PortError> {
        Ok(self
            .flows
            .lock()
            .map_err(|_| PortError::Permanent("flow repository mutex poisoned".to_owned()))?
            .get(flow_id)
            .cloned())
    }

    async fn list_by_session(&self, session_id: &str) -> Result<Vec<HttpFlow>, PortError> {
        Ok(self
            .flows
            .lock()
            .map_err(|_| PortError::Permanent("flow repository mutex poisoned".to_owned()))?
            .values()
            .filter(|flow| flow.session_id == session_id)
            .cloned()
            .collect())
    }
}

#[derive(Default)]
pub struct InMemorySessionRepository {
    sessions: Mutex<BTreeMap<String, Session>>,
}

#[async_trait]
impl SessionRepository for InMemorySessionRepository {
    async fn save(&self, session: &Session) -> Result<(), PortError> {
        self.sessions
            .lock()
            .map_err(|_| PortError::Permanent("session repository mutex poisoned".to_owned()))?
            .insert(session.id.clone(), session.clone());
        Ok(())
    }

    async fn get_by_id(&self, session_id: &str) -> Result<Option<Session>, PortError> {
        Ok(self
            .sessions
            .lock()
            .map_err(|_| PortError::Permanent("session repository mutex poisoned".to_owned()))?
            .get(session_id)
            .cloned())
    }
}

#[derive(Default)]
pub struct RecordingEventPublisher {
    events: Mutex<Vec<DomainEvent>>,
}

impl RecordingEventPublisher {
    pub fn events(&self) -> Vec<DomainEvent> {
        self.events
            .lock()
            .map(|events| events.clone())
            .unwrap_or_default()
    }
}

#[async_trait]
impl EventPublisher for RecordingEventPublisher {
    async fn publish(&self, event: DomainEvent) -> Result<(), PortError> {
        self.events
            .lock()
            .map_err(|_| PortError::Permanent("event publisher mutex poisoned".to_owned()))?
            .push(event);
        Ok(())
    }
}
