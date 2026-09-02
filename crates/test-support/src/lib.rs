use std::collections::BTreeMap;
use std::sync::Mutex;

use api_tester_domain::{DomainEvent, HttpFlow, Session, SitemapAnnotation};
use api_tester_ports::{
    AnnotationRepository, EventPublisher, FlowRepository, HttpClient, HttpRequest, HttpResponse,
    PortError, SessionRepository,
};
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

    async fn clear_all(&self) -> Result<(), PortError> {
        self.flows
            .lock()
            .map_err(|_| PortError::Permanent("flow repository mutex poisoned".to_owned()))?
            .clear();
        Ok(())
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

    async fn delete(&self, session_id: &str) -> Result<(), PortError> {
        self.sessions
            .lock()
            .map_err(|_| PortError::Permanent("session repository mutex poisoned".to_owned()))?
            .remove(session_id);
        Ok(())
    }

    async fn clear_all(&self) -> Result<(), PortError> {
        self.sessions
            .lock()
            .map_err(|_| PortError::Permanent("session repository mutex poisoned".to_owned()))?
            .clear();
        Ok(())
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

/// In-memory `HttpClient` returning queued responses in order. Useful for
/// testing auth and scanner logic without any real network access.
#[derive(Default)]
pub struct MockHttpClient {
    responses: Mutex<Vec<HttpResponse>>,
}

impl MockHttpClient {
    pub fn with_responses(responses: Vec<HttpResponse>) -> Self {
        Self {
            responses: Mutex::new(responses),
        }
    }

    pub fn push(&self, response: HttpResponse) {
        self.responses
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .push(response);
    }
}

#[async_trait]
impl HttpClient for MockHttpClient {
    async fn send(&self, _request: HttpRequest) -> Result<HttpResponse, PortError> {
        let mut responses = self
            .responses
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        if responses.is_empty() {
            return Ok(HttpResponse {
                status: 200,
                headers: Vec::new(),
                body: Vec::new(),
            });
        }
        Ok(responses.remove(0))
    }
}

/// In-memory `AnnotationRepository` for tests.
#[derive(Default)]
pub struct InMemoryAnnotationRepository {
    annotations: Mutex<BTreeMap<String, SitemapAnnotation>>,
}

#[async_trait]
impl AnnotationRepository for InMemoryAnnotationRepository {
    async fn upsert(&self, annotation: &SitemapAnnotation) -> Result<(), PortError> {
        self.annotations
            .lock()
            .map_err(|_| PortError::Permanent("annotation repository mutex poisoned".to_owned()))?
            .insert(annotation.key.clone(), annotation.clone());
        Ok(())
    }

    async fn delete(&self, key: &str) -> Result<(), PortError> {
        self.annotations
            .lock()
            .map_err(|_| PortError::Permanent("annotation repository mutex poisoned".to_owned()))?
            .remove(key);
        Ok(())
    }

    async fn list_all(&self) -> Result<Vec<SitemapAnnotation>, PortError> {
        Ok(self
            .annotations
            .lock()
            .map_err(|_| PortError::Permanent("annotation repository mutex poisoned".to_owned()))?
            .values()
            .cloned()
            .collect())
    }
}
