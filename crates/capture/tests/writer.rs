use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use api_tester_capture::{FlowBuffer, OverflowPolicy, PersistenceWriter};
use api_tester_domain::{DomainEvent, HttpFlow, HttpMethod};
use api_tester_events::EventBus;
use api_tester_ports::{FlowRepository, PortError};
use api_tester_storage::SqliteStore;
use api_tester_test_support::{InMemoryFlowRepository, RecordingEventPublisher};
use async_trait::async_trait;

struct FlakyRepository {
    inner: InMemoryFlowRepository,
    transient_failures_left: AtomicUsize,
}

impl FlakyRepository {
    fn new(transient_failures_left: usize) -> Self {
        Self {
            inner: InMemoryFlowRepository::default(),
            transient_failures_left: AtomicUsize::new(transient_failures_left),
        }
    }
}

#[async_trait]
impl FlowRepository for FlakyRepository {
    async fn save(&self, flow: &HttpFlow) -> Result<(), PortError> {
        self.inner.save(flow).await
    }

    async fn save_batch(&self, flows: &[HttpFlow]) -> Result<(), PortError> {
        let remaining = loop {
            let current = self.transient_failures_left.load(Ordering::SeqCst);
            if current == 0 {
                break 0usize;
            }
            match self.transient_failures_left.compare_exchange_weak(
                current,
                current - 1,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => break current,
                Err(_) => continue,
            }
        };
        if remaining > 0 {
            return Err(PortError::Transient("simulated lock".to_owned()));
        }
        self.inner.save_batch(flows).await
    }

    async fn get_by_id(&self, flow_id: &str) -> Result<Option<HttpFlow>, PortError> {
        self.inner.get_by_id(flow_id).await
    }

    async fn list_by_session(&self, session_id: &str) -> Result<Vec<HttpFlow>, PortError> {
        self.inner.list_by_session(session_id).await
    }
}

fn writer_with_events(
    buffer: Arc<FlowBuffer>,
    repository: Arc<dyn FlowRepository>,
) -> (PersistenceWriter, Arc<RecordingEventPublisher>) {
    let events = Arc::new(RecordingEventPublisher::default());
    let writer = PersistenceWriter::new(buffer, repository, events.clone());
    (writer, events)
}

#[tokio::test]
async fn persistence_writer_drains_and_saves_all_flows() {
    let buffer = Arc::new(FlowBuffer::new(32, false, OverflowPolicy::FailFast));
    let repository = Arc::new(InMemoryFlowRepository::default());

    let mut expected_ids = Vec::new();
    for seed in 0..25 {
        let flow = HttpFlow::new(HttpMethod::Get, "example.com", format!("/api/{seed}"));
        expected_ids.push(flow.id.clone());
        buffer.push(flow).await;
    }

    buffer.close();

    let (writer, _) = writer_with_events(buffer.clone(), repository.clone());
    writer.run().await.expect("writer should drain");

    for flow_id in expected_ids {
        assert!(
            repository.get_by_id(&flow_id).await.unwrap().is_some(),
            "flow {flow_id} should be persisted"
        );
    }
}

#[tokio::test]
async fn persistence_writer_applies_dedup() {
    let buffer = Arc::new(FlowBuffer::new(16, true, OverflowPolicy::FailFast));
    let repository = Arc::new(InMemoryFlowRepository::default());

    let first = HttpFlow::new(HttpMethod::Post, "example.com", "/login");
    let duplicate = first.clone();
    let duplicate_id = duplicate.id.clone();
    buffer.push(first).await;
    buffer.push(duplicate).await;
    buffer.close();

    let (writer, _) = writer_with_events(buffer, repository.clone());
    writer.run().await.unwrap();

    let flows = repository.get_by_id(&duplicate_id).await.unwrap();
    assert!(flows.is_some(), "the accepted flow should be persisted");
}

#[tokio::test]
async fn persistence_writer_publishes_capture_events() {
    let buffer = Arc::new(FlowBuffer::new(16, false, OverflowPolicy::FailFast));
    let repository = Arc::new(InMemoryFlowRepository::default());
    let flow = HttpFlow::new(HttpMethod::Get, "example.com", "/api/events");
    buffer.push(flow.clone()).await;
    buffer.close();

    let (writer, events) = writer_with_events(buffer, repository.clone());
    writer.run().await.unwrap();

    assert_eq!(
        events.events(),
        vec![DomainEvent::FlowCaptured {
            flow_id: flow.id,
            session_id: flow.session_id,
        }]
    );
}

#[tokio::test]
async fn persistence_writer_retries_transient_failures() {
    let buffer = Arc::new(FlowBuffer::new(16, false, OverflowPolicy::FailFast));
    let repository = Arc::new(FlakyRepository::new(2));
    let flow = HttpFlow::new(HttpMethod::Get, "example.com", "/api/retry");
    let flow_id = flow.id.clone();
    buffer.push(flow).await;
    buffer.close();

    let writer = PersistenceWriter::new(
        buffer,
        repository.clone(),
        Arc::new(RecordingEventPublisher::default()),
    );
    writer
        .run()
        .await
        .expect("should succeed after transient retries");

    assert!(repository.get_by_id(&flow_id).await.unwrap().is_some());
}

#[tokio::test]
async fn persistence_writer_aborts_on_permanent_failure() {
    let buffer = Arc::new(FlowBuffer::new(16, false, OverflowPolicy::FailFast));
    let repository = Arc::new(FlakyRepository::new(usize::MAX));
    let flow = HttpFlow::new(HttpMethod::Get, "example.com", "/api/fatal");
    buffer.push(flow).await;
    buffer.close();

    let writer = PersistenceWriter::new(
        buffer,
        repository,
        Arc::new(RecordingEventPublisher::default()),
    )
    .with_max_retries(2);

    assert!(writer.run().await.is_err());
}

#[tokio::test]
async fn end_to_end_buffer_to_sqlite_to_event_bus() {
    let directory = tempfile::tempdir().expect("temp dir");
    let database = directory.path().join("data.db");
    let store = SqliteStore::open(&format!("sqlite://{}", database.display()))
        .await
        .expect("store should open");
    let event_bus = EventBus::new(16);
    let mut receiver = event_bus.subscribe();

    let buffer = Arc::new(FlowBuffer::new(16, false, OverflowPolicy::FailFast));
    let flow = HttpFlow::new(HttpMethod::Get, "example.com", "/api/e2e");
    let flow_id = flow.id.clone();
    buffer.push(flow).await;
    buffer.close();

    let writer =
        PersistenceWriter::new(buffer, Arc::new(store.flows().clone()), Arc::new(event_bus));
    writer.run().await.expect("writer should drain");

    let persisted = store.flows().get_by_id(&flow_id).await.unwrap();
    assert!(persisted.is_some(), "flow should be in sqlite");

    match receiver.recv().await {
        Ok(DomainEvent::FlowCaptured {
            flow_id: received_id,
            ..
        }) => assert_eq!(received_id, flow_id),
        other => panic!("expected a captured event, got {other:?}"),
    }
}
