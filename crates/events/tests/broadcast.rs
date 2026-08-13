use api_tester_domain::DomainEvent;
use api_tester_events::EventBus;
use api_tester_ports::EventPublisher;

#[tokio::test]
async fn all_subscribers_receive_each_event() {
    let bus = EventBus::new(16);
    let mut first = bus.subscribe();
    let mut second = bus.subscribe();
    let event = DomainEvent::FlowCaptured {
        flow_id: "flow-1".to_owned(),
        session_id: "session-1".to_owned(),
    };

    bus.publish(event.clone()).await.unwrap();

    assert_eq!(first.recv().await.unwrap(), event.clone());
    assert_eq!(second.recv().await.unwrap(), event);
}

#[tokio::test]
async fn slow_subscriber_never_blocks_producer() {
    let bus = EventBus::new(2);
    let mut slow = bus.subscribe();

    for index in 0..10 {
        bus.publish(DomainEvent::FlowCaptured {
            flow_id: index.to_string(),
            session_id: String::new(),
        })
        .await
        .unwrap();
    }

    match slow.recv().await {
        Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
        other => panic!("expected lagged receiver, got {other:?}"),
    }
}

#[tokio::test]
async fn publish_without_subscribers_is_safe() {
    let bus = EventBus::new(4);
    let event = DomainEvent::FlowCaptured {
        flow_id: "flow-x".to_owned(),
        session_id: String::new(),
    };

    bus.publish(event).await.unwrap();
    assert_eq!(bus.receiver_count(), 0);
}
