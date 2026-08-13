use api_tester_domain::{HttpFlow, HttpMethod, Session};
use api_tester_ports::{FlowRepository, SessionRepository};
use api_tester_storage::SqliteStore;

async fn store_at(path: &std::path::Path) -> SqliteStore {
    let url = format!("sqlite://{}", path.display());
    SqliteStore::open(&url).await.expect("store should open")
}

#[tokio::test]
async fn flows_survive_process_restart() {
    let directory = tempfile::tempdir().expect("temp dir");
    let database = directory.path().join("data.db");

    let flow = HttpFlow::new(HttpMethod::Post, "example.com", "/login");
    let flow_id = flow.id.clone();

    {
        let store = store_at(&database).await;
        store.flows().save(&flow).await.unwrap();
    }

    let store = store_at(&database).await;
    let loaded = store
        .flows()
        .get_by_id(&flow_id)
        .await
        .unwrap()
        .expect("flow should exist after restart");
    assert_eq!(loaded, flow);
}

#[tokio::test]
async fn large_bodies_round_trip_byte_for_byte() {
    let directory = tempfile::tempdir().expect("temp dir");
    let database = directory.path().join("data.db");
    let body = "x".repeat(2 * 1024 * 1024);

    let mut flow = HttpFlow::new(HttpMethod::Post, "example.com", "/big");
    flow.request_body = Some(body.clone());
    flow.response_body = Some(body.clone());
    let flow_id = flow.id.clone();

    {
        let store = store_at(&database).await;
        store.flows().save(&flow).await.unwrap();
    }

    let store = store_at(&database).await;
    let loaded = store
        .flows()
        .get_by_id(&flow_id)
        .await
        .unwrap()
        .expect("flow should exist");
    assert_eq!(loaded.request_body.as_deref(), Some(body.as_str()));
    assert_eq!(loaded.response_body.as_deref(), Some(body.as_str()));
}

#[tokio::test]
async fn sessions_round_trip_across_restart() {
    let directory = tempfile::tempdir().expect("temp dir");
    let database = directory.path().join("data.db");

    let session = Session {
        name: "capture-1".to_owned(),
        target_host: "example.com".to_owned(),
        flow_count: 7,
        ..Session::default()
    };
    let session_id = session.id.clone();

    {
        let store = store_at(&database).await;
        store.sessions().save(&session).await.unwrap();
    }

    let store = store_at(&database).await;
    let loaded = store
        .sessions()
        .get_by_id(&session_id)
        .await
        .unwrap()
        .expect("session should exist");
    assert_eq!(loaded, session);
}

#[tokio::test]
async fn workflow_placeholder_tables_exist() {
    let directory = tempfile::tempdir().expect("temp dir");
    let store = store_at(&directory.path().join("data.db")).await;

    assert!(store.table_exists("workflow_nodes").await.unwrap());
    assert!(store.table_exists("workflow_edges").await.unwrap());
    assert!(store.table_exists("workflow_runs").await.unwrap());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_writers_produce_consistent_snapshots() {
    let directory = tempfile::tempdir().expect("temp dir");
    let store = store_at(&directory.path().join("data.db")).await;

    let mut handles = Vec::new();
    for seed in 0..200 {
        let store = store.clone();
        handles.push(tokio::spawn(async move {
            let flow = HttpFlow::new(HttpMethod::Get, "example.com", format!("/api/{seed}"));
            store.flows().save(&flow).await.unwrap();
            flow.id
        }));
    }

    let mut ids = Vec::new();
    for handle in handles {
        ids.push(handle.await.unwrap());
    }

    for flow_id in ids {
        assert!(store.flows().get_by_id(&flow_id).await.unwrap().is_some());
    }
}

#[tokio::test]
async fn list_by_session_returns_matching_flows() {
    let directory = tempfile::tempdir().expect("temp dir");
    let store = store_at(&directory.path().join("data.db")).await;

    let mut flow = HttpFlow::new(HttpMethod::Get, "example.com", "/api/orders");
    flow.session_id = "session-a".to_owned();
    store.flows().save(&flow).await.unwrap();

    let mut other = HttpFlow::new(HttpMethod::Get, "example.com", "/api/profile");
    other.session_id = "session-b".to_owned();
    store.flows().save(&other).await.unwrap();

    let flows = store.flows().list_by_session("session-a").await.unwrap();
    assert_eq!(flows.len(), 1);
    assert_eq!(flows[0].path, "/api/orders");
}
