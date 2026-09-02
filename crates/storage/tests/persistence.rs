use api_tester_domain::{
    HttpFlow, HttpMethod, Session, SitemapAnnotation, WorkflowRun, WorkflowVersion,
};
use api_tester_ports::{
    AnnotationRepository, FlowRepository, SessionRepository, WorkflowRepository,
};
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
    assert!(store.table_exists("workflow_versions").await.unwrap());
}

#[tokio::test]
async fn sitemap_annotations_round_trip_and_delete() {
    let directory = tempfile::tempdir().expect("temp dir");
    let database = directory.path().join("data.db");
    let key = "https://api.example.com/api/users";

    {
        let store = store_at(&database).await;
        assert!(store.annotations().list_all().await.unwrap().is_empty());

        let annotation = SitemapAnnotation {
            key: key.to_owned(),
            comment: Some("vulnerable".to_owned()),
            color: Some("red".to_owned()),
            updated_at: chrono::Utc::now(),
        };
        store.annotations().upsert(&annotation).await.unwrap();

        let updated = SitemapAnnotation {
            comment: Some("confirmed".to_owned()),
            color: Some("orange".to_owned()),
            ..annotation
        };
        store.annotations().upsert(&updated).await.unwrap();
    }

    let store = store_at(&database).await;
    let annotations = store.annotations().list_all().await.unwrap();
    assert_eq!(annotations.len(), 1);
    assert_eq!(annotations[0].key, key);
    assert_eq!(annotations[0].comment.as_deref(), Some("confirmed"));
    assert_eq!(annotations[0].color.as_deref(), Some("orange"));

    store.annotations().delete(key).await.unwrap();
    assert!(store.annotations().list_all().await.unwrap().is_empty());
}

#[tokio::test]
async fn workflow_versions_and_runs_round_trip() {
    let directory = tempfile::tempdir().expect("temp dir");
    let database = directory.path().join("data.db");

    let version = WorkflowVersion {
        name: "Login and fetch orders".to_owned(),
        base_url: "https://api.example.com".to_owned(),
        spec_json: r#"{"name":"Login","nodes":[]}"#.to_owned(),
        ..WorkflowVersion::default()
    };
    let version_id = version.id.clone();
    let run = WorkflowRun {
        version_id: version_id.clone(),
        ..WorkflowRun::default()
    };
    let run_id = run.run_id.clone();

    {
        let store = store_at(&database).await;
        store.workflows().save_version(&version).await.unwrap();
        store.workflows().save_run(&run).await.unwrap();
    }

    let store = store_at(&database).await;
    let loaded_version = store
        .workflows()
        .get_version(&version_id)
        .await
        .unwrap()
        .expect("version should exist");
    assert_eq!(loaded_version, version);
    assert_eq!(store.workflows().list_versions().await.unwrap().len(), 1);

    store
        .workflows()
        .update_run(
            &run_id,
            "completed",
            Some(chrono::Utc::now()),
            r#"{"a":{"ok":true}}"#,
        )
        .await
        .unwrap();
    let loaded_run = store
        .workflows()
        .get_run(&run_id)
        .await
        .unwrap()
        .expect("run should exist");
    assert_eq!(loaded_run.status, "completed");
    assert_eq!(loaded_run.results_json, r#"{"a":{"ok":true}}"#);
    assert_eq!(
        store
            .workflows()
            .list_runs(&version_id)
            .await
            .unwrap()
            .len(),
        1
    );
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

#[tokio::test]
async fn count_tracks_total_persisted_flows() {
    let directory = tempfile::tempdir().expect("temp dir");
    let store = store_at(&directory.path().join("data.db")).await;

    assert_eq!(store.flows().count().await.unwrap(), 0);
    for i in 0..5 {
        let flow = HttpFlow::new(HttpMethod::Get, "example.com", format!("/x/{i}"));
        store.flows().save(&flow).await.unwrap();
    }
    assert_eq!(store.flows().count().await.unwrap(), 5);

    // Reopening a fresh store over the same file sees the persisted count.
    let reopened = store_at(&directory.path().join("data.db")).await;
    assert_eq!(reopened.flows().count().await.unwrap(), 5);
}

#[tokio::test]
async fn clear_all_removes_every_persisted_flow() {
    let directory = tempfile::tempdir().expect("temp dir");
    let store = store_at(&directory.path().join("data.db")).await;

    let mut flow = HttpFlow::new(HttpMethod::Post, "example.com", "/login");
    flow.session_id = "session-a".to_owned();
    store.flows().save(&flow).await.unwrap();
    let other = HttpFlow::new(HttpMethod::Get, "example.com", "/profile");
    store.flows().save(&other).await.unwrap();
    assert_eq!(store.flows().count().await.unwrap(), 2);

    store.flows().clear_all().await.unwrap();

    assert_eq!(store.flows().count().await.unwrap(), 0);
    assert!(store.flows().get_by_id(&flow.id).await.unwrap().is_none());
}
