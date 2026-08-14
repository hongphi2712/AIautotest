mod common;

use std::sync::Arc;

use api_tester_domain::{HttpMethod, ProxyConfig, ScopeConfig};
use api_tester_proxy::{InterceptController, InterceptEdit, InterceptHeader};
use common::{
    MockHttpUpstream, VecCaptureSink, send_plain, send_plain_with_body, start_proxy_with_intercept,
    wait_for_flows,
};

async fn poll_entry(
    controller: &InterceptController,
    kind: &str,
) -> api_tester_proxy::InterceptEntry {
    for _ in 0..100 {
        if let Some(entry) = controller
            .list()
            .into_iter()
            .find(|entry| entry.kind == kind)
        {
            return entry;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    panic!("no {kind} entry was intercepted");
}

#[tokio::test]
async fn request_intercept_forward_unchanged() {
    let upstream = MockHttpUpstream::start().await;
    let sink = Arc::new(VecCaptureSink::default());
    let intercept = Arc::new(InterceptController::default());
    intercept.set_enabled(true);
    intercept.set_intercept_requests(true);
    intercept.set_intercept_responses(false);
    let proxy = start_proxy_with_intercept(
        ProxyConfig {
            port: 0,
            ..ProxyConfig::default()
        },
        ScopeConfig::default(),
        sink.clone(),
        intercept.clone(),
    )
    .await;
    let proxy_addr = proxy.local_addr().await.unwrap();
    let target = format!("127.0.0.1:{}", upstream.port);

    let client =
        tokio::spawn(async move { send_plain(proxy_addr, &target, "GET", "/api/hold").await });
    let entry = poll_entry(&intercept, "request").await;
    assert_eq!(entry.method, "GET");
    assert!(entry.url.contains("/api/hold"));

    assert!(intercept.forward(&entry.id, None));
    let response = client.await.unwrap();

    assert!(response.contains("200 OK"), "got: {response}");
    assert!(response.contains(r#"{"received":true}"#));
    let flows = wait_for_flows(&sink, 1).await;
    assert_eq!(flows[0].path, "/api/hold");
}

#[tokio::test]
async fn request_intercept_forward_with_edits() {
    let upstream = MockHttpUpstream::start().await;
    let sink = Arc::new(VecCaptureSink::default());
    let intercept = Arc::new(InterceptController::default());
    intercept.set_enabled(true);
    intercept.set_intercept_requests(true);
    intercept.set_intercept_responses(false);
    let proxy = start_proxy_with_intercept(
        ProxyConfig {
            port: 0,
            ..ProxyConfig::default()
        },
        ScopeConfig::default(),
        sink.clone(),
        intercept.clone(),
    )
    .await;
    let proxy_addr = proxy.local_addr().await.unwrap();
    let target = format!("127.0.0.1:{}", upstream.port);
    let client_target = target.clone();
    let client =
        tokio::spawn(
            async move { send_plain(proxy_addr, &client_target, "GET", "/api/orig").await },
        );
    let entry = poll_entry(&intercept, "request").await;

    let edit = InterceptEdit {
        method: "PATCH".into(),
        url: format!("http://{target}/api/edited?q=1"),
        status: None,
        reason: None,
        headers: vec![
            InterceptHeader {
                name: "x-edited".into(),
                value: "yes".into(),
            },
            InterceptHeader {
                name: "content-type".into(),
                value: "application/json".into(),
            },
        ],
        body: r#"{"edited":true}"#.into(),
    };
    assert!(intercept.forward(&entry.id, Some(edit)));
    let response = client.await.unwrap();

    assert!(response.contains("200 OK"), "got: {response}");
    let head = upstream.received.lock().unwrap()[0].clone();
    assert!(
        head.contains("PATCH"),
        "upstream must see edited method: {head}"
    );
    assert!(
        head.contains("/api/edited?q=1"),
        "upstream must see edited url: {head}"
    );
    assert!(
        head.contains("x-edited: yes"),
        "upstream must see edited header: {head}"
    );

    let flows = wait_for_flows(&sink, 1).await;
    let flow = &flows[0];
    assert_eq!(flow.method, HttpMethod::Patch);
    assert_eq!(flow.path, "/api/edited?q=1");
    assert!(flow.full_url.ends_with("/api/edited?q=1"));
    assert_eq!(flow.request_body.as_deref(), Some(r#"{"edited":true}"#));
    assert_eq!(
        flow.request_headers.get("x-edited").map(String::as_str),
        Some("yes")
    );
}

#[tokio::test]
async fn request_intercept_drop_closes_without_upstream() {
    let upstream = MockHttpUpstream::start().await;
    let sink = Arc::new(VecCaptureSink::default());
    let intercept = Arc::new(InterceptController::default());
    intercept.set_enabled(true);
    intercept.set_intercept_requests(true);
    let proxy = start_proxy_with_intercept(
        ProxyConfig {
            port: 0,
            ..ProxyConfig::default()
        },
        ScopeConfig::default(),
        sink.clone(),
        intercept.clone(),
    )
    .await;
    let proxy_addr = proxy.local_addr().await.unwrap();
    let target = format!("127.0.0.1:{}", upstream.port);

    let client =
        tokio::spawn(async move { send_plain(proxy_addr, &target, "GET", "/api/drop").await });
    let entry = poll_entry(&intercept, "request").await;

    assert!(intercept.drop_item(&entry.id));
    let response = client.await.unwrap();

    assert!(response.contains("200 OK"), "got: {response}");
    assert!(
        upstream.received.lock().unwrap().is_empty(),
        "upstream must not be contacted"
    );
    assert!(
        sink.flows().is_empty(),
        "dropped request must not be captured"
    );
}

#[tokio::test]
async fn response_intercept_forward_with_edits() {
    let upstream = MockHttpUpstream::start().await;
    let sink = Arc::new(VecCaptureSink::default());
    let intercept = Arc::new(InterceptController::default());
    intercept.set_enabled(true);
    intercept.set_intercept_requests(false);
    intercept.set_intercept_responses(true);
    let proxy = start_proxy_with_intercept(
        ProxyConfig {
            port: 0,
            ..ProxyConfig::default()
        },
        ScopeConfig::default(),
        sink.clone(),
        intercept.clone(),
    )
    .await;
    let proxy_addr = proxy.local_addr().await.unwrap();
    let target = format!("127.0.0.1:{}", upstream.port);

    let client =
        tokio::spawn(async move { send_plain(proxy_addr, &target, "GET", "/api/resp").await });
    let entry = poll_entry(&intercept, "response").await;
    assert_eq!(entry.kind, "response");
    assert_eq!(entry.status, Some(200));
    assert!(entry.body.contains("received"));

    let edit = InterceptEdit {
        method: entry.method.clone(),
        url: entry.url.clone(),
        status: Some(201),
        reason: Some("Created".into()),
        headers: vec![InterceptHeader {
            name: "x-rewritten".into(),
            value: "1".into(),
        }],
        body: r#"{"edited_response":true}"#.into(),
    };
    assert!(intercept.forward(&entry.id, Some(edit)));
    let response = client.await.unwrap();

    assert!(response.contains("201 Created"), "got: {response}");
    assert!(
        response.contains(r#"{"edited_response":true}"#),
        "got: {response}"
    );
    assert!(
        !response.contains("received"),
        "client must not see the original body"
    );

    let flows = wait_for_flows(&sink, 1).await;
    let flow = &flows[0];
    assert_eq!(flow.response_status, 201);
    assert_eq!(
        flow.response_body.as_deref(),
        Some(r#"{"edited_response":true}"#)
    );
    assert_eq!(
        flow.response_headers.get("x-rewritten").map(String::as_str),
        Some("1")
    );
}

#[tokio::test]
async fn response_intercept_drop() {
    let upstream = MockHttpUpstream::start().await;
    let sink = Arc::new(VecCaptureSink::default());
    let intercept = Arc::new(InterceptController::default());
    intercept.set_enabled(true);
    intercept.set_intercept_requests(false);
    intercept.set_intercept_responses(true);
    let proxy = start_proxy_with_intercept(
        ProxyConfig {
            port: 0,
            ..ProxyConfig::default()
        },
        ScopeConfig::default(),
        sink.clone(),
        intercept.clone(),
    )
    .await;
    let proxy_addr = proxy.local_addr().await.unwrap();
    let target = format!("127.0.0.1:{}", upstream.port);

    let client =
        tokio::spawn(async move { send_plain(proxy_addr, &target, "GET", "/api/resp").await });
    let entry = poll_entry(&intercept, "response").await;
    assert!(intercept.drop_item(&entry.id));
    let response = client.await.unwrap();

    assert!(response.contains("200 OK"), "got: {response}");
    assert!(
        !response.contains("received"),
        "dropped response body must not reach client"
    );
}

#[tokio::test]
async fn response_intercept_off_still_streams_large_bodies() {
    let upstream = MockHttpUpstream::start_with_body_size(2000).await;
    let sink = Arc::new(VecCaptureSink::default());
    let intercept = Arc::new(InterceptController::default());
    intercept.set_enabled(true);
    intercept.set_intercept_requests(true);
    intercept.set_intercept_responses(false);
    let proxy = start_proxy_with_intercept(
        ProxyConfig {
            port: 0,
            max_body_bytes: 100,
            ..ProxyConfig::default()
        },
        ScopeConfig::default(),
        sink.clone(),
        intercept.clone(),
    )
    .await;
    let proxy_addr = proxy.local_addr().await.unwrap();
    let target = format!("127.0.0.1:{}", upstream.port);

    let client =
        tokio::spawn(async move { send_plain(proxy_addr, &target, "GET", "/api/big").await });
    let entry = poll_entry(&intercept, "request").await;
    assert!(intercept.forward(&entry.id, None));
    let response = client.await.unwrap();

    let body_start = response
        .find("\r\n\r\n")
        .map(|index| index + 4)
        .unwrap_or(0);
    let relayed = response.len().saturating_sub(body_start);
    assert!(
        relayed >= 2000,
        "client must receive the full streamed body, got {relayed} bytes"
    );
    assert!(
        intercept.list().is_empty(),
        "response must not be held when response intercept is off"
    );
}

#[tokio::test]
async fn request_intercept_forward_with_post_body_edits() {
    let upstream = MockHttpUpstream::start().await;
    let sink = Arc::new(VecCaptureSink::default());
    let intercept = Arc::new(InterceptController::default());
    intercept.set_enabled(true);
    intercept.set_intercept_requests(true);
    intercept.set_intercept_responses(false);
    let proxy = start_proxy_with_intercept(
        ProxyConfig {
            port: 0,
            ..ProxyConfig::default()
        },
        ScopeConfig::default(),
        sink.clone(),
        intercept.clone(),
    )
    .await;
    let proxy_addr = proxy.local_addr().await.unwrap();
    let target = format!("127.0.0.1:{}", upstream.port);

    let client = tokio::spawn(async move {
        send_plain_with_body(
            proxy_addr,
            &target,
            "POST",
            "/api/login",
            r#"{"user":"admin"}"#,
        )
        .await
    });
    let entry = poll_entry(&intercept, "request").await;
    assert!(entry.body.contains("admin"));

    let edit = InterceptEdit {
        method: "POST".into(),
        url: entry.url.clone(),
        status: None,
        reason: None,
        headers: entry.headers.clone(),
        body: r#"{"user":"hacker"}"#.into(),
    };
    assert!(intercept.forward(&entry.id, Some(edit)));
    let response = client.await.unwrap();
    assert!(response.contains("200 OK"), "got: {response}");

    let flows = wait_for_flows(&sink, 1).await;
    assert_eq!(
        flows[0].request_body.as_deref(),
        Some(r#"{"user":"hacker"}"#)
    );
}

#[tokio::test]
async fn stop_proxy_releases_intercepted_requests() {
    let upstream = MockHttpUpstream::start().await;
    let sink = Arc::new(VecCaptureSink::default());
    let intercept = Arc::new(InterceptController::default());
    intercept.set_enabled(true);
    intercept.set_intercept_requests(true);
    let proxy = start_proxy_with_intercept(
        ProxyConfig {
            port: 0,
            ..ProxyConfig::default()
        },
        ScopeConfig::default(),
        sink.clone(),
        intercept.clone(),
    )
    .await;
    let proxy_addr = proxy.local_addr().await.unwrap();
    let target = format!("127.0.0.1:{}", upstream.port);

    let client =
        tokio::spawn(async move { send_plain(proxy_addr, &target, "GET", "/api/hang").await });
    let _entry = poll_entry(&intercept, "request").await;
    assert!(!intercept.is_empty());

    proxy.stop().await.unwrap();

    let response = tokio::time::timeout(std::time::Duration::from_secs(5), client)
        .await
        .expect("paused request must be released on stop (no hang)")
        .unwrap();
    assert!(response.contains("200 OK"), "got: {response}");
    assert_eq!(intercept.len(), 0, "pending items must be cleared on stop");
}
