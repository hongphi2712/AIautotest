mod common;

use std::sync::Arc;

use api_tester_domain::{ProxyConfig, ScopeConfig};
use common::{MockHttpUpstream, VecCaptureSink, send_plain, send_plain_with_body, start_proxy};
use tokio::io::AsyncWriteExt;

#[tokio::test]
async fn http_forward_and_capture() {
    let upstream = MockHttpUpstream::start().await;
    let sink = Arc::new(VecCaptureSink::default());
    let proxy = start_proxy(
        ProxyConfig {
            port: 0,
            ..ProxyConfig::default()
        },
        ScopeConfig::default(),
        sink.clone(),
    )
    .await;
    let proxy_addr = proxy.local_addr().await.unwrap();

    let target = format!("127.0.0.1:{}", upstream.port);
    let response = send_plain(proxy_addr, &target, "GET", "/api/test").await;

    assert!(response.contains("200 OK"), "got: {response}");
    assert!(response.contains(r#"{"received":true}"#));
    assert!(!upstream.received.lock().unwrap().is_empty());

    let flows = sink.flows();
    assert_eq!(flows.len(), 1);
    let flow = &flows[0];
    assert_eq!(flow.path, "/api/test");
    assert_eq!(flow.response_status, 200);
    assert!(flow.full_url.starts_with("http://"));
    assert!(
        flow.response_body
            .as_deref()
            .is_some_and(|body| body.contains("received"))
    );
    assert!(!flow.session_id.is_empty());
}

#[tokio::test]
async fn http_post_body_is_captured() {
    let upstream = MockHttpUpstream::start().await;
    let sink = Arc::new(VecCaptureSink::default());
    let proxy = start_proxy(
        ProxyConfig {
            port: 0,
            ..ProxyConfig::default()
        },
        ScopeConfig::default(),
        sink.clone(),
    )
    .await;
    let proxy_addr = proxy.local_addr().await.unwrap();

    let target = format!("127.0.0.1:{}", upstream.port);
    let response = send_plain_with_body(
        proxy_addr,
        &target,
        "POST",
        "/api/login",
        r#"{"user":"admin"}"#,
    )
    .await;

    assert!(response.contains("200 OK"), "got: {response}");

    let flows = sink.flows();
    assert_eq!(flows.len(), 1);
    let flow = &flows[0];
    assert_eq!(flow.method.as_str(), "POST");
    assert!(
        flow.request_body
            .as_deref()
            .is_some_and(|body| body.contains("admin"))
    );
}

#[tokio::test]
async fn out_of_scope_is_forwarded_but_not_captured() {
    let upstream = MockHttpUpstream::start().await;
    let sink = Arc::new(VecCaptureSink::default());
    let scope_config = ScopeConfig {
        include_hosts: vec!["never-matches\\.example".to_owned()],
        ..ScopeConfig::default()
    };
    let proxy = start_proxy(
        ProxyConfig {
            port: 0,
            ..ProxyConfig::default()
        },
        scope_config,
        sink.clone(),
    )
    .await;
    let proxy_addr = proxy.local_addr().await.unwrap();

    let target = format!("127.0.0.1:{}", upstream.port);
    let response = send_plain(proxy_addr, &target, "GET", "/out").await;

    assert!(response.contains("200 OK"), "got: {response}");
    assert!(!upstream.received.lock().unwrap().is_empty());
    assert!(sink.flows().is_empty());
}

#[tokio::test]
async fn http_keep_alive_captures_each_request() {
    let upstream = MockHttpUpstream::start().await;
    let sink = Arc::new(VecCaptureSink::default());
    let proxy = start_proxy(
        ProxyConfig {
            port: 0,
            ..ProxyConfig::default()
        },
        ScopeConfig::default(),
        sink.clone(),
    )
    .await;
    let proxy_addr = proxy.local_addr().await.unwrap();

    let target = format!("127.0.0.1:{}", upstream.port);
    let mut socket = tokio::net::TcpStream::connect(proxy_addr).await.unwrap();
    for index in 0..2 {
        let request =
            format!("GET http://{target}/api/keep/{index} HTTP/1.1\r\nHost: {target}\r\n\r\n");
        socket.write_all(request.as_bytes()).await.unwrap();
    }
    let first = common::read_response(&mut socket).await;
    let second = common::read_response(&mut socket).await;
    assert!(first.contains("200 OK") && second.contains("200 OK"));
    drop(socket);

    tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    let flows = sink.flows();
    assert_eq!(flows.len(), 2, "each keep-alive request must be captured");
    assert_eq!(flows[0].path, "/api/keep/0");
    assert_eq!(flows[1].path, "/api/keep/1");
}
