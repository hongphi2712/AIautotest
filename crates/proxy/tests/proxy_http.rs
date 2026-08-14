mod common;

use std::sync::Arc;

use api_tester_domain::{ProxyConfig, ScopeConfig};
use common::{
    MockHttpUpstream, VecCaptureSink, send_plain, send_plain_with_body, start_proxy, wait_for_flows,
};
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

    let flows = wait_for_flows(&sink, 1).await;
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

    let flows = wait_for_flows(&sink, 1).await;
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
    let flows = wait_for_flows(&sink, 2).await;
    assert_eq!(flows.len(), 2, "each keep-alive request must be captured");
    assert_eq!(flows[0].path, "/api/keep/0");
    assert_eq!(flows[1].path, "/api/keep/1");
}

#[tokio::test]
async fn large_response_relays_full_but_capture_is_capped() {
    let upstream = MockHttpUpstream::start_with_body_size(2000).await;
    let sink = Arc::new(VecCaptureSink::default());
    let proxy = start_proxy(
        ProxyConfig {
            port: 0,
            max_body_bytes: 100,
            ..ProxyConfig::default()
        },
        ScopeConfig::default(),
        sink.clone(),
    )
    .await;
    let proxy_addr = proxy.local_addr().await.unwrap();

    let target = format!("127.0.0.1:{}", upstream.port);
    let response = send_plain(proxy_addr, &target, "GET", "/api/big").await;

    let body_start = response
        .find("\r\n\r\n")
        .map(|index| index + 4)
        .unwrap_or(0);
    let relayed = response.len().saturating_sub(body_start);
    assert!(
        relayed >= 2000,
        "client must receive the full body, got {relayed} bytes"
    );

    let flows = wait_for_flows(&sink, 1).await;
    let flow = &flows[0];
    assert!(
        flow.response_body.as_deref().map(str::len).unwrap_or(0) <= 100,
        "capture must be capped at max_body_bytes"
    );
}

#[tokio::test]
async fn large_request_body_is_forwarded_in_full_but_capture_is_capped() {
    use tokio::io::AsyncReadExt;

    // Upstream that reads the declared content-length body and echoes the
    // received byte count back.
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .unwrap();
    let upstream_port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut buffer = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            let n = socket.read(&mut chunk).await.unwrap();
            if n == 0 {
                break;
            }
            buffer.extend_from_slice(&chunk[..n]);
            if let Some(end) = buffer.windows(4).position(|w| w == b"\r\n\r\n") {
                let head = String::from_utf8_lossy(&buffer[..end]).into_owned();
                let content_length: usize = head
                    .lines()
                    .find_map(|line| {
                        line.split_once(':').and_then(|(name, value)| {
                            if name.eq_ignore_ascii_case("content-length") {
                                value.trim().parse().ok()
                            } else {
                                None
                            }
                        })
                    })
                    .unwrap_or(0);
                if buffer.len() >= end + 4 + content_length {
                    let body_bytes = buffer.len() - (end + 4);
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body_bytes.to_string().len(),
                        body_bytes
                    );
                    let _ = socket.write_all(response.as_bytes()).await;
                    break;
                }
            }
        }
    });

    let sink = Arc::new(VecCaptureSink::default());
    let proxy = start_proxy(
        ProxyConfig {
            port: 0,
            max_body_bytes: 100,
            ..ProxyConfig::default()
        },
        ScopeConfig::default(),
        sink.clone(),
    )
    .await;
    let proxy_addr = proxy.local_addr().await.unwrap();

    let target = format!("127.0.0.1:{upstream_port}");
    let body = "x".repeat(500);
    let response = send_plain_with_body(proxy_addr, &target, "POST", "/api/upload", &body).await;

    assert!(
        response.contains("\r\n\r\n500"),
        "upstream must receive all 500 bytes, got: {response}"
    );

    let flows = wait_for_flows(&sink, 1).await;
    let flow = &flows[0];
    assert!(
        flow.request_body.as_deref().map(str::len).unwrap_or(0) <= 100,
        "captured request body must be capped at max_body_bytes"
    );
}
