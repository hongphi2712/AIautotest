mod common;

use std::sync::Arc;

use api_tester_domain::{ProxyConfig, ScopeConfig};
use common::{MockTlsUpstream, VecCaptureSink, send_connect_https, start_proxy};

#[tokio::test]
async fn https_mitm_decrypts_and_captures() {
    let upstream = MockTlsUpstream::start().await;
    let sink = Arc::new(VecCaptureSink::default());
    let scope_config = ScopeConfig {
        include_hosts: vec![r"127\.0\.0\.1".to_owned()],
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
    let response = send_connect_https(proxy_addr, &target, "GET", "/secure?x=1").await;

    assert!(response.contains("200 OK"), "got: {response}");
    assert!(response.contains(r#"{"secure":true}"#));
    assert!(!upstream.received.lock().unwrap().is_empty());

    let flows = sink.flows();
    assert_eq!(flows.len(), 1);
    let flow = &flows[0];
    assert_eq!(flow.method.as_str(), "GET");
    assert_eq!(flow.response_status, 200);
    assert!(flow.full_url.starts_with("https://"));
    assert!(
        flow.response_body
            .as_deref()
            .is_some_and(|body| body.contains("secure"))
    );
}

#[tokio::test]
async fn out_of_scope_connect_tunnels_without_capture() {
    let upstream = MockTlsUpstream::start().await;
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
    let response = send_connect_https(proxy_addr, &target, "GET", "/blinded").await;

    assert!(response.contains("200 OK"), "got: {response}");
    assert!(!upstream.received.lock().unwrap().is_empty());
    assert!(sink.flows().is_empty());
}
