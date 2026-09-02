mod common;

use std::sync::Arc;
use std::time::Duration;

use api_tester_domain::{ProxyConfig, ScopeConfig};
use api_tester_proxy::ScopeFilter;
use common::{MockHttpUpstream, VecCaptureSink, send_plain, start_proxy};

#[tokio::test]
async fn replaced_scope_takes_effect_without_restart() {
    let upstream = MockHttpUpstream::start().await;
    let sink = Arc::new(VecCaptureSink::default());
    let proxy = start_proxy(
        ProxyConfig {
            port: 0,
            ..ProxyConfig::default()
        },
        ScopeConfig {
            include_hosts: vec![r"^127\.0\.0\.1$".to_owned()],
            ..ScopeConfig::default()
        },
        sink.clone(),
    )
    .await;

    proxy.replace_scope(
        ScopeFilter::new(ScopeConfig {
            include_hosts: vec![r"^never\.captured$".to_owned()],
            ..ScopeConfig::default()
        })
        .unwrap(),
    );

    let proxy_addr = proxy.local_addr().await.unwrap();
    let target = format!("127.0.0.1:{}", upstream.port);
    let response = send_plain(proxy_addr, &target, "GET", "/api/test").await;
    assert!(response.contains("200 OK"), "got: {response}");

    for _ in 0..25 {
        if !sink.flows().is_empty() {
            panic!("request was captured after scope replacement");
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}
