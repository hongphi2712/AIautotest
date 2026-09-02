mod common;

use std::sync::{Arc, RwLock};

use api_tester_domain::{ProxyConfig, ScopeConfig};
use api_tester_ports::SessionRepository;
use api_tester_proxy::{
    CertProvider, MatchReplaceEngine, ProxyServer, RcgenCertProvider, ScopeFilter, UpstreamClient,
};
use api_tester_test_support::InMemorySessionRepository;
use common::{MockTlsUpstream, VecCaptureSink, send_connect_https, start_proxy, wait_for_flows};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

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

    let flows = wait_for_flows(&sink, 1).await;
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

#[tokio::test]
async fn https_mitm_cert_is_signed_by_generated_ca() {
    let upstream = MockTlsUpstream::start().await;
    let sink = Arc::new(VecCaptureSink::default());
    let scope_config = ScopeConfig {
        include_hosts: vec![r"127\.0\.0\.1".to_owned()],
        ..ScopeConfig::default()
    };

    let cert_dir = tempfile::tempdir().unwrap();
    let cert: Arc<dyn CertProvider> =
        Arc::new(RcgenCertProvider::new(cert_dir.path().to_path_buf()));
    let ca_pem = cert.ca_cert_pem().unwrap();

    let config = ProxyConfig {
        port: 0,
        ..ProxyConfig::default()
    };
    let scope = Arc::new(RwLock::new(ScopeFilter::new(scope_config).unwrap()));
    let match_replace = Arc::new(MatchReplaceEngine::new(vec![]));
    let upstream_client = Arc::new(UpstreamClient::new(&config).unwrap());
    let session_repository: Arc<dyn SessionRepository> =
        Arc::new(InMemorySessionRepository::default());
    let proxy = Arc::new(ProxyServer::new(
        config,
        scope,
        match_replace,
        cert,
        upstream_client,
        sink,
        session_repository,
    ));
    proxy.clone().start().await.unwrap();
    let proxy_addr = proxy.local_addr().await.unwrap();

    let target = format!("127.0.0.1:{}", upstream.port);
    let response = send_connect_https_trusting_ca(proxy_addr, &target, &ca_pem).await;

    assert!(response.contains("200 OK"), "got: {response}");
    assert!(response.contains(r#"{"secure":true}"#));
    assert!(!upstream.received.lock().unwrap().is_empty());
}

/// Connects through the proxy and completes a TLS handshake using a trust
/// store built from the proxy's generated CA, proving the MITM host
/// certificate chains to that CA.
async fn send_connect_https_trusting_ca(
    proxy: std::net::SocketAddr,
    target: &str,
    ca_pem: &str,
) -> String {
    let mut socket = TcpStream::connect(proxy).await.unwrap();
    let connect = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n");
    socket.write_all(connect.as_bytes()).await.unwrap();

    let mut head = Vec::new();
    let mut chunk = [0u8; 256];
    loop {
        let n = socket.read(&mut chunk).await.unwrap();
        head.extend_from_slice(&chunk[..n]);
        if head.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
    }
    assert!(
        String::from_utf8_lossy(&head).contains("200"),
        "expected 200 Connection Established, got: {}",
        String::from_utf8_lossy(&head)
    );

    let mut roots = rustls::RootCertStore::empty();
    let ca_der = CertificateDer::from_pem_slice(ca_pem.as_bytes()).unwrap();
    roots.add(ca_der).unwrap();
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(config));
    let server_name = ServerName::try_from("127.0.0.1").unwrap();
    let mut tls = connector.connect(server_name, socket).await.unwrap();

    let request = format!("GET /secure HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n");
    tls.write_all(request.as_bytes()).await.unwrap();

    let mut buffer = Vec::new();
    let mut read_chunk = [0u8; 4096];
    loop {
        match tls.read(&mut read_chunk).await {
            Ok(0) => break,
            Ok(n) => buffer.extend_from_slice(&read_chunk[..n]),
            Err(_) => break,
        }
    }
    String::from_utf8_lossy(&buffer).into_owned()
}
