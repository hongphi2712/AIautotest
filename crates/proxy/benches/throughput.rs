use std::sync::Arc;

use api_tester_domain::{HttpFlow, ProxyConfig, ScopeConfig};
use api_tester_ports::{CaptureSink, PortError, SessionRepository};
use api_tester_proxy::{
    CertProvider, MatchReplaceEngine, ProxyServer, RcgenCertProvider, ScopeFilter, UpstreamClient,
};
use api_tester_test_support::InMemorySessionRepository;
use async_trait::async_trait;
use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};

const BATCH: usize = 100;
const BODY: &[u8] = br#"{"received":true}"#;

struct NoopSink;

#[async_trait]
impl CaptureSink for NoopSink {
    async fn push(&self, _flow: HttpFlow) -> Result<(), PortError> {
        Ok(())
    }
}

fn bench_plain(c: &mut Criterion) {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let (proxy_addr, upstream_port, _ca_pem, _cert_keep) = runtime.block_on(setup_proxy(false));
    let target = format!("127.0.0.1:{upstream_port}");

    let mut group = c.benchmark_group("proxy/plain/keepalive");
    group.throughput(Throughput::Elements(BATCH as u64));
    group.bench_function("batch", |b| {
        b.iter(|| runtime.block_on(plain_batch(proxy_addr, &target)));
    });
    group.finish();
}

fn bench_https(c: &mut Criterion) {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let (proxy_addr, upstream_port, ca_pem, _cert_keep) = runtime.block_on(setup_proxy(true));
    let target = format!("127.0.0.1:{upstream_port}");
    let tls_config = ca_trusting_client_config(&ca_pem);

    let mut group = c.benchmark_group("proxy/https/mitm/keepalive");
    group.throughput(Throughput::Elements(BATCH as u64));
    group.bench_function("batch", |b| {
        b.iter(|| runtime.block_on(https_batch(proxy_addr, &target, tls_config.clone())));
    });
    group.finish();
}

/// Starts a proxy (plain or HTTPS-capable) with a local keep-alive upstream
/// and returns the proxy address, upstream port, generated CA PEM, and the
/// certificate directory guard (kept alive so the on-disk certs survive).
async fn setup_proxy(tls_upstream: bool) -> (std::net::SocketAddr, u16, String, tempfile::TempDir) {
    let upstream_port = if tls_upstream {
        start_tls_upstream().await
    } else {
        start_plain_upstream().await
    };

    let config = ProxyConfig {
        port: 0,
        ..ProxyConfig::default()
    };
    let scope = Arc::new(ScopeFilter::new(ScopeConfig::default()).unwrap());
    let match_replace = Arc::new(MatchReplaceEngine::new(vec![]));
    let cert_dir = tempfile::tempdir().unwrap();
    let cert: Arc<dyn CertProvider> =
        Arc::new(RcgenCertProvider::new(cert_dir.path().to_path_buf()));
    let ca_pem = cert.ca_cert_pem().unwrap();
    let upstream = Arc::new(UpstreamClient::new(&config).unwrap());
    let sink: Arc<dyn CaptureSink> = Arc::new(NoopSink);
    let session_repository: Arc<dyn SessionRepository> =
        Arc::new(InMemorySessionRepository::default());
    let proxy = Arc::new(ProxyServer::new(
        config,
        scope,
        match_replace,
        cert,
        upstream,
        sink,
        session_repository,
    ));
    proxy.clone().start().await.unwrap();
    let proxy_addr = proxy.local_addr().await.unwrap();
    (proxy_addr, upstream_port, ca_pem, cert_dir)
}

async fn start_plain_upstream() -> u16 {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((socket, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(serve_keepalive(socket));
        }
    });
    port
}

async fn start_tls_upstream() -> u16 {
    let cert_dir = tempfile::tempdir().unwrap();
    let provider = RcgenCertProvider::new(cert_dir.path().to_path_buf());
    let host_cert = provider.host_cert("localhost").unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(host_cert.server_config().unwrap()));
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((socket, _)) = listener.accept().await else {
                break;
            };
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                if let Ok(tls) = acceptor.accept(socket).await {
                    serve_keepalive(tls).await;
                }
            });
        }
    });
    port
}

/// Responds to every request head on one keep-alive connection.
async fn serve_keepalive<R>(mut socket: R)
where
    R: AsyncRead + AsyncWrite + Unpin,
{
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 2048];
    loop {
        while buffer.windows(4).any(|window| window == b"\r\n\r\n") {
            buffer.drain(..head_end(&buffer));
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}",
                BODY.len(),
                String::from_utf8_lossy(BODY)
            );
            if socket.write_all(response.as_bytes()).await.is_err() {
                return;
            }
        }
        match socket.read(&mut chunk).await {
            Ok(0) => return,
            Ok(n) => buffer.extend_from_slice(&chunk[..n]),
            Err(_) => return,
        }
    }
}

fn head_end(buffer: &[u8]) -> usize {
    buffer
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|index| index + 4)
        .unwrap_or(buffer.len())
}

/// Sends `BATCH` sequential keep-alive requests and reads each response.
async fn plain_batch(proxy_addr: std::net::SocketAddr, target: &str) {
    let mut socket = TcpStream::connect(proxy_addr).await.unwrap();
    for _ in 0..BATCH {
        let request = format!("GET http://{target}/api HTTP/1.1\r\nHost: {target}\r\n\r\n");
        socket.write_all(request.as_bytes()).await.unwrap();
        let mut chunk = [0u8; 4096];
        let n = socket.read(&mut chunk).await.unwrap();
        assert!(String::from_utf8_lossy(&chunk[..n]).contains("200 OK"));
    }
}

/// Connects via CONNECT + TLS (validating the proxy cert against its CA),
/// then sends `BATCH` sequential keep-alive requests over the tunnel.
async fn https_batch(proxy_addr: std::net::SocketAddr, target: &str, config: rustls::ClientConfig) {
    let mut socket = TcpStream::connect(proxy_addr).await.unwrap();
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
    assert!(String::from_utf8_lossy(&head).contains("200"));

    let connector = TlsConnector::from(Arc::new(config));
    let server_name = ServerName::try_from("127.0.0.1").unwrap();
    let mut tls = connector.connect(server_name, socket).await.unwrap();
    for _ in 0..BATCH {
        let request = format!("GET /api HTTP/1.1\r\nHost: {target}\r\n\r\n");
        tls.write_all(request.as_bytes()).await.unwrap();
        let mut chunk = [0u8; 4096];
        let n = tls.read(&mut chunk).await.unwrap();
        assert!(String::from_utf8_lossy(&chunk[..n]).contains("200 OK"));
    }
}

fn ca_trusting_client_config(ca_pem: &str) -> rustls::ClientConfig {
    let mut roots = rustls::RootCertStore::empty();
    let ca_der = CertificateDer::from_pem_slice(ca_pem.as_bytes()).unwrap();
    roots.add(ca_der).unwrap();
    rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth()
}

criterion_group!(benches, bench_plain, bench_https);
criterion_main!(benches);
