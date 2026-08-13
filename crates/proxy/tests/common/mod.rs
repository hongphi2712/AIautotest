#![allow(dead_code)]

use std::sync::{Arc, Mutex};

use api_tester_domain::{HttpFlow, ProxyConfig, ScopeConfig};
use api_tester_ports::{CaptureSink, PortError, SessionRepository};
use api_tester_proxy::{
    CertProvider, MatchReplaceEngine, ProxyServer, RcgenCertProvider, ScopeFilter, UpstreamClient,
};
use api_tester_test_support::InMemorySessionRepository;
use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;

#[derive(Default)]
pub struct VecCaptureSink {
    pub flows: Mutex<Vec<HttpFlow>>,
}

#[async_trait]
impl CaptureSink for VecCaptureSink {
    async fn push(&self, flow: HttpFlow) -> Result<(), PortError> {
        self.flows
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .push(flow);
        Ok(())
    }
}

impl VecCaptureSink {
    pub fn flows(&self) -> Vec<HttpFlow> {
        self.flows
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .clone()
    }
}

pub async fn start_proxy(
    config: ProxyConfig,
    scope_config: ScopeConfig,
    sink: Arc<VecCaptureSink>,
) -> Arc<ProxyServer> {
    let scope = Arc::new(ScopeFilter::new(scope_config).unwrap());
    let match_replace = Arc::new(MatchReplaceEngine::new(vec![]));
    let cert_dir = tempfile::tempdir().unwrap();
    let cert: Arc<dyn CertProvider> =
        Arc::new(RcgenCertProvider::new(cert_dir.path().to_path_buf()));
    let upstream = Arc::new(UpstreamClient::new(&config).unwrap());
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
    proxy
}

pub struct MockHttpUpstream {
    pub port: u16,
    pub received: Arc<Mutex<Vec<String>>>,
}

impl MockHttpUpstream {
    pub async fn start() -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let received = Arc::new(Mutex::new(Vec::new()));
        tokio::spawn({
            let received = received.clone();
            async move {
                loop {
                    let Ok((socket, _)) = listener.accept().await else {
                        break;
                    };
                    let received = received.clone();
                    tokio::spawn(async move {
                        let mut socket = socket;
                        let mut buffer = Vec::new();
                        loop {
                            // Read until we have a complete request head.
                            while buffer.windows(4).any(|w| w == b"\r\n\r\n") {
                                let head_end = head_end_index(&buffer);
                                let head =
                                    String::from_utf8_lossy(&buffer[..head_end]).into_owned();
                                received
                                    .lock()
                                    .unwrap_or_else(|poison| poison.into_inner())
                                    .push(head);
                                buffer.drain(..head_end + 4);

                                let body = b"{\"received\":true}";
                                let response = format!(
                                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                                    body.len(),
                                    String::from_utf8_lossy(body)
                                );
                                if socket.write_all(response.as_bytes()).await.is_err() {
                                    return;
                                }
                            }
                            let mut chunk = [0u8; 2048];
                            match socket.read(&mut chunk).await {
                                Ok(0) => break,
                                Ok(n) => buffer.extend_from_slice(&chunk[..n]),
                                Err(_) => break,
                            }
                        }
                    });
                }
            }
        });
        Self { port, received }
    }
}

fn head_end_index(buffer: &[u8]) -> usize {
    buffer
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .unwrap_or(buffer.len())
}

pub async fn read_response<R: AsyncRead + Unpin>(reader: &mut R) -> String {
    let mut buffer = Vec::new();
    loop {
        if let Some(end) = buffer.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&buffer[..end]);
            if let Some(len) = content_length_of(&head) {
                if buffer.len() >= end + 4 + len {
                    return String::from_utf8_lossy(&buffer[..end + 4 + len]).into_owned();
                }
            }
        }
        let mut chunk = [0u8; 2048];
        let n = reader.read(&mut chunk).await.unwrap();
        if n == 0 {
            break;
        }
        buffer.extend_from_slice(&chunk[..n]);
    }
    String::from_utf8_lossy(&buffer).into_owned()
}

fn content_length_of(head: &str) -> Option<usize> {
    for line in head.split("\r\n").skip(1) {
        if let Some((name, value)) = line.split_once(':') {
            if name.eq_ignore_ascii_case("content-length") {
                return value.trim().parse().ok();
            }
        }
    }
    None
}

pub struct MockTlsUpstream {
    pub port: u16,
    pub received: Arc<Mutex<Vec<String>>>,
}

impl MockTlsUpstream {
    pub async fn start() -> Self {
        let cert_dir = tempfile::tempdir().unwrap();
        let provider = RcgenCertProvider::new(cert_dir.path().to_path_buf());
        let host_cert = provider.host_cert("localhost").unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(host_cert.server_config().unwrap()));

        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let received = Arc::new(Mutex::new(Vec::new()));
        tokio::spawn({
            let received = received.clone();
            async move {
                loop {
                    let Ok((socket, _)) = listener.accept().await else {
                        break;
                    };
                    let acceptor = acceptor.clone();
                    let received = received.clone();
                    tokio::spawn(async move {
                        let mut tls = match acceptor.accept(socket).await {
                            Ok(stream) => stream,
                            Err(_) => return,
                        };
                        let mut buffer = Vec::new();
                        let mut chunk = [0u8; 2048];
                        loop {
                            match tls.read(&mut chunk).await {
                                Ok(0) => break,
                                Ok(n) => {
                                    buffer.extend_from_slice(&chunk[..n]);
                                    if buffer.windows(4).any(|w| w == b"\r\n\r\n") {
                                        break;
                                    }
                                }
                                Err(_) => break,
                            }
                        }
                        received
                            .lock()
                            .unwrap_or_else(|poison| poison.into_inner())
                            .push(String::from_utf8_lossy(&buffer).into_owned());
                        let body = b"{\"secure\":true}";
                        let response = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            body.len(),
                            String::from_utf8_lossy(body)
                        );
                        let _ = tls.write_all(response.as_bytes()).await;
                    });
                }
            }
        });
        Self { port, received }
    }
}

pub async fn send_plain(
    proxy: std::net::SocketAddr,
    target: &str,
    method: &str,
    path: &str,
) -> String {
    let mut socket = TcpStream::connect(proxy).await.unwrap();
    let request = format!(
        "{method} http://{target}{path} HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n"
    );
    socket.write_all(request.as_bytes()).await.unwrap();
    read_all(socket).await
}

pub async fn send_plain_with_body(
    proxy: std::net::SocketAddr,
    target: &str,
    method: &str,
    path: &str,
    body: &str,
) -> String {
    let mut socket = TcpStream::connect(proxy).await.unwrap();
    let request = format!(
        "{method} http://{target}{path} HTTP/1.1\r\nHost: {target}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    socket.write_all(request.as_bytes()).await.unwrap();
    read_all(socket).await
}

pub async fn send_connect_https(
    proxy: std::net::SocketAddr,
    target: &str,
    method: &str,
    path: &str,
) -> String {
    let mut socket = TcpStream::connect(proxy).await.unwrap();
    let connect = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n");
    socket.write_all(connect.as_bytes()).await.unwrap();

    let mut head = Vec::new();
    let mut chunk = [0u8; 256];
    loop {
        let n = socket.read(&mut chunk).await.unwrap();
        head.extend_from_slice(&chunk[..n]);
        if head.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }
    assert!(
        String::from_utf8_lossy(&head).contains("200"),
        "expected 200 Connection Established, got: {}",
        String::from_utf8_lossy(&head)
    );

    let config = no_verify_client_config();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let server_name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
    let mut tls = connector.connect(server_name, socket).await.unwrap();

    let request =
        format!("{method} {path} HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n");
    tls.write_all(request.as_bytes()).await.unwrap();
    read_all(tls).await
}

fn no_verify_client_config() -> rustls::ClientConfig {
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::crypto::ring;
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use rustls::{DigitallySignedStruct, SignatureScheme};

    #[derive(Debug)]
    struct NoVerify;

    impl ServerCertVerifier for NoVerify {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, rustls::Error> {
            Ok(ServerCertVerified::assertion())
        }
        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }
        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }
        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            ring::default_provider()
                .signature_verification_algorithms
                .supported_schemes()
        }
    }

    let mut config = rustls::ClientConfig::builder()
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth();
    config
        .dangerous()
        .set_certificate_verifier(Arc::new(NoVerify));
    config
}

async fn read_all<R: AsyncRead + Unpin>(mut reader: R) -> String {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        match reader.read(&mut chunk).await {
            Ok(0) => break,
            Ok(n) => buffer.extend_from_slice(&chunk[..n]),
            Err(_) => break,
        }
    }
    String::from_utf8_lossy(&buffer).into_owned()
}
