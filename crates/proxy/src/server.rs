use std::convert::Infallible;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use bytes::Bytes;
use http_body_util::BodyExt;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio_rustls::TlsAcceptor;

use api_tester_domain::{HttpMethod, ProxyConfig};
use api_tester_ports::{CaptureSink, SessionRepository};

use crate::cert::CertProvider;
use crate::connect::parse_connect_target;
use crate::error::ProxyError;
use crate::flow::{FlowBuilder, FlowParts};
use crate::match_replace::MatchReplaceEngine;
use crate::scope::ScopeFilter;
use crate::session::ActiveSession;
use crate::transport::PrefixIo;
use crate::upstream::UpstreamClient;

const READ_HEAD_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
const MAX_HEAD_BYTES: usize = 64 * 1024;

pub struct ProxyServer {
    config: ProxyConfig,
    scope: Arc<ScopeFilter>,
    match_replace: Arc<MatchReplaceEngine>,
    cert: Arc<dyn CertProvider>,
    upstream: Arc<UpstreamClient>,
    sink: Arc<dyn CaptureSink>,
    session_repository: Arc<dyn SessionRepository>,
    session: tokio::sync::Mutex<Option<Arc<ActiveSession>>>,
    semaphore: Arc<Semaphore>,
    running: AtomicBool,
    accept_task: tokio::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
    bound_addr: tokio::sync::Mutex<Option<std::net::SocketAddr>>,
}

impl ProxyServer {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        config: ProxyConfig,
        scope: Arc<ScopeFilter>,
        match_replace: Arc<MatchReplaceEngine>,
        cert: Arc<dyn CertProvider>,
        upstream: Arc<UpstreamClient>,
        sink: Arc<dyn CaptureSink>,
        session_repository: Arc<dyn SessionRepository>,
    ) -> Self {
        let max_connections = config.max_connections.max(1);
        Self {
            config,
            scope,
            match_replace,
            cert,
            upstream,
            sink,
            session_repository,
            session: tokio::sync::Mutex::new(None),
            semaphore: Arc::new(Semaphore::new(max_connections)),
            running: AtomicBool::new(false),
            accept_task: tokio::sync::Mutex::new(None),
            bound_addr: tokio::sync::Mutex::new(None),
        }
    }

    pub async fn local_addr(&self) -> Option<std::net::SocketAddr> {
        *self.bound_addr.lock().await
    }

    pub async fn start(self: Arc<Self>) -> Result<(), ProxyError> {
        let addr = format!("{}:{}", self.config.host, self.config.port);
        let listener = TcpListener::bind(&addr).await.map_err(ProxyError::from)?;
        *self.bound_addr.lock().await = Some(listener.local_addr().map_err(ProxyError::from)?);

        let session = ActiveSession::start(
            self.session_repository.clone(),
            "capture",
            format!("{}:{}", self.config.host, self.config.port),
        )
        .await
        .map_err(|error| ProxyError::Runtime(error.to_string()))?;
        *self.session.lock().await = Some(Arc::new(session));

        self.running.store(true, Ordering::SeqCst);
        let this = self.clone();
        let task = tokio::spawn(async move {
            this.accept_loop(listener).await;
        });
        *self.accept_task.lock().await = Some(task);
        Ok(())
    }

    pub async fn stop(&self) -> Result<(), ProxyError> {
        self.running.store(false, Ordering::SeqCst);
        if let Some(task) = self.accept_task.lock().await.take() {
            task.abort();
        }
        if let Some(session) = self.session.lock().await.take() {
            session
                .stop()
                .await
                .map_err(|error| ProxyError::Runtime(error.to_string()))?;
        }
        Ok(())
    }

    async fn accept_loop(self: Arc<Self>, listener: TcpListener) {
        while self.running.load(Ordering::SeqCst) {
            match listener.accept().await {
                Ok((socket, _)) => {
                    let permit = match self.semaphore.clone().acquire_owned().await {
                        Ok(permit) => permit,
                        Err(_) => break,
                    };
                    let this = self.clone();
                    tokio::spawn(async move {
                        let _permit = permit;
                        this.handle_connection(socket).await;
                    });
                }
                Err(_) => break,
            }
        }
    }

    async fn handle_connection(self: Arc<Self>, mut socket: TcpStream) {
        let head = match tokio::time::timeout(READ_HEAD_TIMEOUT, read_head(&mut socket)).await {
            Ok(Ok(head)) => head,
            _ => return,
        };
        let method = first_token(&head);
        if method.eq_ignore_ascii_case("CONNECT") {
            let target = second_token(&head);
            self.handle_connect(socket, &target).await;
        } else {
            let client_ip = peer_ip(&socket);
            let io = TokioIo::new(PrefixIo::new(head, socket));
            let service = service_fn(move |req| {
                self.clone()
                    .handle_proxy_request(req, None, client_ip.clone())
            });
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(io, service)
                .await;
        }
    }

    async fn handle_connect(self: Arc<Self>, socket: TcpStream, target: &str) {
        let (host, port) = parse_connect_target(target);

        if self.scope.should_capture(&host, "/") {
            self.mitm(socket, &host, port).await;
        } else {
            self.tunnel(socket, &host, port).await;
        }
    }

    async fn mitm(self: Arc<Self>, socket: TcpStream, host: &str, port: u16) {
        let mut socket = socket;
        if socket
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await
            .is_err()
        {
            return;
        }

        let host_cert = match self.cert.host_cert(host) {
            Ok(cert) => cert,
            Err(_) => return,
        };
        let server_config = match host_cert.server_config() {
            Ok(config) => config,
            Err(_) => return,
        };
        let acceptor = TlsAcceptor::from(Arc::new(server_config));
        let tls_stream = match acceptor.accept(socket).await {
            Ok(stream) => stream,
            Err(_) => return,
        };

        let io = TokioIo::new(tls_stream);
        let client_ip = String::new();
        let tunnel_host = Some(if port == 443 {
            host.to_owned()
        } else {
            format!("{host}:{port}")
        });
        let service = service_fn(move |req| {
            self.clone()
                .handle_proxy_request(req, tunnel_host.clone(), client_ip.clone())
        });
        let _ = hyper::server::conn::http1::Builder::new()
            .serve_connection(io, service)
            .await;
    }

    async fn tunnel(&self, socket: TcpStream, host: &str, port: u16) {
        let mut socket = socket;
        let mut upstream = match TcpStream::connect((host, port)).await {
            Ok(stream) => stream,
            Err(_) => {
                let _ = socket.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await;
                return;
            }
        };
        if socket
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await
            .is_err()
        {
            return;
        }
        let _ = tokio::io::copy_bidirectional(&mut socket, &mut upstream).await;
    }

    async fn handle_proxy_request(
        self: Arc<Self>,
        mut req: Request<Incoming>,
        tunnel_host: Option<String>,
        client_ip: String,
    ) -> Result<Response<Full<Bytes>>, Infallible> {
        Ok(
            match self
                .proxy_request_inner(&mut req, tunnel_host, &client_ip)
                .await
            {
                Ok(response) => response,
                Err(error) => {
                    let body = Full::new(Bytes::from(error.to_string()));
                    Response::builder()
                        .status(StatusCode::BAD_GATEWAY)
                        .body(body)
                        .unwrap_or_else(|_| error_response(StatusCode::BAD_GATEWAY))
                }
            },
        )
    }

    async fn proxy_request_inner(
        &self,
        req: &mut Request<Incoming>,
        tunnel_host: Option<String>,
        client_ip: &str,
    ) -> Result<Response<Full<Bytes>>, ProxyError> {
        let (scheme, host) = match &tunnel_host {
            Some(host) => ("https".to_owned(), host.clone()),
            None => {
                let scheme = req.uri().scheme_str().unwrap_or("http").to_owned();
                let host = req
                    .uri()
                    .authority()
                    .map(|authority| authority.as_str().to_owned())
                    .or_else(|| {
                        req.headers()
                            .get("host")
                            .and_then(|value| value.to_str().ok())
                            .map(str::to_owned)
                    })
                    .ok_or_else(|| ProxyError::Runtime("missing target host".to_owned()))?;
                (scheme, host)
            }
        };
        let path = req
            .uri()
            .path_and_query()
            .map(|pq| pq.as_str().to_owned())
            .unwrap_or_else(|| "/".to_owned());
        let capture = self.scope.should_capture(&host, &path);

        let request_body = collect_body(req.body_mut(), self.config.max_body_bytes).await?;

        let mut request_headers = btree_from_headers(req.headers());
        let request_body_str = String::from_utf8_lossy(&request_body);
        request_headers = self.match_replace.apply_to_request_headers(
            &request_headers,
            &path,
            Some(&request_body_str),
        );

        let upstream_uri = format!("{scheme}://{host}{path}");
        let mut builder = Request::builder()
            .method(req.method().clone())
            .uri(&upstream_uri);
        for (name, value) in &request_headers {
            if !is_hop_by_hop(name) {
                builder = builder.header(name, value);
            }
        }
        let upstream_request = builder
            .body(Full::new(request_body.clone()))
            .map_err(|error| ProxyError::Runtime(error.to_string()))?;

        let response = self.upstream.send(upstream_request).await?;
        let (response_parts, mut response_body) = response.into_parts();
        let response_bytes = collect_body(&mut response_body, self.config.max_body_bytes).await?;

        let mut response_headers = btree_from_headers(&response_parts.headers);
        response_headers = self
            .match_replace
            .apply_to_response_headers(&response_headers, &path);

        let mut response_builder = Response::builder().status(response_parts.status);
        for (name, value) in &response_headers {
            if !is_hop_by_hop(name) {
                response_builder = response_builder.header(name, value);
            }
        }
        let client_response = response_builder
            .body(Full::new(response_bytes.clone()))
            .map_err(|error| ProxyError::Runtime(error.to_string()))?;

        if capture {
            self.capture_flow(
                req,
                &scheme,
                &host,
                &path,
                client_ip,
                &request_body,
                response_parts.status.as_u16(),
                &response_parts.headers,
                &response_bytes,
            )
            .await;
        }

        Ok(client_response)
    }

    #[allow(clippy::too_many_arguments)]
    async fn capture_flow(
        &self,
        req: &Request<Incoming>,
        scheme: &str,
        host: &str,
        path: &str,
        client_ip: &str,
        request_body: &[u8],
        status: u16,
        response_headers: &http::HeaderMap,
        response_body: &[u8],
    ) {
        let session_id = self
            .session
            .lock()
            .await
            .as_ref()
            .map(|session| session.id().to_owned())
            .unwrap_or_default();

        let builder = FlowBuilder::new(session_id, self.sink.clone(), self.config.max_body_bytes);
        let parts = FlowParts {
            timestamp: chrono::Utc::now(),
            method: method_from_str(req.method().as_str()),
            host,
            ip: client_ip,
            scheme,
            path,
            request_headers: req.headers(),
            request_body: Some(request_body),
            status,
            response_headers,
            response_body: Some(response_body),
        };
        let _ = builder.capture(parts).await;
    }
}

async fn read_head(socket: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let read = socket.read(&mut chunk).await?;
        if read == 0 {
            break;
        }
        buffer.extend_from_slice(&chunk[..read]);
        if buffer.windows(4).any(|window| window == b"\r\n\r\n") || buffer.len() > MAX_HEAD_BYTES {
            break;
        }
    }
    Ok(buffer)
}

fn first_token(head: &[u8]) -> String {
    head.split(|&byte| byte == b' ')
        .next()
        .map(|token| String::from_utf8_lossy(token).into_owned())
        .unwrap_or_default()
}

fn second_token(head: &[u8]) -> String {
    head.split(|&byte| byte == b' ')
        .nth(1)
        .map(|token| String::from_utf8_lossy(token).into_owned())
        .unwrap_or_default()
}

fn peer_ip(socket: &TcpStream) -> String {
    socket
        .peer_addr()
        .map(|addr| addr.ip().to_string())
        .unwrap_or_default()
}

async fn collect_body(body: &mut Incoming, max: usize) -> Result<Bytes, ProxyError> {
    let mut collected = Vec::new();
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|error| ProxyError::Runtime(error.to_string()))?;
        if let Ok(data) = frame.into_data() {
            if collected.len() + data.len() > max {
                let remaining = max.saturating_sub(collected.len());
                collected.extend_from_slice(&data[..remaining]);
                break;
            }
            collected.extend_from_slice(&data);
        }
    }
    Ok(Bytes::from(collected))
}

fn btree_from_headers(headers: &http::HeaderMap) -> std::collections::BTreeMap<String, String> {
    let mut map = std::collections::BTreeMap::new();
    for name in headers.keys() {
        if let Some(value) = headers.get(name) {
            map.insert(
                name.as_str().to_owned(),
                String::from_utf8_lossy(value.as_bytes()).into_owned(),
            );
        }
    }
    map
}

fn is_hop_by_hop(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "connection"
            | "proxy-connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

fn method_from_str(value: &str) -> HttpMethod {
    match value {
        "GET" => HttpMethod::Get,
        "POST" => HttpMethod::Post,
        "PUT" => HttpMethod::Put,
        "DELETE" => HttpMethod::Delete,
        "PATCH" => HttpMethod::Patch,
        "OPTIONS" => HttpMethod::Options,
        "HEAD" => HttpMethod::Head,
        _ => HttpMethod::Get,
    }
}

fn error_response(status: StatusCode) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .body(Full::new(Bytes::new()))
        .unwrap_or_else(|_| {
            Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Full::new(Bytes::new()))
                .unwrap()
        })
}
