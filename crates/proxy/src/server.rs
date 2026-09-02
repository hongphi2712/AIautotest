use std::collections::HashMap;
use std::convert::Infallible;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::RwLock;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use bytes::Bytes;
use http_body_util::BodyExt;
use http_body_util::Full;
use http_body_util::combinators::BoxBody;
use hyper::body::{Body, Frame, Incoming, SizeHint};
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::sync::watch;
use tokio_rustls::TlsAcceptor;

use api_tester_domain::{HttpMethod, ProxyConfig, RuleDirection, ScopeFilter};
use api_tester_ports::{CaptureSink, SessionRepository};

use crate::cert::CertProvider;
use crate::connect::parse_connect_target;
use crate::error::ProxyError;
use crate::flow::{FlowBuilder, FlowParts};
use crate::intercept::{
    InterceptController, InterceptDecision, InterceptEntry, headers_from_intercept,
    headers_to_intercept, parse_edited_url,
};
use crate::match_replace::MatchReplaceEngine;
use crate::session::ActiveSession;
use crate::transport::PrefixIo;
use crate::upstream::UpstreamClient;

const READ_HEAD_TIMEOUT: Duration = Duration::from_secs(10);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const DRAIN_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_HEAD_BYTES: usize = 64 * 1024;
/// Cooldown before the same tunnel failure (per host/error) is reported again.
/// Ad/tracker beacons to dead hosts (e.g. AdSense tynt.com) fail repeatedly and
/// would otherwise flood the console and the UI's `last_error`.
const TUNNEL_ERROR_COOLDOWN: Duration = Duration::from_secs(30);
const MAX_TUNNEL_ERROR_KEYS: usize = 512;
/// Cap on the body shipped with each intercepted entry to the UI (polled every
/// second while intercept is on). Forwarding unchanged still uses the full body
/// held by the proxy; only an explicit edit round-trips the truncated copy.
const INTERCEPT_BODY_CAP: usize = 256 * 1024;

/// Throttles repeated diagnostics for identical tunnel failures so ad beacons
/// to dead hosts (e.g. AdSense tynt.com) only surface once per cooldown.
struct TunnelErrorReporter {
    reported: HashMap<String, Instant>,
}

impl TunnelErrorReporter {
    fn new() -> Self {
        Self {
            reported: HashMap::new(),
        }
    }

    fn should_report(&mut self, message: &str) -> bool {
        if self.reported.len() >= MAX_TUNNEL_ERROR_KEYS {
            self.reported.clear();
        }
        let now = Instant::now();
        if let Some(last) = self.reported.get(message) {
            if now.duration_since(*last) < TUNNEL_ERROR_COOLDOWN {
                return false;
            }
        }
        self.reported.insert(message.to_owned(), now);
        true
    }
}

type RelayBody = BoxBody<Bytes, Infallible>;

pub struct ProxyServer {
    config: ProxyConfig,
    scope: Arc<RwLock<ScopeFilter>>,
    match_replace: Arc<MatchReplaceEngine>,
    cert: Arc<dyn CertProvider>,
    upstream: Arc<UpstreamClient>,
    sink: Arc<dyn CaptureSink>,
    session_repository: Arc<dyn SessionRepository>,
    intercept: Arc<InterceptController>,
    session: Arc<tokio::sync::Mutex<Option<Arc<ActiveSession>>>>,
    session_id_source: Option<Arc<tokio::sync::Mutex<Option<String>>>>,
    semaphore: Arc<Semaphore>,
    running: AtomicBool,
    accept_task: tokio::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
    connections: tokio::sync::Mutex<Vec<tokio::task::JoinHandle<()>>>,
    shutdown: watch::Sender<bool>,
    bound_addr: tokio::sync::Mutex<Option<std::net::SocketAddr>>,
    on_error: Option<Arc<dyn Fn(String) + Send + Sync>>,
    tunnel_errors: std::sync::Mutex<TunnelErrorReporter>,
}

/// Request-side context needed to build the captured flow after a response
/// has finished streaming to the client.
#[derive(Clone)]
struct FlowCaptureCtx {
    timestamp: chrono::DateTime<chrono::Utc>,
    duration_ms: u64,
    method: HttpMethod,
    host: String,
    ip: String,
    scheme: String,
    path: String,
    request_headers: http::HeaderMap,
    request_body: Vec<u8>,
    status: u16,
    response_headers: http::HeaderMap,
}

/// Builds a capture context from the (possibly edited) request and the final
/// response status/headers. Shared by the streaming and intercepted-response
/// paths.
#[allow(clippy::too_many_arguments)]
fn build_ctx(
    start_instant: Instant,
    method: &HttpMethod,
    host: &str,
    ip: &str,
    scheme: &str,
    path: &str,
    request_headers: &http::HeaderMap,
    request_body: &[u8],
    status: u16,
    response_headers: &http::HeaderMap,
) -> FlowCaptureCtx {
    FlowCaptureCtx {
        timestamp: chrono::Utc::now(),
        duration_ms: start_instant.elapsed().as_millis() as u64,
        method: method.clone(),
        host: host.to_owned(),
        ip: ip.to_owned(),
        scheme: scheme.to_owned(),
        path: path.to_owned(),
        request_headers: request_headers.clone(),
        request_body: request_body.to_vec(),
        status,
        response_headers: response_headers.clone(),
    }
}

#[derive(Default)]
struct CapturedBody {
    bytes: Vec<u8>,
    truncated: bool,
}

/// Relays an upstream response body to the client while capturing a capped
/// copy for the flow. The flow is finalized when the captured body reaches the
/// declared `Content-Length`, when it is truncated at the cap, or when the
/// (chunked) stream ends â€” because hyper stops polling a sized relay body
/// without awaiting `Ready(None)`.
struct TeeBody {
    inner: Incoming,
    capture: CapturedBody,
    max_capture: usize,
    expected: Option<u64>,
    done: bool,
    sink: Arc<dyn CaptureSink>,
    session: Arc<tokio::sync::Mutex<Option<Arc<ActiveSession>>>>,
    session_id_source: Option<Arc<tokio::sync::Mutex<Option<String>>>>,
    ctx: Option<FlowCaptureCtx>,
}

impl TeeBody {
    fn new(
        inner: Incoming,
        max_capture: usize,
        expected: Option<u64>,
        sink: Arc<dyn CaptureSink>,
        session: Arc<tokio::sync::Mutex<Option<Arc<ActiveSession>>>>,
        session_id_source: Option<Arc<tokio::sync::Mutex<Option<String>>>>,
        ctx: Option<FlowCaptureCtx>,
    ) -> Self {
        Self {
            inner,
            capture: CapturedBody::default(),
            max_capture,
            expected,
            done: false,
            sink,
            session,
            session_id_source,
            ctx,
        }
    }

    fn capture_frame(&mut self, data: &[u8]) {
        if self.done {
            return;
        }
        let room = self.max_capture.saturating_sub(self.capture.bytes.len());
        if data.len() > room {
            self.capture.bytes.extend_from_slice(&data[..room]);
            self.capture.truncated = true;
            self.finalize();
            return;
        }
        self.capture.bytes.extend_from_slice(data);
        if let Some(expected) = self.expected {
            if self.capture.bytes.len() >= expected as usize {
                self.finalize();
            }
        }
    }

    fn finalize(&mut self) {
        if self.done {
            return;
        }
        self.done = true;
        let Some(ctx) = self.ctx.take() else {
            return;
        };
        let sink = self.sink.clone();
        let session = self.session.clone();
        let session_id_source = self.session_id_source.clone();
        let max = self.max_capture;
        let captured = std::mem::take(&mut self.capture);
        spawn_capture(session, session_id_source, sink, max, ctx, captured.bytes);
    }
}

/// Persists a finished request/response pair via `FlowBuilder` and updates the
/// session flow count. Shared by the streaming (`TeeBody`) and buffered
/// (intercepted response) capture paths.
/// When `session_id_source` is Some, per-flow captures prefer the active
/// session id from AppState (async lock per flow) with fallback to the
/// legacy orphan `session` for tests / when no active session.
fn spawn_capture(
    session: Arc<tokio::sync::Mutex<Option<Arc<ActiveSession>>>>,
    session_id_source: Option<Arc<tokio::sync::Mutex<Option<String>>>>,
    sink: Arc<dyn CaptureSink>,
    max: usize,
    ctx: FlowCaptureCtx,
    response_body: Vec<u8>,
) {
    let session_clone = session.clone();
    let sink_clone = sink.clone();
    tokio::spawn(async move {
        let supplied: Option<String> = if let Some(src) = &session_id_source {
            src.lock().await.clone()
        } else {
            None
        };
        let (session_id, is_supplied) = match supplied {
            Some(id) if !id.trim().is_empty() => (id, true),
            _ => {
                let guard = session_clone.lock().await;
                let Some(active) = guard.as_ref() else {
                    return;
                };
                (active.id().to_owned(), false)
            }
        };
        let builder = FlowBuilder::new(session_id.clone(), sink_clone, max);
        let parts = FlowParts {
            timestamp: ctx.timestamp,
            duration_ms: ctx.duration_ms,
            method: ctx.method,
            host: &ctx.host,
            ip: &ctx.ip,
            scheme: &ctx.scheme,
            path: &ctx.path,
            request_headers: &ctx.request_headers,
            request_body: Some(&ctx.request_body),
            status: ctx.status,
            response_headers: &ctx.response_headers,
            response_body: if response_body.is_empty() {
                None
            } else {
                Some(&response_body)
            },
        };
        if builder.capture(parts).await.is_ok() {
            // flow_count now handled thoroughly in DashboardSink for both orphan and supplied
            let _ = is_supplied;
        }
    });
}

impl Body for TeeBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        match Pin::new(&mut self.inner).poll_frame(cx) {
            std::task::Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    self.capture_frame(data);
                }
                std::task::Poll::Ready(Some(Ok(frame)))
            }
            std::task::Poll::Ready(Some(Err(_))) => std::task::Poll::Ready(None),
            std::task::Poll::Ready(None) => {
                self.finalize();
                std::task::Poll::Ready(None)
            }
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

impl ProxyServer {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        config: ProxyConfig,
        scope: Arc<RwLock<ScopeFilter>>,
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
            intercept: Arc::new(InterceptController::default()),
            session: Arc::new(tokio::sync::Mutex::new(None)),
            session_id_source: None,
            semaphore: Arc::new(Semaphore::new(max_connections)),
            running: AtomicBool::new(false),
            accept_task: tokio::sync::Mutex::new(None),
            connections: tokio::sync::Mutex::new(Vec::new()),
            shutdown: watch::channel(false).0,
            bound_addr: tokio::sync::Mutex::new(None),
            on_error: None,
            tunnel_errors: std::sync::Mutex::new(TunnelErrorReporter::new()),
        }
    }

    /// Supply active-session id from AppState. Per-flow captures prefer this
    /// id (async lock per flow) with fallback to legacy orphan session.
    pub fn with_session_id_source(
        mut self,
        source: Arc<tokio::sync::Mutex<Option<String>>>,
    ) -> Self {
        self.session_id_source = Some(source);
        self
    }

    /// Replaces the capture scope without restarting the listener.
    pub fn replace_scope(&self, scope: ScopeFilter) {
        *self
            .scope
            .write()
            .unwrap_or_else(|poison| poison.into_inner()) = scope;
    }

    /// Registers a callback invoked with the error message whenever a proxied
    /// request fails (surfaced to the UI for diagnostics).
    pub fn on_error(mut self, callback: Arc<dyn Fn(String) + Send + Sync>) -> Self {
        self.on_error = Some(callback);
        self
    }

    /// Attaches the intercept controller. Requests/responses pause for the
    /// UI to forward or drop them only while `set_enabled(true)`.
    pub fn with_intercept(mut self, intercept: Arc<InterceptController>) -> Self {
        self.intercept = intercept;
        self
    }

    pub async fn local_addr(&self) -> Option<std::net::SocketAddr> {
        *self.bound_addr.lock().await
    }

    pub async fn start(self: Arc<Self>) -> Result<(), ProxyError> {
        let addr = format!("{}:{}", self.config.host, self.config.port);
        let listener = TcpListener::bind(&addr).await.map_err(ProxyError::from)?;
        *self.bound_addr.lock().await = Some(listener.local_addr().map_err(ProxyError::from)?);

        // Strict gate: when supplier is present, don't create orphan capture session
        let should_create_orphan = self.session_id_source.is_none();
        if should_create_orphan {
            let session = ActiveSession::start(
                self.session_repository.clone(),
                "capture",
                format!("{}:{}", self.config.host, self.config.port),
            )
            .await
            .map_err(|error| ProxyError::Runtime(error.to_string()))?;
            *self.session.lock().await = Some(Arc::new(session));
        } else {
            *self.session.lock().await = None;
        }

        self.running.store(true, Ordering::SeqCst);
        let this = self.clone();
        let task = tokio::spawn(async move {
            this.accept_loop(listener).await;
        });
        *self.accept_task.lock().await = Some(task);
        Ok(())
    }

    pub async fn stop(&self) -> Result<(), ProxyError> {
        // Release any intercepted items so paused proxy tasks can finish.
        self.intercept.clear_all();
        self.running.store(false, Ordering::SeqCst);
        if let Some(task) = self.accept_task.lock().await.take() {
            task.abort();
        }

        let _ = self.shutdown.send(true);
        let mut handles = std::mem::take(&mut *self.connections.lock().await);
        let deadline = std::time::Instant::now() + DRAIN_TIMEOUT;
        loop {
            let mut remaining = Vec::new();
            for handle in handles {
                if handle.is_finished() {
                    let _ = handle.await;
                } else {
                    remaining.push(handle);
                }
            }
            handles = remaining;
            if handles.is_empty() || std::time::Instant::now() >= deadline {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        for handle in handles {
            handle.abort();
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
                    let handle = tokio::spawn(async move {
                        let _permit = permit;
                        this.handle_connection(socket).await;
                    });
                    self.connections.lock().await.push(handle);
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
        let shutdown = self.shutdown.subscribe();
        let method = first_token(&head);
        if method.eq_ignore_ascii_case("CONNECT") {
            let target = second_token(&head);
            self.handle_connect(socket, &target, shutdown).await;
        } else {
            let client_ip = peer_ip(&socket);
            let io = PrefixIo::new(head, socket);
            let service = service_fn(move |req| {
                self.clone()
                    .handle_proxy_request(req, None, client_ip.clone())
            });
            serve_with_graceful_shutdown(io, service, shutdown).await;
        }
    }

    async fn handle_connect(
        self: Arc<Self>,
        socket: TcpStream,
        target: &str,
        shutdown: watch::Receiver<bool>,
    ) {
        let (host, port) = parse_connect_target(target);

        let should_capture = self
            .scope
            .read()
            .unwrap_or_else(|poison| poison.into_inner())
            .should_capture(&host, "/");
        if should_capture {
            let client_ip = peer_ip(&socket);
            self.mitm(socket, &host, port, client_ip, shutdown).await;
        } else {
            self.tunnel(socket, &host, port, shutdown).await;
        }
    }

    async fn mitm(
        self: Arc<Self>,
        socket: TcpStream,
        host: &str,
        port: u16,
        client_ip: String,
        shutdown: watch::Receiver<bool>,
    ) {
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
        let tls_stream =
            match tokio::time::timeout(TLS_HANDSHAKE_TIMEOUT, acceptor.accept(socket)).await {
                Ok(Ok(stream)) => stream,
                _ => return,
            };

        let tunnel_host = Some(if port == 443 {
            host.to_owned()
        } else {
            format!("{host}:{port}")
        });
        let service = service_fn(move |req| {
            self.clone()
                .handle_proxy_request(req, tunnel_host.clone(), client_ip.clone())
        });
        serve_with_graceful_shutdown(tls_stream, service, shutdown).await;
    }

    async fn tunnel(
        &self,
        socket: TcpStream,
        host: &str,
        port: u16,
        mut shutdown: watch::Receiver<bool>,
    ) {
        let mut socket = socket;
        let mut upstream =
            match tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect((host, port))).await {
                Ok(Ok(stream)) => stream,
                Ok(Err(error)) => {
                    let message = format!("tunnel connect failed for {host}:{port}: {error}");
                    self.report_tunnel_error(&message);
                    let _ = socket.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await;
                    return;
                }
                Err(_) => {
                    let message = format!("tunnel connect timed out for {host}:{port}");
                    self.report_tunnel_error(&message);
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
        tokio::select! {
            _ = tokio::io::copy_bidirectional(&mut socket, &mut upstream) => {}
            _ = shutdown.changed() => {}
        }
    }

    /// Reports a tunnel failure, throttling repeats of the same error so ad
    /// beacons to dead hosts don't flood the console or the UI diagnostics.
    fn report_tunnel_error(&self, message: &str) {
        let should_report = self
            .tunnel_errors
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .should_report(message);
        if !should_report {
            return;
        }
        eprintln!("[proxy] {message}");
        if let Some(callback) = &self.on_error {
            callback(message.to_owned());
        }
    }

    async fn handle_proxy_request(
        self: Arc<Self>,
        mut req: Request<Incoming>,
        tunnel_host: Option<String>,
        client_ip: String,
    ) -> Result<Response<RelayBody>, Infallible> {
        Ok(
            match self
                .proxy_request_inner(&mut req, tunnel_host, &client_ip)
                .await
            {
                Ok(response) => response,
                Err(error) => {
                    eprintln!("[proxy] request failed: {error}");
                    if let Some(callback) = &self.on_error {
                        callback(error.to_string());
                    }
                    let body = BoxBody::new(Full::new(Bytes::from(error.to_string())));
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
    ) -> Result<Response<RelayBody>, ProxyError> {
        let start_instant = std::time::Instant::now();
        let (mut scheme, mut host) = match &tunnel_host {
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
        let mut path = req
            .uri()
            .path_and_query()
            .map(|pq| pq.as_str().to_owned())
            .unwrap_or_else(|| "/".to_owned());

        // Serve the CRL that MITM certificates point to, so strict clients can
        // complete revocation checks against this proxy.
        if tunnel_host.is_none() && path == "/ca.crl" {
            return self.serve_crl();
        }

        let capture = self
            .scope
            .read()
            .unwrap_or_else(|poison| poison.into_inner())
            .should_capture(&host, &path);

        // Collect the full request body: truncating here would silently corrupt
        // large uploads forwarded upstream. The captured copy is capped instead
        // (`capture_request_body` below).
        let (request_body, _request_truncated) = collect_body(req.body_mut(), usize::MAX).await?;

        let mut request_headers = req.headers().clone();
        let request_body_str = String::from_utf8_lossy(&request_body);

        // Apply `replace_url` rules to the full request URL (scheme://host/path)
        // before anything downstream (intercept entry, upstream target, captured
        // flow) observes it. The Host header is synced so HTTP/1.1 stays
        // consistent with the new authority. An unparseable rewrite keeps the
        // original URL.
        let url_before = format!("{scheme}://{host}{path}");
        let url_after = self.match_replace.apply_to_url(
            &url_before,
            &request_headers,
            &path,
            Some(&request_body_str),
        );
        if url_after != url_before {
            if let Some((edit_scheme, edit_host, edit_path)) = parse_edited_url(&url_after) {
                scheme = edit_scheme;
                host = edit_host;
                path = edit_path;
                if let Ok(host_value) = http::HeaderValue::from_str(&host) {
                    request_headers.insert("host", host_value);
                }
            }
        }

        request_headers = self.match_replace.apply_to_request_headers(
            &request_headers,
            &path,
            Some(&request_body_str),
        );

        let mut request_body = request_body;
        let mut request_modified = false;
        if let Ok(request_text) = std::str::from_utf8(&request_body) {
            let rewritten = self.match_replace.apply_to_body(
                request_text,
                RuleDirection::Request,
                &request_headers,
                &path,
            );
            if rewritten != request_text {
                request_body = Bytes::from(rewritten.into_bytes());
                request_modified = true;
            }
        }
        if request_modified {
            let content_length = http::HeaderValue::from_str(&request_body.len().to_string())
                .map_err(|error| ProxyError::Runtime(error.to_string()))?;
            request_headers.insert("content-length", content_length);
        }

        let mut method = req.method().clone();

        if self.intercept.should_intercept_request() {
            let entry = InterceptEntry {
                id: uuid::Uuid::new_v4().to_string(),
                kind: "request".to_owned(),
                method: method.as_str().to_owned(),
                url: format!("{scheme}://{host}{path}"),
                status: None,
                reason: None,
                headers: headers_to_intercept(&request_headers),
                body: String::from_utf8_lossy(
                    &request_body[..request_body.len().min(INTERCEPT_BODY_CAP)],
                )
                .into_owned(),
                body_len: request_body.len(),
                timestamp: chrono::Utc::now(),
            };
            let rx = self.intercept.enqueue(entry);
            match InterceptController::wait_for_decision(rx).await {
                InterceptDecision::Drop => return dropped_response(),
                InterceptDecision::Forward(edit) => {
                    if let Some(edit) = edit {
                        if let Some((edit_scheme, edit_host, edit_path)) =
                            parse_edited_url(&edit.url)
                        {
                            scheme = edit_scheme;
                            host = edit_host;
                            path = edit_path;
                        }
                        if let Ok(edit_method) = edit.method.parse::<http::Method>() {
                            method = edit_method;
                        }
                        request_headers = headers_from_intercept(&edit.headers);
                        request_body = Bytes::from(edit.body.into_bytes());
                        let content_length =
                            http::HeaderValue::from_str(&request_body.len().to_string())
                                .map_err(|error| ProxyError::Runtime(error.to_string()))?;
                        request_headers.insert("content-length", content_length);
                    }
                }
            }
        }

        // Capped copy of the (possibly edited) request body for capture, so the
        // stored flow stays within `max_body_bytes` regardless of upload size.
        let capture_request_body =
            request_body[..request_body.len().min(self.config.max_body_bytes)].to_vec();

        let upstream_uri = format!("{scheme}://{host}{path}");
        let mut builder = Request::builder().method(method.clone()).uri(&upstream_uri);
        for (name, value) in &request_headers {
            if !is_hop_by_hop(name.as_str()) {
                builder = builder.header(name, value);
            }
        }
        let upstream_request = builder
            .body(Full::new(request_body.clone()))
            .map_err(|error| ProxyError::Runtime(error.to_string()))?;

        let response = self.upstream.send(upstream_request).await?;
        let (response_parts, mut response_body) = response.into_parts();

        let mut response_headers = response_parts.headers.clone();
        response_headers = self
            .match_replace
            .apply_to_response_headers(&response_headers, &path);

        if self.intercept.should_intercept_response() {
            let cap = self.config.max_body_bytes.max(64 * 1024);
            let (full_body, _) = collect_body(&mut response_body, cap).await?;
            let entry = InterceptEntry {
                id: uuid::Uuid::new_v4().to_string(),
                kind: "response".to_owned(),
                method: method.as_str().to_owned(),
                url: format!("{scheme}://{host}{path}"),
                status: Some(response_parts.status.as_u16()),
                reason: response_parts.status.canonical_reason().map(str::to_owned),
                headers: headers_to_intercept(&response_headers),
                body: String::from_utf8_lossy(
                    &full_body[..full_body.len().min(INTERCEPT_BODY_CAP)],
                )
                .into_owned(),
                body_len: full_body.len(),
                timestamp: chrono::Utc::now(),
            };
            let rx = self.intercept.enqueue(entry);
            let (status, headers, body) = match InterceptController::wait_for_decision(rx).await {
                InterceptDecision::Drop => return dropped_response(),
                InterceptDecision::Forward(edit) => {
                    let mut status = response_parts.status;
                    let mut headers = response_headers;
                    let mut body = full_body;
                    if let Some(edit) = edit {
                        if let Ok(edit_status) =
                            http::StatusCode::from_u16(edit.status.unwrap_or(status.as_u16()))
                        {
                            status = edit_status;
                        }
                        headers = headers_from_intercept(&edit.headers);
                        body = Bytes::from(edit.body.into_bytes());
                    }
                    headers.remove("content-length");
                    headers.remove("transfer-encoding");
                    (status, headers, body)
                }
            };

            if capture {
                spawn_capture(
                    self.session.clone(),
                    self.session_id_source.clone(),
                    self.sink.clone(),
                    self.config.max_body_bytes,
                    build_ctx(
                        start_instant,
                        &method_from_str(method.as_str()),
                        &host,
                        client_ip,
                        &scheme,
                        &path,
                        &request_headers,
                        &capture_request_body,
                        status.as_u16(),
                        &headers,
                    ),
                    body.to_vec(),
                );
            }

            let mut response_builder = Response::builder().status(status);
            for (name, value) in &headers {
                if !is_hop_by_hop(name.as_str()) {
                    response_builder = response_builder.header(name, value);
                }
            }
            let client_response = response_builder
                .body(BoxBody::new(Full::new(body)))
                .map_err(|error| ProxyError::Runtime(error.to_string()))?;
            return Ok(client_response);
        }

        let ctx = if capture {
            Some(build_ctx(
                start_instant,
                &method_from_str(method.as_str()),
                &host,
                client_ip,
                &scheme,
                &path,
                &request_headers,
                &capture_request_body,
                response_parts.status.as_u16(),
                &response_parts.headers,
            ))
        } else {
            None
        };

        let expected = response_parts
            .headers
            .get("content-length")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok());

        let mut response_builder = Response::builder().status(response_parts.status);
        for (name, value) in &response_headers {
            if !is_hop_by_hop(name.as_str()) {
                response_builder = response_builder.header(name, value);
            }
        }
        let client_response = response_builder
            .body(BoxBody::new(TeeBody::new(
                response_body,
                self.config.max_body_bytes,
                expected,
                self.sink.clone(),
                self.session.clone(),
                self.session_id_source.clone(),
                ctx,
            )))
            .map_err(|error| ProxyError::Runtime(error.to_string()))?;

        Ok(client_response)
    }

    fn serve_crl(&self) -> Result<Response<RelayBody>, ProxyError> {
        let crl = self.cert.ca_crl_der()?;
        Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "application/pkix-crl")
            .body(BoxBody::new(Full::new(Bytes::from(crl))))
            .map_err(|error| ProxyError::Runtime(error.to_string()))
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

/// Serves an HTTP/1 connection and finishes the in-flight request before
/// closing when the proxy shutdown signal fires (graceful drain).
async fn serve_with_graceful_shutdown<I, S>(io: I, service: S, mut shutdown: watch::Receiver<bool>)
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    S: hyper::service::Service<
            Request<Incoming>,
            Response = Response<RelayBody>,
            Error = Infallible,
        > + Send
        + 'static,
{
    let conn =
        hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(io), service);
    tokio::pin!(conn);
    tokio::select! {
        _ = conn.as_mut() => {}
        _ = shutdown.changed() => {
            conn.as_mut().graceful_shutdown();
            let _ = conn.await;
        }
    }
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

/// Collects a body into memory up to `max` bytes. Returns the bytes and
/// whether the body was truncated at the cap. The `Content-Length` header
/// must be rewritten by the caller when truncation occurs, otherwise the
/// peer waits for bytes that will never arrive.
async fn collect_body(body: &mut Incoming, max: usize) -> Result<(Bytes, bool), ProxyError> {
    let mut collected = Vec::new();
    let mut truncated = false;
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|error| ProxyError::Runtime(error.to_string()))?;
        if let Ok(data) = frame.into_data() {
            if collected.len().saturating_add(data.len()) > max {
                let remaining = max.saturating_sub(collected.len());
                collected.extend_from_slice(&data[..remaining]);
                truncated = true;
                break;
            }
            collected.extend_from_slice(&data);
        }
    }
    Ok((Bytes::from(collected), truncated))
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
        other => HttpMethod::Other(other.to_owned()),
    }
}

fn error_response(status: StatusCode) -> Response<RelayBody> {
    Response::builder()
        .status(status)
        .body(BoxBody::new(Full::new(Bytes::new())))
        .unwrap_or_else(|_| {
            Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(BoxBody::new(Full::new(Bytes::new())))
                .unwrap()
        })
}

/// Response returned when an intercepted item is dropped: an empty 200 with
/// `Connection: close` so the client sees the connection shut down.
fn dropped_response() -> Result<Response<RelayBody>, ProxyError> {
    Response::builder()
        .status(StatusCode::OK)
        .header("connection", "close")
        .header("content-length", "0")
        .body(BoxBody::new(Full::new(Bytes::new())))
        .map_err(|error| ProxyError::Runtime(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::TunnelErrorReporter;

    #[test]
    fn identical_repeat_is_suppressed_within_cooldown() {
        let mut reporter = TunnelErrorReporter::new();
        let message = "tunnel connect failed for ic.tynt.com:443: refused";
        assert!(
            reporter.should_report(message),
            "first occurrence must be reported"
        );
        assert!(
            !reporter.should_report(message),
            "immediate repeat must be suppressed"
        );
        assert!(!reporter.should_report(message), "still within cooldown");
    }

    #[test]
    fn distinct_failures_are_reported_independently() {
        let mut reporter = TunnelErrorReporter::new();
        assert!(reporter.should_report("tunnel connect failed for host-a:443: refused"));
        assert!(reporter.should_report("tunnel connect failed for host-b:443: refused"));
    }
}
