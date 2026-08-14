use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use api_tester_domain::{DomainEvent, HttpFlow, HttpMethod, ScanJob, ScopeConfig, Session};
use api_tester_ports::{
    FlowRepository, HttpClient, HttpRequest, HttpResponse, PortError, ScanExecutor,
};
use api_tester_scanner::{
    BuiltinPayloadSource, MutationEngine, PayloadSource, Replayer, RequestExecutor,
    ResponseVerifier, ScanScheduler, StopReason, TokioScanExecutor,
};
use api_tester_test_support::{InMemoryFlowRepository, MockHttpClient, RecordingEventPublisher};
use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;
use url::Url;

fn build_scheduler(client: Arc<dyn HttpClient>) -> Arc<ScanScheduler> {
    let source: Arc<dyn PayloadSource> = Arc::new(BuiltinPayloadSource);
    let mutation = Arc::new(MutationEngine::new(source, 20));
    let executor = Arc::new(RequestExecutor::new(client, 0, 30));
    Arc::new(ScanScheduler::new(
        executor,
        mutation,
        Arc::new(ResponseVerifier),
    ))
}

fn make_job(budget: u64, concurrency: u32, host_pattern: &str) -> ScanJob {
    let mut job = ScanJob::new(budget, concurrency).unwrap();
    job.config.scope = ScopeConfig {
        include_hosts: vec![host_pattern.to_owned()],
        ..ScopeConfig::default()
    };
    job.config.enabled_skills = vec!["sqli".to_owned()];
    job
}

fn flow(url: &str) -> HttpFlow {
    let parsed = Url::parse(url).unwrap();
    let mut flow = HttpFlow::new(
        HttpMethod::Get,
        parsed.host_str().unwrap_or_default(),
        parsed.path(),
    );
    flow.full_url = url.to_owned();
    flow.response_status = 200;
    flow
}

/// A real local HTTP target that echoes the first decoded query value (or the
/// body) so reflection detection works end-to-end.
struct MockTarget {
    port: u16,
    requests: Arc<Mutex<Vec<RecordedRequest>>>,
}

#[derive(Clone)]
struct RecordedRequest {
    method: String,
    target: String,
}

impl MockTarget {
    async fn start() -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let requests = Arc::new(Mutex::new(Vec::new()));
        tokio::spawn({
            let requests = requests.clone();
            async move {
                loop {
                    let Ok((socket, _)) = listener.accept().await else {
                        break;
                    };
                    let requests = requests.clone();
                    tokio::spawn(async move {
                        let _ = serve(socket, requests).await;
                    });
                }
            }
        });
        Self { port, requests }
    }

    fn url(&self, path: &str) -> String {
        format!("http://127.0.0.1:{port}{path}", port = self.port)
    }

    fn requests(&self) -> Vec<RecordedRequest> {
        self.requests
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .clone()
    }
}

async fn serve(
    mut socket: TcpStream,
    requests: Arc<Mutex<Vec<RecordedRequest>>>,
) -> std::io::Result<()> {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 2048];
    loop {
        let n = socket.read(&mut chunk).await?;
        if n == 0 {
            return Ok(());
        }
        buffer.extend_from_slice(&chunk[..n]);
        if buffer.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
    }
    let head_end = buffer
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .unwrap();
    let head = String::from_utf8_lossy(&buffer[..head_end]).into_owned();
    let mut lines = head.split("\r\n");
    let request_line = lines.next().unwrap_or_default();
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default().to_owned();
    let target = parts.next().unwrap_or_default().to_owned();

    let mut content_length = 0usize;
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            if name.eq_ignore_ascii_case("content-length") {
                content_length = value.trim().parse().unwrap_or(0);
            }
        }
    }
    while buffer.len() < head_end + 4 + content_length {
        let n = socket.read(&mut chunk).await?;
        if n == 0 {
            break;
        }
        buffer.extend_from_slice(&chunk[..n]);
    }
    let body = buffer[head_end + 4..(head_end + 4 + content_length).min(buffer.len())].to_vec();

    requests
        .lock()
        .unwrap_or_else(|poison| poison.into_inner())
        .push(RecordedRequest {
            method,
            target: target.clone(),
        });

    let echo = echo_of(&target, &body);
    let json = format!(r#"{{"echo":{echo},"path":"{}"}}"#, target.replace('"', ""));
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        json.len(),
        json
    );
    let _ = socket.write_all(response.as_bytes()).await;
    Ok(())
}

fn echo_of(target: &str, body: &[u8]) -> String {
    if let Some(query) = target.split_once('?').map(|(_, query)| query) {
        let pairs: Vec<(String, String)> = url::form_urlencoded::parse(query.as_bytes())
            .into_owned()
            .collect();
        if let Some((_, value)) = pairs.first() {
            return serde_json::to_string(value).unwrap_or_default();
        }
    }
    let text = String::from_utf8_lossy(body);
    serde_json::to_string(&text).unwrap_or_default()
}

/// A minimal real HTTP/1.1 client used to reach the local mock target.
struct RawTcpClient;

#[async_trait]
impl HttpClient for RawTcpClient {
    async fn send(&self, request: HttpRequest) -> Result<HttpResponse, PortError> {
        let url = Url::parse(&request.url).map_err(|e| PortError::Permanent(e.to_string()))?;
        let host = url
            .host_str()
            .ok_or_else(|| PortError::Permanent("no host in url".to_owned()))?
            .to_owned();
        let port = url.port_or_known_default().unwrap_or(80);
        let path = match url.query() {
            Some(query) => format!("{}?{query}", url.path()),
            None => url.path().to_owned(),
        };

        let mut stream = TcpStream::connect((host.as_str(), port))
            .await
            .map_err(|e| PortError::Transient(e.to_string()))?;
        let headers: String = request
            .headers
            .iter()
            .map(|(name, value)| format!("{name}: {value}\r\n"))
            .collect();
        let body = request.body.unwrap_or_default();
        let head = format!(
            "{} {path} HTTP/1.1\r\nHost: {host}\r\n{headers}Content-Length: {}\r\nConnection: close\r\n\r\n",
            request.method,
            body.len()
        );
        stream
            .write_all(head.as_bytes())
            .await
            .map_err(|e| PortError::Transient(e.to_string()))?;
        stream
            .write_all(&body)
            .await
            .map_err(|e| PortError::Transient(e.to_string()))?;

        let mut buffer = Vec::new();
        let mut chunk = [0u8; 2048];
        loop {
            match stream.read(&mut chunk).await {
                Ok(0) => break,
                Ok(n) => buffer.extend_from_slice(&chunk[..n]),
                Err(_) => break,
            }
        }
        let text = String::from_utf8_lossy(&buffer);
        let status = text
            .split_whitespace()
            .nth(1)
            .and_then(|value| value.parse::<u16>().ok())
            .unwrap_or(0);
        let body = match buffer.windows(4).position(|window| window == b"\r\n\r\n") {
            Some(end) => buffer[end + 4..].to_vec(),
            None => buffer,
        };
        Ok(HttpResponse {
            status,
            headers: Vec::new(),
            body,
        })
    }
}

/// A client that sleeps so concurrency and cancellation can be measured.
struct SlowClient {
    delay: Duration,
    inflight: Arc<AtomicUsize>,
    peak: Arc<AtomicUsize>,
}

#[async_trait]
impl HttpClient for SlowClient {
    async fn send(&self, _request: HttpRequest) -> Result<HttpResponse, PortError> {
        let current = self.inflight.fetch_add(1, AtomicOrdering::SeqCst) + 1;
        self.peak.fetch_max(current, AtomicOrdering::SeqCst);
        tokio::time::sleep(self.delay).await;
        self.inflight.fetch_sub(1, AtomicOrdering::SeqCst);
        Ok(HttpResponse {
            status: 200,
            headers: Vec::new(),
            body: b"{}".to_vec(),
        })
    }
}

/// A client that records the URLs it is asked to send.
struct RecordingClient {
    urls: Arc<Mutex<Vec<String>>>,
}

#[async_trait]
impl HttpClient for RecordingClient {
    async fn send(&self, request: HttpRequest) -> Result<HttpResponse, PortError> {
        self.urls
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .push(request.url);
        Ok(HttpResponse {
            status: 200,
            headers: Vec::new(),
            body: b"{}".to_vec(),
        })
    }
}

fn sqli_flow_url(base: &str) -> String {
    format!("{base}/api/search?q=value&id=7")
}

#[tokio::test]
async fn mutation_scan_reaches_mock_target_and_detects_reflection() {
    let mock = MockTarget::start().await;
    let scheduler = build_scheduler(Arc::new(RawTcpClient));
    let job = make_job(10_000, 4, r"127\.0\.0\.1");

    let result = scheduler
        .run(
            &[flow(&sqli_flow_url(&mock.url("")))],
            &job,
            CancellationToken::new(),
        )
        .await
        .unwrap();

    assert_eq!(result.stop_reason, StopReason::Completed);
    assert!(result.mutations_planned > 0);
    assert_eq!(result.requests_sent, result.mutations_planned as u64);
    assert!(
        !result.findings.is_empty(),
        "sqli reflection should be detected"
    );
    let requests = mock.requests();
    assert!(!requests.is_empty());
    assert!(requests.iter().all(|request| request.method == "GET"));
}

#[tokio::test]
async fn replay_orders_flows_by_dependency() {
    let mock = MockTarget::start().await;
    let client: Arc<dyn HttpClient> = Arc::new(RawTcpClient);
    let executor = Arc::new(RequestExecutor::new(client, 0, 30));
    let replayer = Replayer::new(executor, None);

    let login = flow(&mock.url("/api/login"));
    let profile = flow(&mock.url("/api/profile"));
    let outcomes = replayer
        .replay(vec![profile.clone(), login.clone()])
        .await
        .unwrap();

    assert_eq!(outcomes.len(), 2);
    assert_eq!(outcomes[0].path, "/api/login");
    assert_eq!(outcomes[1].path, "/api/profile");
    assert!(outcomes.iter().all(|outcome| outcome.ok));
    let requests = mock.requests();
    assert_eq!(requests.len(), 2);
    assert!(requests[0].target.contains("/api/login"));
    assert!(requests[1].target.contains("/api/profile"));
}

#[tokio::test]
async fn concurrency_is_bounded_by_max_concurrency() {
    let slow = Arc::new(SlowClient {
        delay: Duration::from_millis(30),
        inflight: Arc::new(AtomicUsize::new(0)),
        peak: Arc::new(AtomicUsize::new(0)),
    });
    let scheduler = build_scheduler(slow.clone());
    let job = make_job(10_000, 3, r"127\.0\.0\.1");
    let url = "http://127.0.0.1/api/x?q=value&id=7";

    let started = std::time::Instant::now();
    let result = scheduler
        .run(&[flow(url)], &job, CancellationToken::new())
        .await
        .unwrap();
    let elapsed = started.elapsed();

    assert_eq!(result.requests_sent, result.mutations_planned as u64);
    let peak = slow.peak.load(AtomicOrdering::SeqCst);
    assert!(peak <= 3, "peak concurrency {peak} exceeded limit");
    assert!(peak >= 2, "expected some parallelism, got {peak}");
    assert!(
        elapsed < Duration::from_millis(300),
        "too serial: {elapsed:?}"
    );
}

#[tokio::test]
async fn per_host_rate_limit_paces_requests() {
    let scheduler = build_scheduler(Arc::new(MockHttpClient::default()));
    let mut job = make_job(10_000, 4, r"127\.0\.0\.1");
    job.config.per_host_requests_per_sec = 15;
    let urls: Vec<String> = (0..3)
        .map(|i| format!("http://127.0.0.1/api/item_{i}?q=value&id=7"))
        .collect();
    let flows: Vec<HttpFlow> = urls.iter().map(|url| flow(url)).collect();

    let started = std::time::Instant::now();
    let result = scheduler
        .run(&flows, &job, CancellationToken::new())
        .await
        .unwrap();
    let elapsed = started.elapsed();

    assert_eq!(result.requests_sent, 36, "all mutations should be sent");
    assert!(
        elapsed >= Duration::from_millis(1200),
        "rate limit should pace requests, took {elapsed:?}"
    );
}

#[tokio::test]
async fn cancellation_stops_promptly() {
    let slow = Arc::new(SlowClient {
        delay: Duration::from_millis(50),
        inflight: Arc::new(AtomicUsize::new(0)),
        peak: Arc::new(AtomicUsize::new(0)),
    });
    let scheduler = build_scheduler(slow);
    let job = make_job(10_000, 2, r"127\.0\.0\.1");
    let url = "http://127.0.0.1/api/x?q=value&id=7";
    let cancel = CancellationToken::new();
    let cancel_task = cancel.clone();

    let scheduler = scheduler.clone();
    let flows = vec![flow(url)];
    let handle =
        tokio::spawn(async move { scheduler.run(&flows, &job, cancel_task).await.unwrap() });
    tokio::time::sleep(Duration::from_millis(120)).await;
    cancel.cancel();
    let result = handle.await.unwrap();

    assert_eq!(result.stop_reason, StopReason::Cancelled);
    assert!(result.requests_sent < result.mutations_planned as u64);
}

#[tokio::test]
async fn request_budget_stops_the_scan() {
    let scheduler = build_scheduler(Arc::new(MockHttpClient::default()));
    let job = make_job(5, 4, r"127\.0\.0\.1");
    let url = "http://127.0.0.1/api/x?q=value&id=7";

    let result = scheduler
        .run(&[flow(url)], &job, CancellationToken::new())
        .await
        .unwrap();

    assert_eq!(result.stop_reason, StopReason::BudgetExhausted);
    assert_eq!(result.requests_sent, 5);
    assert!(result.mutations_planned > 5);
}

#[tokio::test]
async fn scope_violation_stops_before_sending() {
    let scheduler = build_scheduler(Arc::new(MockHttpClient::default()));
    let job = make_job(10_000, 2, r"other\.example");
    let url = "http://127.0.0.1/api/x?q=value&id=7";

    let result = scheduler
        .run(&[flow(url)], &job, CancellationToken::new())
        .await
        .unwrap();

    assert_eq!(result.stop_reason, StopReason::ScopeViolation);
    assert_eq!(result.requests_sent, 0);
}

#[tokio::test]
async fn dry_run_never_sends_requests() {
    let recording = Arc::new(RecordingClient {
        urls: Arc::new(Mutex::new(Vec::new())),
    });
    let scheduler = build_scheduler(recording.clone());
    let mut job = make_job(10_000, 2, r"127\.0\.0\.1");
    job.config.dry_run = true;
    let url = "http://127.0.0.1/api/x?q=value&id=7";

    let result = scheduler
        .run(&[flow(url)], &job, CancellationToken::new())
        .await
        .unwrap();

    assert_eq!(result.stop_reason, StopReason::Completed);
    assert_eq!(result.requests_sent, 0);
    assert!(result.mutations_planned > 0);
    assert!(recording.urls.lock().unwrap().is_empty());
}

#[tokio::test]
async fn same_seed_produces_same_order() {
    async fn run_order(seed: u64) -> Vec<String> {
        let client = Arc::new(RecordingClient {
            urls: Arc::new(Mutex::new(Vec::new())),
        });
        let scheduler = build_scheduler(client.clone());
        let mut job = make_job(10_000, 1, r"127\.0\.0\.1");
        job.seed = Some(seed);
        let urls: Vec<String> = (0..2)
            .map(|i| format!("http://127.0.0.1/api/item_{i}?q=value&id=7"))
            .collect();
        let flows: Vec<HttpFlow> = urls.iter().map(|url| flow(url)).collect();
        let result = scheduler
            .run(&flows, &job, CancellationToken::new())
            .await
            .unwrap();
        assert_eq!(result.requests_sent, 24);
        client.urls.lock().unwrap().clone()
    }

    let first = run_order(42).await;
    let second = run_order(42).await;
    assert_eq!(
        first, second,
        "same seed must produce identical execution order"
    );
}

#[tokio::test]
async fn allowlist_is_required() {
    let scheduler = build_scheduler(Arc::new(MockHttpClient::default()));
    let mut job = make_job(10_000, 2, r"127\.0\.0\.1");
    job.config.scope = ScopeConfig::default();
    let url = "http://127.0.0.1/api/x?q=value&id=7";

    let result = scheduler
        .run(&[flow(url)], &job, CancellationToken::new())
        .await;
    assert!(matches!(
        result,
        Err(api_tester_scanner::ScanError::NoTargetsAllowed)
    ));
}

#[tokio::test]
async fn scan_executor_submits_and_publishes_event() {
    let mock = MockTarget::start().await;
    let repository = Arc::new(InMemoryFlowRepository::default());
    let session = Session::default();
    let mut captured = flow(&sqli_flow_url(&mock.url("")));
    captured.session_id = session.id.clone();
    repository.save(&captured).await.unwrap();

    let scheduler = build_scheduler(Arc::new(RawTcpClient));
    let events = Arc::new(RecordingEventPublisher::default());
    let executor = TokioScanExecutor::new(repository, scheduler, Some(events.clone()));

    let mut job = make_job(10_000, 2, r"127\.0\.0\.1");
    job.session_id = Some(session.id.clone());
    let job_id = executor.submit(job).await.unwrap();
    assert!(!job_id.is_empty());

    tokio::time::sleep(Duration::from_millis(400)).await;
    assert!(
        events
            .events()
            .iter()
            .any(|event| matches!(event, DomainEvent::ScanCompleted { .. })),
        "expected a ScanCompleted event"
    );
    let _ = executor.cancel(&job_id).await;
}

#[tokio::test]
async fn dedup_skips_identical_requests() {
    let recording = Arc::new(RecordingClient {
        urls: Arc::new(Mutex::new(Vec::new())),
    });
    let scheduler = build_scheduler(recording.clone());
    let job = make_job(10_000, 1, r"127\.0\.0\.1");

    // Two flows with identical method+url+body produce identical mutations.
    let url = "http://127.0.0.1/api/x?q=value&id=7";
    let flows = vec![flow(url), flow(url)];
    let result = scheduler
        .run(&flows, &job, CancellationToken::new())
        .await
        .unwrap();

    let recorded = recording.urls.lock().unwrap().clone();
    assert_eq!(result.requests_sent as usize, recorded.len());
    assert!(
        recorded.len() < result.mutations_planned,
        "dedup should drop duplicate mutations"
    );
}

#[tokio::test]
async fn many_mutations_without_rate_limit_complete() {
    let scheduler = build_scheduler(Arc::new(MockHttpClient::default()));
    let job = make_job(10_000, 4, r"127\.0\.0\.1");
    let urls: Vec<String> = (0..3)
        .map(|i| format!("http://127.0.0.1/api/item_{i}?q=value&id=7"))
        .collect();
    let flows: Vec<HttpFlow> = urls.iter().map(|url| flow(url)).collect();
    let result = scheduler
        .run(&flows, &job, CancellationToken::new())
        .await
        .unwrap();
    assert_eq!(result.requests_sent, 36);
}
