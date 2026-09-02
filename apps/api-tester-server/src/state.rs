use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use api_tester_capture::RingBuffer;
use api_tester_domain::{AppConfig, HttpFlow};
use api_tester_events::EventBus;
use api_tester_proxy::{InterceptController, ProxyServer};
use api_tester_storage::SqliteStore;
use tokio::runtime::Handle;
use tokio_util::sync::CancellationToken;

use crate::http_client::ReqwestHttpClient;

pub fn home_dir() -> PathBuf {
    std::env::var_os("USERPROFILE")
        .or_else(|| std::env::var_os("HOME"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
}

pub fn data_dir() -> PathBuf {
    home_dir().join(".api-tester")
}

pub fn certs_dir() -> PathBuf {
    data_dir().join("certs")
}

pub fn database_path() -> PathBuf {
    data_dir().join("api-tester.db")
}

/// Shared state managed by the app. All async backend work runs on a dedicated
/// background tokio runtime so the HTTP/UI thread never blocks and the proxy's
/// tokio primitives (net/time) are available regardless of the server runtime.
pub struct AppState {
    pub config: std::sync::RwLock<AppConfig>,
    pub config_path: PathBuf,
    pub buffer: Arc<RingBuffer<HttpFlow>>,
    pub store: Arc<tokio::sync::Mutex<Option<SqliteStore>>>,
    pub runtime: Handle,
    pub http: Arc<ReqwestHttpClient>,
    pub proxy: tokio::sync::Mutex<Option<Arc<ProxyServer>>>,
    pub proxy_running: Arc<AtomicBool>,
    pub events: Arc<EventBus>,
    pub intercept: Arc<InterceptController>,
    /// Most recent proxy request error, surfaced to the UI.
    pub last_error: Arc<std::sync::Mutex<Option<String>>>,
    /// Real-time event bus pushed over the WebSocket to the browser UI.
    pub ws_tx: Arc<tokio::sync::broadcast::Sender<String>>,
    /// Cancellation tokens for running workflow executions, keyed by run id.
    /// Currently active capture session (set by /api/sessions/start).
    pub active_session_id: Arc<tokio::sync::Mutex<Option<String>>>,
    pub workflow_tokens:
        Arc<std::sync::Mutex<std::collections::HashMap<String, CancellationToken>>>,
    /// Pending security confirmation senders keyed by run_id.
    /// Each entry contains a map of test_id -> oneshot::Sender<ConfirmationResponse>.
    pub security_confirmations: Arc<std::sync::Mutex<
        std::collections::HashMap<String, Arc<tokio::sync::Mutex<
            std::collections::HashMap<String, tokio::sync::oneshot::Sender<api_tester_security::ConfirmationResponse>>
        >>>
    >>,
}

impl AppState {
    pub fn new(config: AppConfig) -> Result<Self, String> {
        // Fixed-size worker pool (not num_cpus) keeps threads/overhead down.
        // 4 workers handle the async proxy + SQLite + repeater today and leave
        // headroom for the planned Intruder engine; raise if scans need more.
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4)
            .enable_all()
            .build()
            .map_err(|error| error.to_string())?;
        let handle = runtime.handle().clone();
        std::thread::spawn(move || {
            runtime.block_on(std::future::pending::<()>());
        });

        let http = Arc::new(ReqwestHttpClient::new()?);
        let _ = std::fs::create_dir_all(data_dir());
        let (ws_tx, _) = tokio::sync::broadcast::channel::<String>(256);

        Ok(Self {
            config: std::sync::RwLock::new(config),
            config_path: data_dir().join("config.json"),
            buffer: Arc::new(RingBuffer::new(5_000)),
            store: Arc::new(tokio::sync::Mutex::new(None)),
            runtime: handle,
            http,
            proxy: tokio::sync::Mutex::new(None),
            proxy_running: Arc::new(AtomicBool::new(false)),
            events: Arc::new(EventBus::new(256)),
            intercept: Arc::new(InterceptController::default()),
            last_error: Arc::new(std::sync::Mutex::new(None)),
            ws_tx: Arc::new(ws_tx),
            active_session_id: Arc::new(tokio::sync::Mutex::new(None)),
            workflow_tokens: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
            security_confirmations: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
        })
    }

    /// Opens the SQLite store once, lazily.
    pub async fn store(&self) -> Option<SqliteStore> {
        open_store(&self.store).await
    }

    /// Broadcasts a JSON message to every WebSocket client (the browser UI).
    pub fn ws_send(&self, message: &serde_json::Value) {
        if let Ok(text) = serde_json::to_string(message) {
            let _ = self.ws_tx.send(text);
        }
    }
}

/// Opens the SQLite store lazily (shared with the proxy sink and the command
/// layer). The single connection is cached in `AppState::store`. Open failures
/// are logged and remembered in `last_storage_error` so the proxy start path
/// can surface the real cause instead of a bare "storage unavailable".
pub async fn open_store(
    store: &Arc<tokio::sync::Mutex<Option<SqliteStore>>>,
) -> Option<SqliteStore> {
    let mut guard = store.lock().await;
    if guard.is_none() {
        let path = database_path();
        let _ = std::fs::create_dir_all(data_dir());
        match SqliteStore::open(path.to_str().unwrap_or(":memory:")).await {
            Ok(opened) => {
                *LAST_STORAGE_ERROR.lock().await = None;
                *guard = Some(opened);
            }
            Err(error) => {
                let message = error.to_string();
                eprintln!("[storage] open failed for {}: {message}", path.display());
                *LAST_STORAGE_ERROR.lock().await = Some(message);
            }
        }
    }
    guard.clone()
}

/// Last storage open failure, shared process-wide (set by [`open_store`]).
static LAST_STORAGE_ERROR: tokio::sync::Mutex<Option<String>> = tokio::sync::Mutex::const_new(None);

pub async fn last_storage_error() -> Option<String> {
    LAST_STORAGE_ERROR.lock().await.clone()
}

pub async fn clear_storage_error() {
    *LAST_STORAGE_ERROR.lock().await = None;
}

/// Drops the cached store so the next `open_store` reopens SQLite from
/// scratch. Used after readonly/lock failures: reopening runs WAL recovery
/// and rebuilds a healthy pool instead of reusing the poisoned one.
pub async fn reset_store(store: &Arc<tokio::sync::Mutex<Option<SqliteStore>>>) {
    *store.lock().await = None;
}
