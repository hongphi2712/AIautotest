//! Application logic as `AppState` methods (ex-Tauri commands). The axum
//! routes layer calls these directly; there is no IPC/serde boundary anymore.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use api_tester_domain::Session;
use api_tester_ports::{FlowRepository, HttpClient, HttpRequest, SessionRepository};
use api_tester_proxy::{
    CertProvider, InterceptEdit, InterceptEntry, MatchReplaceEngine, ProxyServer,
    RcgenCertProvider, ScopeFilter, UpstreamClient,
};
use serde_json::json;

use crate::dashboard::DashboardSink;
use crate::serialization::{
    CertInfo, FlowDetail, FlowFilters, FlowSummary, ProxyStatus, RepeaterRequest, RepeaterResponse,
    SessionSummary, filter_flows,
};
use crate::state::{AppState, certs_dir, open_store};

impl AppState {
    pub async fn app_health(&self) -> Result<serde_json::Value, String> {
        // Consume `last_error` so the UI banner shows a diagnostic once instead
        // of sticking permanently (proxy errors are throttled server-side).
        let last_error = self
            .last_error
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .take();
        // Fast count (SQL COUNT + buffer length) instead of materializing the
        // full `list_recent` window on the 2s health poll.
        let flows = persisted_flow_count(self)
            .await
            .max(self.buffer.len() as u64) as usize;
        Ok(json!({
            "status": "ok",
            "proxy_running": self.proxy_running.load(Ordering::SeqCst),
            "flows": flows,
            "last_error": last_error,
        }))
    }

    pub async fn list_flows(&self, filters: &FlowFilters) -> Result<Vec<FlowSummary>, String> {
        let flows = all_flows(self).await;
        Ok(filter_flows(flows, filters)
            .iter()
            .map(FlowSummary::from)
            .collect())
    }

    pub async fn flow_detail(&self, flow_id: &str) -> Result<FlowDetail, String> {
        let flow = flow_by_id(self, flow_id)
            .await
            .ok_or_else(|| format!("flow {flow_id} not found"))?;
        Ok(FlowDetail::from(&flow))
    }

    pub async fn list_sessions(&self) -> Result<Vec<SessionSummary>, String> {
        let sessions = persisted_sessions(self).await;
        Ok(sessions
            .into_iter()
            .map(|session| SessionSummary {
                id: session.id,
                name: session.name,
                target_host: session.target_host,
                start_time: session.start_time,
                end_time: session.end_time,
                flow_count: session.flow_count,
            })
            .collect())
    }

    pub async fn repeater_send(
        &self,
        request: RepeaterRequest,
    ) -> Result<RepeaterResponse, String> {
        let http = self.http.clone();
        let request = HttpRequest {
            method: request.method,
            url: request.url,
            headers: request.headers.into_iter().collect(),
            body: Some(request.body.into_bytes()),
        };
        let sent = self
            .runtime
            .spawn(async move {
                tokio::time::timeout(Duration::from_secs(30), http.send(request)).await
            })
            .await
            .map_err(|error| error.to_string())?
            .map_err(|error| error.to_string())?
            .map_err(|error| error.to_string())?;
        Ok(RepeaterResponse {
            status: sent.status,
            length: sent.body.len(),
            body: String::from_utf8_lossy(&sent.body).into_owned(),
            headers: sent.headers,
        })
    }

    pub async fn start_proxy(&self) -> Result<ProxyStatus, String> {
        ensure_proxy_running(self).await?;
        Ok(self.proxy_status())
    }

    pub async fn stop_proxy(&self) -> Result<ProxyStatus, String> {
        if let Some(proxy) = self.proxy.lock().await.take() {
            self.runtime
                .spawn(async move { proxy.stop().await })
                .await
                .map_err(|error| error.to_string())?
                .map_err(|error| error.to_string())?;
        }
        self.proxy_running.store(false, Ordering::SeqCst);
        Ok(self.proxy_status())
    }

    pub fn proxy_status(&self) -> ProxyStatus {
        ProxyStatus {
            running: self.proxy_running.load(Ordering::SeqCst),
            host: self.config.proxy.host.clone(),
            port: self.config.proxy.port,
            address: format!("{}:{}", self.config.proxy.host, self.config.proxy.port),
            error: None,
        }
    }

    pub fn cert_info(&self) -> CertInfo {
        let path = ca_path(self);
        CertInfo {
            path: path.display().to_string(),
            exists: path.exists(),
            installed: ca_installed(&path),
        }
    }

    pub fn install_ca(&self) -> Result<CertInfo, String> {
        let path = ca_path(self);
        if !path.exists() {
            return Err("CA not generated yet — start the proxy first".to_owned());
        }
        install_ca_win(&path)?;
        Ok(CertInfo {
            path: path.display().to_string(),
            exists: true,
            installed: true,
        })
    }

    pub async fn open_browser(&self) -> Result<(), String> {
        ensure_proxy_running(self).await?;

        let ca = ca_path(self);
        if ca.exists() && !ca_installed(&ca) {
            let _ = install_ca_win(&ca);
        }

        let host = &self.config.proxy.host;
        let port = self.config.proxy.port;
        let home = std::env::var_os("USERPROFILE")
            .or_else(|| std::env::var_os("HOME"))
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| std::path::PathBuf::from("."));
        let profile_dir = home.join(".api-tester").join("chrome-profile");
        std::fs::create_dir_all(&profile_dir).ok();

        let proxy_arg = format!("--proxy-server=http={host}:{port};https={host}:{port}");
        let args = [
            proxy_arg,
            format!("--user-data-dir={}", profile_dir.display()),
            "--no-first-run".into(),
            "--no-default-browser-check".into(),
            "--disable-quic".into(),
        ];

        let chrome_paths = [
            r"C:\Program Files\Google\Chrome\Application\chrome.exe",
            r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
            r"C:\Users\gtvbe\AppData\Local\Google\Chrome\Application\chrome.exe",
            #[cfg(target_os = "linux")]
            "/usr/bin/google-chrome",
            #[cfg(target_os = "linux")]
            "/usr/bin/chromium-browser",
            #[cfg(target_os = "linux")]
            "/usr/bin/chromium",
            #[cfg(target_os = "macos")]
            "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
        ];
        for path in &chrome_paths {
            if std::path::Path::new(path).exists() {
                let _ = std::process::Command::new(path).args(&args).spawn();
                return Ok(());
            }
        }

        let edge_paths = [
            r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
            r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
        ];
        for path in &edge_paths {
            if std::path::Path::new(path).exists() {
                let _ = std::process::Command::new(path).args(&args).spawn();
                return Ok(());
            }
        }

        let _ = open::that("https://example.com");
        Ok(())
    }

    pub fn intercept_set_enabled(&self, enabled: bool) -> Result<(), String> {
        self.intercept.set_enabled(enabled);
        Ok(())
    }

    pub fn intercept_set_scopes(
        &self,
        intercept_requests: bool,
        intercept_responses: bool,
    ) -> Result<(), String> {
        self.intercept.set_intercept_requests(intercept_requests);
        self.intercept.set_intercept_responses(intercept_responses);
        Ok(())
    }

    pub fn intercept_status(&self) -> Result<serde_json::Value, String> {
        Ok(json!({
            "enabled": self.intercept.is_enabled(),
            "intercept_requests": self.intercept.intercept_requests_enabled(),
            "intercept_responses": self.intercept.intercept_responses_enabled(),
            "held": self.intercept.len(),
        }))
    }

    pub fn intercept_list(&self) -> Result<Vec<InterceptEntry>, String> {
        Ok(self.intercept.list())
    }

    pub fn intercept_detail(&self, id: &str) -> Result<Option<InterceptEntry>, String> {
        Ok(self.intercept.get(id))
    }

    pub fn intercept_forward(&self, id: &str, edit: Option<InterceptEdit>) -> Result<bool, String> {
        Ok(self.intercept.forward(id, edit))
    }

    pub fn intercept_drop(&self, id: &str) -> Result<bool, String> {
        Ok(self.intercept.drop_item(id))
    }

    pub fn intercept_clear(&self) -> Result<(), String> {
        self.intercept.clear_all();
        Ok(())
    }
}

/// Starts the proxy if it is not already running.
async fn ensure_proxy_running(state: &AppState) -> Result<(), String> {
    if state.proxy_running.load(Ordering::SeqCst) {
        return Ok(());
    }
    let proxy = build_proxy(state).await?;
    state
        .runtime
        .spawn({
            let proxy = proxy.clone();
            async move { proxy.start().await }
        })
        .await
        .map_err(|error| error.to_string())?
        .map_err(|error| error.to_string())?;
    *state.proxy.lock().await = Some(proxy);
    state.proxy_running.store(true, Ordering::SeqCst);
    Ok(())
}

/// Merges persisted SQLite history (summary rows only) with the live in-memory
/// buffer (also summary-only), newest first. Never ships request/response
/// bodies over the poll; `flow_detail` loads the full flow on demand.
async fn all_flows(state: &AppState) -> Vec<api_tester_domain::HttpFlow> {
    let buffer = state.buffer.snapshot();
    let mut merged = persisted_flow_meta(state).await;
    for flow in buffer {
        if let Some(existing) = merged.iter_mut().find(|item| item.id == flow.id) {
            *existing = flow;
        } else {
            merged.push(flow);
        }
    }
    merged.sort_by_key(|flow| std::cmp::Reverse(flow.timestamp));
    merged
}

/// Summary-only persisted rows (bodies are not read from SQLite).
async fn persisted_flow_meta(state: &AppState) -> Vec<api_tester_domain::HttpFlow> {
    let store_arc = state.store.clone();
    state
        .runtime
        .spawn(async move {
            if let Some(store) = open_store(&store_arc).await {
                store
                    .flows()
                    .list_recent_meta(5000)
                    .await
                    .unwrap_or_default()
            } else {
                Vec::new()
            }
        })
        .await
        .unwrap_or_default()
}

/// Full flow for the inspector: loaded from SQLite (bodies included) on demand,
/// falling back to the in-memory summary buffer if not yet persisted.
async fn flow_by_id(state: &AppState, flow_id: &str) -> Option<api_tester_domain::HttpFlow> {
    let store_arc = state.store.clone();
    let id = flow_id.to_owned();
    let persisted = state
        .runtime
        .spawn(async move {
            if let Some(store) = open_store(&store_arc).await {
                store.flows().get_by_id(&id).await.ok().flatten()
            } else {
                None
            }
        })
        .await
        .ok()
        .flatten();
    persisted.or_else(|| {
        state
            .buffer
            .snapshot()
            .into_iter()
            .find(|f| f.id == flow_id)
    })
}

/// Total persisted flow count (used by the dashboard health poll).
async fn persisted_flow_count(state: &AppState) -> u64 {
    let store_arc = state.store.clone();
    state
        .runtime
        .spawn(async move {
            if let Some(store) = open_store(&store_arc).await {
                store.flows().count().await.unwrap_or(0)
            } else {
                0
            }
        })
        .await
        .unwrap_or(0)
}

async fn persisted_sessions(state: &AppState) -> Vec<Session> {
    let store_arc = state.store.clone();
    state
        .runtime
        .spawn(async move {
            if let Some(store) = open_store(&store_arc).await {
                store.sessions().list_recent(100).await.unwrap_or_default()
            } else {
                Vec::new()
            }
        })
        .await
        .unwrap_or_default()
}

/// Location of the MITM CA certificate file.
fn ca_path(state: &AppState) -> PathBuf {
    state
        .config
        .proxy
        .ssl_cert_dir
        .clone()
        .unwrap_or_else(certs_dir)
        .join("ca.crt")
}

/// Whether the CA is present in the current user's trusted root store,
/// matched by thumbprint so a stale (e.g. regenerated) CA is not trusted.
fn ca_installed(path: &Path) -> bool {
    let Some(thumbprint) = ca_thumbprint(path) else {
        return false;
    };
    let script = format!(
        "if (Get-ChildItem Cert:\\CurrentUser\\Root | Where-Object {{ $_.Thumbprint -eq '{thumbprint}' }}) {{ 'yes' }} else {{ 'no' }}",
        thumbprint = thumbprint
    );
    match std::process::Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .output()
    {
        Ok(output) => String::from_utf8_lossy(&output.stdout).contains("yes"),
        Err(_) => false,
    }
}

/// Thumbprint (uppercase hex) of a certificate file, or None when unreadable.
fn ca_thumbprint(path: &Path) -> Option<String> {
    let script = format!(
        "(New-Object System.Security.Cryptography.X509Certificates.X509Certificate2('{}')).Thumbprint",
        path.display()
    );
    let output = std::process::Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .output()
        .ok()?;
    let thumbprint = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    (thumbprint.len() == 40).then_some(thumbprint.to_uppercase())
}

/// Installs the CA into the current user's trusted root store (no admin).
fn install_ca_win(path: &Path) -> Result<(), String> {
    let output = std::process::Command::new("certutil")
        .args([
            "-user",
            "-addstore",
            "-f",
            "Root",
            &path.display().to_string(),
        ])
        .output()
        .map_err(|error| error.to_string())?;
    if output.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&output.stderr).into_owned())
    }
}

/// Wires the proxy to the dashboard sink and SQLite session repository.
async fn build_proxy(state: &AppState) -> Result<Arc<ProxyServer>, String> {
    let store = state
        .store()
        .await
        .ok_or_else(|| "storage unavailable".to_owned())?;

    let config = state.config.clone();
    let scope =
        Arc::new(ScopeFilter::new(config.scope.clone()).map_err(|error| error.to_string())?);
    let match_replace = Arc::new(MatchReplaceEngine::new(config.match_replace_rules.clone()));
    let cert_dir = config.proxy.ssl_cert_dir.clone().unwrap_or_else(certs_dir);
    std::fs::create_dir_all(&cert_dir).map_err(|error| error.to_string())?;
    // Host certificates point their CRL distribution point at the proxy's real
    // listener so strict clients (Windows schannel) can fetch the CRL.
    let crl_host = match config.proxy.host.as_str() {
        "0.0.0.0" | "::" | "" => "127.0.0.1".to_owned(),
        host => host.to_owned(),
    };
    let crl_url = format!("http://{crl_host}:{}/ca.crl", config.proxy.port);
    let cert: Arc<dyn CertProvider> = Arc::new(RcgenCertProvider::new_with_crl(cert_dir, crl_url));
    cert.ca_cert_pem().map_err(|error| error.to_string())?;
    let upstream = Arc::new(UpstreamClient::new(&config.proxy).map_err(|error| error.to_string())?);
    let sink: Arc<dyn api_tester_ports::CaptureSink> = Arc::new(DashboardSink::new(
        state.buffer.clone(),
        state.store.clone(),
        state.events.clone(),
    ));
    let session_repository: Arc<dyn SessionRepository> = Arc::new(store.sessions().clone());

    let last_error = state.last_error.clone();
    let error_callback: Arc<dyn Fn(String) + Send + Sync> = Arc::new(move |message| {
        *last_error
            .lock()
            .unwrap_or_else(|poison| poison.into_inner()) = Some(message);
    });

    Ok(Arc::new(
        ProxyServer::new(
            config.proxy,
            scope,
            match_replace,
            cert,
            upstream,
            sink,
            session_repository,
        )
        .on_error(error_callback)
        .with_intercept(state.intercept.clone()),
    ))
}
