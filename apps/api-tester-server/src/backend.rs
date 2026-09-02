//! Application logic as `AppState` methods (ex-Tauri commands, now plain async
//! methods called by the axum routes). There is no IPC/serde boundary anymore.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use api_tester_ai::{DeepSeekClient, build_summary_prompt};
use api_tester_analysis::{DependencyMapper, FlowSequencer};
use api_tester_config::ConfigLoader;
use api_tester_domain::{
    HttpFlow, SITEMAP_ANNOTATION_COLORS, ScopeConfig, Session, SitemapAnnotation,
};
use api_tester_ports::{
    AnnotationRepository, FlowRepository, HttpClient, HttpRequest, SessionRepository,
};
use api_tester_proxy::{
    CertProvider, InterceptEdit, InterceptEntry, MatchReplaceEngine, ProxyServer,
    RcgenCertProvider, ScopeFilter, UpstreamClient,
};
use api_tester_reporting::{MermaidGenerator, PythonReplayGenerator, ReplayMode};
use serde_json::json;

use crate::dashboard::DashboardSink;
use crate::serialization::{
    CertInfo, FlowDetail, FlowFilters, FlowGraphNode, FlowReport, FlowReportRequest, FlowStep,
    FlowSummary, ProxyStatus, RepeaterRequest, RepeaterResponse, SessionSummary,
    SitemapAnnotationDto, SitemapTree, build_sitemap_tree, filter_flows,
};
use crate::state::{
    AppState, certs_dir, clear_storage_error, last_storage_error, open_store, reset_store,
};

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
        let flows = if let Some(ref sid) = filters.session_id {
            self.flows_for_session_meta(sid).await
        } else {
            all_flows(self).await
        };
        Ok(filter_flows(flows, filters)
            .iter()
            .map(FlowSummary::from)
            .collect())
    }

    /// Summary-only flows for one session (SQL pushdown), merged with the
    /// live buffer so unflushed entries are not missed.
    async fn flows_for_session_meta(&self, session_id: &str) -> Vec<HttpFlow> {
        let store_arc = self.store.clone();
        let sid = session_id.to_owned();
        let mut flows: Vec<HttpFlow> = self
            .runtime
            .spawn(async move {
                if let Some(store) = open_store(&store_arc).await {
                    store
                        .flows()
                        .list_by_session_meta(&sid, 5000)
                        .await
                        .unwrap_or_default()
                } else {
                    Vec::new()
                }
            })
            .await
            .unwrap_or_default();
        for flow in self.buffer.snapshot() {
            if flow.session_id == session_id && !flows.iter().any(|existing| existing.id == flow.id)
            {
                flows.push(flow);
            }
        }
        flows.sort_by_key(|flow| std::cmp::Reverse(flow.timestamp));
        flows
    }

    pub async fn flow_detail(&self, flow_id: &str) -> Result<FlowDetail, String> {
        let flow = flow_by_id(self, flow_id)
            .await
            .ok_or_else(|| format!("flow {flow_id} not found"))?;
        Ok(FlowDetail::from(&flow))
    }

    pub async fn start_session(
        &self,
        name: String,
        target_host: String,
    ) -> Result<Session, String> {
        let session = Session {
            id: uuid_v4(),
            name,
            target_host,
            start_time: chrono::Utc::now(),
            end_time: None,
            flow_count: 0,
            notes: String::new(),
        };
        let store_arc = self.store.clone();
        let s = session.clone();
        self.runtime
            .spawn(async move {
                if let Some(store) = open_store(&store_arc).await {
                    let _ = store.sessions().save(&s).await;
                }
            })
            .await
            .map_err(|e| e.to_string())?;
        *self.active_session_id.lock().await = Some(session.id.clone());
        Ok(session)
    }

    pub async fn stop_session(&self) -> Result<(), String> {
        let session_id = self.active_session_id.lock().await.take();
        if let Some(id) = session_id {
            let store_arc = self.store.clone();
            self.runtime
                .spawn(async move {
                    if let Some(store) = open_store(&store_arc).await {
                        if let Ok(Some(mut s)) = store.sessions().get_by_id(&id).await {
                            s.end_time = Some(chrono::Utc::now());
                            let _ = store.sessions().save(&s).await;
                        }
                    }
                })
                .await
                .map_err(|e| e.to_string())?;
        }
        Ok(())
    }

    /// Returns the currently active session id (or None).
    pub async fn active_session(&self) -> Option<String> {
        self.active_session_id.lock().await.clone()
    }

    pub async fn delete_session(&self, session_id: &str) -> Result<(), String> {
        let sid = session_id.to_owned();
        let store_arc = self.store.clone();
        self.runtime
            .spawn(async move {
                if let Some(store) = open_store(&store_arc).await {
                    store
                        .sessions()
                        .delete(&sid)
                        .await
                        .map_err(|e| e.to_string())
                } else {
                    Err("storage unavailable".to_owned())
                }
            })
            .await
            .map_err(|e| e.to_string())?
    }

    pub async fn clear_all_sessions(&self) -> Result<(), String> {
        let store_arc = self.store.clone();
        self.runtime
            .spawn(async move {
                if let Some(store) = open_store(&store_arc).await {
                    store
                        .sessions()
                        .clear_all()
                        .await
                        .map_err(|e| e.to_string())
                } else {
                    Err("storage unavailable".to_owned())
                }
            })
            .await
            .map_err(|e| e.to_string())?
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
            body: display_body(&sent.body),
            headers: sent.headers,
        })
    }

    pub async fn start_proxy(&self) -> Result<ProxyStatus, String> {
        ensure_proxy_running(self).await?;
        self.ws_send(
            &json!({"type": "proxy", "running": true, "address": self.proxy_status().address}),
        );
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
        // Reopen SQLite on the next start so stale WAL state never lingers
        // across proxy sessions.
        reset_store(&self.store).await;
        clear_storage_error().await;
        self.proxy_running.store(false, Ordering::SeqCst);
        self.ws_send(
            &json!({"type": "proxy", "running": false, "address": self.proxy_status().address}),
        );
        Ok(self.proxy_status())
    }

    pub fn proxy_status(&self) -> ProxyStatus {
        let config = self
            .config
            .read()
            .unwrap_or_else(|poison| poison.into_inner());
        ProxyStatus {
            running: self.proxy_running.load(Ordering::SeqCst),
            host: config.proxy.host.clone(),
            port: config.proxy.port,
            address: format!("{}:{}", config.proxy.host, config.proxy.port),
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

        let config = self
            .config
            .read()
            .unwrap_or_else(|poison| poison.into_inner());
        let host = config.proxy.host.clone();
        let port = config.proxy.port;
        drop(config);
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
        self.ws_send(&json!({"type": "intercept", "held": self.intercept.len()}));
        Ok(())
    }

    pub fn intercept_set_scopes(
        &self,
        intercept_requests: bool,
        intercept_responses: bool,
    ) -> Result<(), String> {
        self.intercept.set_intercept_requests(intercept_requests);
        self.intercept.set_intercept_responses(intercept_responses);
        self.ws_send(&json!({"type": "intercept", "held": self.intercept.len()}));
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
        let ok = self.intercept.forward(id, edit);
        self.ws_send(&json!({"type": "intercept", "held": self.intercept.len()}));
        Ok(ok)
    }

    pub fn intercept_drop(&self, id: &str) -> Result<bool, String> {
        let ok = self.intercept.drop_item(id);
        self.ws_send(&json!({"type": "intercept", "held": self.intercept.len()}));
        Ok(ok)
    }

    pub fn intercept_clear(&self) -> Result<(), String> {
        self.intercept.clear_all();
        self.ws_send(&json!({"type": "intercept", "held": self.intercept.len()}));
        Ok(())
    }

    /// Clears the captured HTTP history: the in-memory ring buffer and every
    /// persisted flow in SQLite. New captures after this point repopulate both.
    pub async fn clear_logs(&self) -> Result<(), String> {
        self.buffer.clear();
        let store_arc = self.store.clone();
        self.runtime
            .spawn(async move {
                if let Some(store) = open_store(&store_arc).await {
                    store
                        .flows()
                        .clear_all()
                        .await
                        .map_err(|error| error.to_string())
                } else {
                    Ok(())
                }
            })
            .await
            .map_err(|error| error.to_string())?
            .map_err(|error| error.to_string())?;
        self.ws_send(&json!({"type": "flows_cleared"}));
        Ok(())
    }

    /// Full captured flows (bodies included) needed by the analysis pipeline.
    /// Prefers the SQLite store because the in-memory buffer only keeps summary
    /// rows; falls back to the buffer when storage is unavailable. Returned in
    /// chronological order so the topo-sort has a stable input.
    /// Flows captured in a specific session (bodies included).
    /// Merges persisted SQLite rows with any unflushed ring-buffer entries
    /// matching the session, so recently captured flows are not missed.
    pub async fn flows_for_session(&self, session_id: &str, limit: usize) -> Vec<HttpFlow> {
        let store_arc = self.store.clone();
        let sid = session_id.to_owned();
        let mut flows: Vec<HttpFlow> = self
            .runtime
            .spawn(async move {
                if let Some(store) = open_store(&store_arc).await {
                    store
                        .flows()
                        .list_by_session(&sid)
                        .await
                        .unwrap_or_default()
                } else {
                    Vec::new()
                }
            })
            .await
            .unwrap_or_default();
        for flow in self.buffer.snapshot() {
            if flow.session_id == session_id && !flows.iter().any(|existing| existing.id == flow.id)
            {
                flows.push(flow);
            }
        }
        flows.sort_by_key(|flow| flow.timestamp);
        flows.truncate(limit);
        flows
    }

    pub async fn full_flows_for_analysis(&self, limit: usize) -> Vec<HttpFlow> {
        let store_arc = self.store.clone();
        let mut flows = self
            .runtime
            .spawn(async move {
                if let Some(store) = open_store(&store_arc).await {
                    store
                        .flows()
                        .list_recent(limit as u64)
                        .await
                        .unwrap_or_default()
                } else {
                    Vec::new()
                }
            })
            .await
            .unwrap_or_default();
        let buffer = self.buffer.snapshot();
        for flow in buffer {
            if let Some(existing) = flows.iter_mut().find(|item| item.id == flow.id) {
                *existing = flow;
            } else {
                flows.push(flow);
            }
        }
        flows.sort_by_key(|flow| flow.timestamp);
        flows.truncate(limit);
        flows
    }

    /// Builds the flow-code report (Mermaid sequence or Python replay) with the
    /// dependency-ordered steps, from captured traffic. Noise (tracking beacons,
    /// static assets) is filtered and identical requests are deduped so the
    /// diagram stays focused on the application.
    pub async fn flow_report(&self, request: FlowReportRequest) -> Result<FlowReport, String> {
        let raw = self.full_flows_for_analysis(1000).await;
        let deduped = api_tester_analysis::filter_for_analysis_with_counts(&raw);
        let flows: Vec<HttpFlow> = deduped.iter().map(|(flow, _)| flow.clone()).collect();
        let mut count_by_fingerprint: std::collections::HashMap<String, usize> =
            std::collections::HashMap::new();
        for (flow, count) in &deduped {
            count_by_fingerprint.insert(flow.fingerprint(), *count);
        }
        let mapper = DependencyMapper::new();
        let graph = mapper.build_graph(&flows);
        let dependencies = mapper.build_dependencies(&flows);
        let sorted = FlowSequencer.topological_sort(&flows, &graph);
        let output = match request.format.as_str() {
            "python" => {
                let mode = match request.mode.as_deref() {
                    Some("parameterized") => ReplayMode::Parameterized,
                    _ => ReplayMode::Recording,
                };
                PythonReplayGenerator::new(mode).generate(&flows, &graph)
            }
            _ => MermaidGenerator::new().generate(&flows, &graph),
        };
        let steps = sorted
            .flows
            .iter()
            .map(|flow| FlowStep {
                fingerprint: flow.fingerprint(),
                method: flow.method.as_str().to_owned(),
                path: flow.path.split('?').next().unwrap_or(&flow.path).to_owned(),
                status: flow.response_status,
                count: count_by_fingerprint
                    .get(&flow.fingerprint())
                    .copied()
                    .unwrap_or(1),
            })
            .collect();
        let filtered_raw = api_tester_analysis::filter_noise(&raw);
        let graph_builder = api_tester_analysis::FlowGraphBuilder::new();
        let timeline_graph = graph_builder.build_timeline_graph(&filtered_raw);
        let graph_nodes: Vec<FlowGraphNode> = timeline_graph
            .nodes
            .iter()
            .map(FlowGraphNode::from)
            .collect();

        Ok(FlowReport {
            flow_count: raw.len(),
            cycles: sorted.cycles_detected,
            format: request.format,
            output,
            steps,
            graph_nodes,
            dependencies,
        })
    }

    /// Sitemap of captured endpoints as a Burp-style tree
    /// (site → directories → endpoint leaves), with annotations merged in.
    pub async fn sitemap(&self, session_id: Option<String>) -> Result<SitemapTree, String> {
        let flows = if let Some(ref sid) = session_id {
            self.flows_for_session_meta(sid).await
        } else {
            all_flows(self).await
        };
        let flows = api_tester_analysis::filter_noise(&flows);
        let annotations = self.load_annotation_map().await;
        Ok(build_sitemap_tree(&flows, &annotations))
    }

    /// Loads every stored sitemap annotation keyed by URL, for tree merging.
    async fn load_annotation_map(&self) -> std::collections::HashMap<String, SitemapAnnotationDto> {
        let Some(store) = self.store().await else {
            return std::collections::HashMap::new();
        };
        match store.annotations().list_all().await {
            Ok(list) => list
                .into_iter()
                .map(|annotation| {
                    (
                        annotation.key,
                        SitemapAnnotationDto {
                            comment: annotation.comment,
                            color: annotation.color,
                        },
                    )
                })
                .collect(),
            Err(error) => {
                eprintln!("[sitemap] failed to load annotations: {error}");
                std::collections::HashMap::new()
            }
        }
    }

    pub fn scope(&self) -> Result<ScopeConfig, String> {
        Ok(self
            .config
            .read()
            .unwrap_or_else(|poison| poison.into_inner())
            .scope
            .clone())
    }

    pub fn security_scope(&self) -> Result<ScopeConfig, String> {
        Ok(self
            .config
            .read()
            .unwrap_or_else(|poison| poison.into_inner())
            .security
            .scope
            .clone())
    }

    pub async fn update_scope(
        &self,
        include_hosts: Option<Vec<String>>,
        exclude_hosts: Option<Vec<String>>,
        include_paths: Option<Vec<String>>,
        exclude_paths: Option<Vec<String>>,
    ) -> Result<ScopeConfig, String> {
        // Serializes with proxy startup: `ensure_proxy_running` holds this mutex
        // until its built proxy is installed, so an update cannot miss it.
        let proxy_guard = self.proxy.lock().await;
        let proxy = proxy_guard.clone();

        // Persist the candidate before committing state so a failed write never
        // leaves in-memory scope ahead of disk.
        let mut candidate = {
            let config = self
                .config
                .read()
                .unwrap_or_else(|poison| poison.into_inner());
            config.clone()
        };
        if let Some(patterns) = include_hosts {
            candidate.scope.include_hosts = normalized_scope_patterns(patterns);
        }
        if let Some(patterns) = exclude_hosts {
            candidate.scope.exclude_hosts = normalized_scope_patterns(patterns);
        }
        if let Some(patterns) = include_paths {
            candidate.scope.include_paths = normalized_scope_patterns(patterns);
        }
        if let Some(patterns) = exclude_paths {
            candidate.scope.exclude_paths = normalized_scope_patterns(patterns);
        }

        let scope_filter =
            ScopeFilter::new(candidate.scope.clone()).map_err(|error| error.to_string())?;
        ConfigLoader::save(&candidate, &self.config_path).map_err(|error| error.to_string())?;
        *self
            .config
            .write()
            .unwrap_or_else(|poison| poison.into_inner()) = candidate.clone();
        if let Some(proxy) = proxy {
            proxy.replace_scope(scope_filter);
        }

        Ok(candidate.scope)
    }

    pub async fn update_security_scope(
        &self,
        include_hosts: Option<Vec<String>>,
        exclude_hosts: Option<Vec<String>>,
        include_paths: Option<Vec<String>>,
        exclude_paths: Option<Vec<String>>,
    ) -> Result<ScopeConfig, String> {
        let mut candidate = {
            let config = self
                .config
                .read()
                .unwrap_or_else(|poison| poison.into_inner());
            config.clone()
        };
        if let Some(patterns) = include_hosts {
            candidate.security.scope.include_hosts = normalized_scope_patterns(patterns);
        }
        if let Some(patterns) = exclude_hosts {
            candidate.security.scope.exclude_hosts = normalized_scope_patterns(patterns);
        }
        if let Some(patterns) = include_paths {
            candidate.security.scope.include_paths = normalized_scope_patterns(patterns);
        }
        if let Some(patterns) = exclude_paths {
            candidate.security.scope.exclude_paths = normalized_scope_patterns(patterns);
        }
        let scope_filter =
            ScopeFilter::new(candidate.security.scope.clone()).map_err(|error| error.to_string())?;
        // Validate but do not hot-swap proxy (security scope is for executor only)
        let _ = scope_filter;
        ConfigLoader::save(&candidate, &self.config_path).map_err(|error| error.to_string())?;
        *self
            .config
            .write()
            .unwrap_or_else(|poison| poison.into_inner()) = candidate.clone();
        Ok(candidate.security.scope)
    }

    /// Creates or updates the annotation (comment and/or color) of one sitemap
    /// URL key. `None` fields keep their stored value untouched is NOT the
    /// contract here: the PUT replaces the whole annotation.
    pub async fn sitemap_upsert_annotation(
        &self,
        key: String,
        comment: Option<String>,
        color: Option<String>,
    ) -> Result<(), String> {
        let key = key.trim().to_owned();
        if key.is_empty() {
            return Err("annotation key must not be empty".to_owned());
        }
        if let Some(color) = color.as_deref() {
            if !SITEMAP_ANNOTATION_COLORS.contains(&color) {
                return Err(format!(
                    "unknown annotation color '{color}' (allowed: {})",
                    SITEMAP_ANNOTATION_COLORS.join(", ")
                ));
            }
        }
        let comment = comment.filter(|value| !value.trim().is_empty());
        if comment.is_none() && color.is_none() {
            // Nothing left after clearing both fields — drop the row instead.
            return self.sitemap_delete_annotation(key).await;
        }
        let annotation = SitemapAnnotation {
            key,
            comment,
            color,
            updated_at: chrono::Utc::now(),
        };
        let store = self.store().await.ok_or("storage unavailable")?;
        store
            .annotations()
            .upsert(&annotation)
            .await
            .map_err(|error| error.to_string())
    }

    pub async fn sitemap_delete_annotation(&self, key: String) -> Result<(), String> {
        let store = self.store().await.ok_or("storage unavailable")?;
        store
            .annotations()
            .delete(key.trim())
            .await
            .map_err(|error| error.to_string())
    }

    /// AI availability (model + configured flag); never exposes the API key.
    pub fn ai_status(&self) -> serde_json::Value {
        let config = self
            .config
            .read()
            .unwrap_or_else(|poison| poison.into_inner());
        let ai = &config.ai;
        json!({
            "configured": ai.api_key.as_ref().is_some_and(|key| !key.trim().is_empty()),
            "model": ai.model,
            "base_url": ai.base_url,
        })
    }

    pub async fn update_ai_config(
        &self,
        api_key: Option<String>,
        base_url: Option<String>,
        model: Option<String>,
        max_tokens: Option<u32>,
        timeout_secs: Option<u64>,
    ) -> Result<serde_json::Value, String> {
        let mut candidate = {
            let config = self
                .config
                .read()
                .unwrap_or_else(|poison| poison.into_inner());
            config.clone()
        };

        if let Some(key) = api_key {
            candidate.ai.api_key = Some(key);
        }
        if let Some(url) = base_url {
            candidate.ai.base_url = url;
        }
        if let Some(m) = model {
            candidate.ai.model = m;
        }
        if let Some(t) = max_tokens {
            candidate.ai.max_tokens = t;
        }
        if let Some(t) = timeout_secs {
            candidate.ai.timeout_secs = t;
        }

        candidate.validate().map_err(|e| e.to_string())?;

        ConfigLoader::save(&candidate, &self.config_path)
            .map_err(|e| e.to_string())?;

        *self
            .config
            .write()
            .unwrap_or_else(|poison| poison.into_inner()) = candidate.clone();

        Ok(json!({
            "ok": true,
            "model": candidate.ai.model,
            "base_url": candidate.ai.base_url,
            "configured": candidate.ai.api_key
                .as_ref()
                .is_some_and(|k| !k.trim().is_empty()),
        }))
    }

    pub async fn ai_models_list(&self) -> Result<serde_json::Value, String> {
        let (base_url, api_key) = {
            let config = self
                .config
                .read()
                .unwrap_or_else(|poison| poison.into_inner());
            (
                config.ai.base_url.trim_end_matches('/').to_owned(),
                config.ai.api_key.clone().unwrap_or_default(),
            )
        };
        let url = format!("{}/models", base_url);
        let http = self.http.clone();
        let api_key = api_key.clone();
        let response = self
            .runtime
            .spawn(async move {
                http.send(api_tester_ports::HttpRequest {
                    method: "GET".to_owned(),
                    url,
                    headers: vec![("Authorization".to_owned(), format!("Bearer {}", api_key))],
                    body: None,
                })
                .await
            })
            .await
            .map_err(|e| e.to_string())?
            .map_err(|e| e.to_string())?;
        let body: serde_json::Value =
            serde_json::from_slice(&response.body).map_err(|e| e.to_string())?;
        Ok(body)
    }

    pub async fn ai_prompt_preview(&self) -> Result<serde_json::Value, String> {
        let ctx = self
            .build_ai_context(None, false, None)
            .await
            .map_err(|e| e.to_string())?;
        let prompt = api_tester_ai::build_summary_prompt(&ctx, 200);
        Ok(serde_json::json!({"system": prompt.system, "user": prompt.user}))
    }

    pub async fn reload_config(&self) -> Result<serde_json::Value, String> {
        let cfg = api_tester_config::ConfigLoader::load(Some(&self.config_path))
            .map_err(|e| e.to_string())?;
        cfg.validate().map_err(|e| e.to_string())?;
        api_tester_analysis::init_analysis_config(cfg.analysis.clone());
        api_tester_analysis::init_host_profiles(cfg.host_profiles.clone());
        *self
            .config
            .write()
            .unwrap_or_else(|poison| poison.into_inner()) = cfg.clone();
        if let Some(proxy) = self.proxy.lock().await.as_ref() {
            if let Ok(filter) = api_tester_domain::ScopeFilter::new(cfg.scope.clone()) {
                proxy.replace_scope(filter);
            }
        }
        Ok(serde_json::json!({"ok": true, "config": cfg}))
    }

    /// One-shot DeepSeek summary of the captured flow. Only sends a compact,
    /// redacted context (steps/dependencies/sitemap) — never raw bodies,
    /// headers, or token values — and only runs on an explicit user action.
    pub async fn ai_flow_summary(&self, model: Option<String>) -> Result<String, String> {
        let ai = self
            .config
            .read()
            .unwrap_or_else(|poison| poison.into_inner())
            .ai
            .clone();
        let Some(api_key) = ai.api_key.filter(|key| !key.trim().is_empty()) else {
            return Err(
                "AI chưa được cấu hình — đặt biến môi trường DEEPSEEK_API_KEY hoặc ai.api_key trong config.json"
                    .to_owned(),
            );
        };

        let context = self
            .build_ai_context(None, false, None)
            .await
            .map_err(|error| error.to_string())?;
        let prompt = build_summary_prompt(&context, 200);

        let model = model.unwrap_or_else(|| ai.model.clone());
        let client = DeepSeekClient::new(
            self.http.clone(),
            ai.base_url.clone(),
            model,
            api_key,
            ai.max_tokens,
            Duration::from_secs(ai.timeout_secs.max(1)),
        );
        client
            .chat(&prompt.system, &prompt.user)
            .await
            .map_err(|error| error.to_string())
    }
}

fn display_body(body: &[u8]) -> String {
    match std::str::from_utf8(body) {
        Ok(text) => text.to_owned(),
        Err(_) => body
            .chunks(16)
            .enumerate()
            .map(|(offset, chunk)| {
                let bytes = chunk
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<Vec<_>>()
                    .join(" ");
                format!("{:08x}  {bytes}", offset * 16)
            })
            .collect::<Vec<_>>()
            .join("\n"),
    }
}

/// Starts the proxy if it is not already running. On a readonly-database
/// failure the cached store is dropped so the next attempt reopens SQLite
/// with full recovery instead of retrying through the poisoned pool.
async fn ensure_proxy_running(state: &AppState) -> Result<(), String> {
    let mut proxy_guard = state.proxy.lock().await;
    if state.proxy_running.load(Ordering::SeqCst) {
        return Ok(());
    }
    let proxy = build_proxy(state).await?;
    let start_result = state
        .runtime
        .spawn({
            let proxy = proxy.clone();
            async move { proxy.start().await }
        })
        .await
        .map_err(|error| error.to_string())?
        .map_err(|error| error.to_string());
    if let Err(message) = &start_result {
        let lowered = message.to_lowercase();
        if lowered.contains("readonly")
            || lowered.contains("read-only")
            || lowered.contains("code: 8")
            || lowered.contains("database is locked")
        {
            reset_store(&state.store).await;
        }
    }
    start_result?;
    *proxy_guard = Some(proxy);
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
    let config = state
        .config
        .read()
        .unwrap_or_else(|poison| poison.into_inner());
    config
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
    let store = match state.store().await {
        Some(store) => store,
        None => {
            let detail = last_storage_error()
                .await
                .unwrap_or_else(|| "unknown error".to_owned());
            return Err(format!("storage unavailable: {detail}"));
        }
    };

    let config = state
        .config
        .read()
        .unwrap_or_else(|poison| poison.into_inner())
        .clone();
    let scope = Arc::new(std::sync::RwLock::new(
        ScopeFilter::new(config.scope.clone()).map_err(|error| error.to_string())?,
    ));
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
        state.ws_tx.clone(),
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
        .with_session_id_source(state.active_session_id.clone())
        .on_error(error_callback)
        .with_intercept(state.intercept.clone()),
    ))
}

fn uuid_v4() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("{:032x}", now | 0x8000000000000000)
}

fn normalized_scope_patterns(patterns: Vec<String>) -> Vec<String> {
    let mut normalized = patterns
        .into_iter()
        .map(|pattern| pattern.trim().to_owned())
        .filter(|pattern| !pattern.is_empty())
        .collect::<Vec<_>>();
    normalized.sort();
    normalized.dedup();
    normalized
}
