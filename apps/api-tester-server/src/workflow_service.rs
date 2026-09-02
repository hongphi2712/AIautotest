//! Workflow AI generation + execution orchestration. Implements the bounded
//! repair loop (AI -> parse -> schema -> graph/scope validation, max 2
//! repairs), versioned saving on approval, and streaming execution with
//! cancellation. AI never runs requests on its own: generation only produces a
//! preview; a run requires explicit approval + scope confirmation.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use api_tester_ai::{DeepSeekClient, FlowContext, build_workflow_prompt};
use api_tester_analysis::{DependencyMapper, FlowSequencer};
use api_tester_domain::{ScopeFilter, WorkflowRun, WorkflowVersion};
use api_tester_ports::WorkflowRepository;
use api_tester_workflow::{Workflow, WorkflowRunner, validate};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio_util::sync::CancellationToken;

use crate::state::AppState;

const MAX_GENERATION_ATTEMPTS: usize = 3; // 1 initial + 2 repairs

/// Typed workflow service error carrying an HTTP status for the route layer.
#[derive(Debug)]
pub enum WorkflowError {
    BadRequest(String),
    NotFound(String),
    ScopeConflict(String),
    Storage(String),
}

impl fmt::Display for WorkflowError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadRequest(message) => write!(formatter, "{message}"),
            Self::NotFound(message) => write!(formatter, "{message}"),
            Self::ScopeConflict(message) => write!(formatter, "{message}"),
            Self::Storage(message) => write!(formatter, "{message}"),
        }
    }
}

impl std::error::Error for WorkflowError {}

impl From<api_tester_ports::PortError> for WorkflowError {
    fn from(error: api_tester_ports::PortError) -> Self {
        Self::Storage(error.to_string())
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct WorkflowGenerateRequest {
    pub prompt: String,
    pub base_url: String,
    #[serde(default)]
    pub use_traffic: bool,
    #[serde(default)]
    pub session_id: Option<String>,
    #[serde(default)]
    pub model: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct WorkflowApproveRequest {
    pub name: String,
    pub base_url: String,
    pub spec_json: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct WorkflowRunRequest {
    pub version_id: String,
    #[serde(default)]
    pub confirm_scope_override: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct WorkflowCancelRequest {
    pub run_id: String,
}

impl AppState {
    /// Generates a workflow from a natural-language request. Returns a preview
    /// payload: the parsed JSON (possibly invalid), the number of AI attempts,
    /// final validation errors (empty = ready to approve) and scope warnings.
    pub async fn workflow_generate(
        &self,
        request: WorkflowGenerateRequest,
    ) -> Result<Value, WorkflowError> {
        let ai = self
            .config
            .read()
            .unwrap_or_else(|poison| poison.into_inner())
            .ai
            .clone();
        let Some(api_key) = ai.api_key.filter(|key| !key.trim().is_empty()) else {
            return Err(WorkflowError::BadRequest(
                "AI chưa được cấu hình — đặt DEEPSEEK_API_KEY hoặc ai.api_key trong config.json"
                    .to_owned(),
            ));
        };
        if request.prompt.trim().is_empty() {
            return Err(WorkflowError::BadRequest(
                "Yêu cầu (prompt) không được để trống".to_owned(),
            ));
        }
        if request.base_url.trim().is_empty() {
            return Err(WorkflowError::BadRequest(
                "base_url không được để trống".to_owned(),
            ));
        }

        let model = request.model.unwrap_or_else(|| ai.model.clone());
        let client = DeepSeekClient::new(
            self.http.clone(),
            ai.base_url.clone(),
            model,
            api_key,
            ai.max_tokens,
            Duration::from_secs(ai.timeout_secs.max(1)),
        );
        let scope = ScopeFilter::new(
            self.config
                .read()
                .unwrap_or_else(|poison| poison.into_inner())
                .scope
                .clone(),
        )
        .map_err(|error| WorkflowError::BadRequest(error.to_string()))
        .ok();
        let context = if request.use_traffic {
            Some(
                self.build_ai_context(
                    Some(&request.base_url),
                    false,
                    request.session_id.as_deref(),
                )
                .await?,
            )
        } else {
            None
        };

        let mut repair_hint: Option<String> = None;
        let mut attempts = 0usize;
        loop {
            attempts += 1;
            let prompt = build_workflow_prompt(
                &request.prompt,
                &request.base_url,
                context.as_ref(),
                repair_hint.as_deref(),
            );
            let raw = client
                .chat_json(&prompt.system, &prompt.user)
                .await
                .map_err(|error| WorkflowError::Storage(error.to_string()))?;
            let raw = strip_code_fences(&raw);

            let parsed: Value = match serde_json::from_str(&raw) {
                Ok(parsed) => parsed,
                Err(error) => {
                    if attempts >= MAX_GENERATION_ATTEMPTS {
                        return Ok(preview_json(
                            Value::Null,
                            attempts,
                            vec![format!("JSON parse failed: {error}")],
                            Vec::new(),
                        ));
                    }
                    repair_hint = Some(format!(
                        "The response was not valid JSON: {error}. Return a single JSON object only."
                    ));
                    continue;
                }
            };

            let workflow: Workflow = match serde_json::from_value(parsed.clone()) {
                Ok(workflow) => workflow,
                Err(error) => {
                    if attempts >= MAX_GENERATION_ATTEMPTS {
                        return Ok(preview_json(
                            parsed,
                            attempts,
                            vec![format!("schema validation failed: {error}")],
                            Vec::new(),
                        ));
                    }
                    repair_hint = Some(format!("Schema validation failed: {error}"));
                    continue;
                }
            };

            let validation = validate(&workflow, scope.as_ref());
            if validation.errors.is_empty() || attempts >= MAX_GENERATION_ATTEMPTS {
                return Ok(preview_json(
                    parsed,
                    attempts,
                    validation.errors,
                    validation.scope_warnings,
                ));
            }
            repair_hint = Some(format!(
                "Validation errors — fix ALL of them: {}",
                validation.errors.join("\n")
            ));
        }
    }

    /// Validates and saves an approved workflow version. Scope warnings are
    /// allowed here — they only require explicit confirmation at run time.
    pub async fn workflow_approve(
        &self,
        request: WorkflowApproveRequest,
    ) -> Result<Value, WorkflowError> {
        let workflow: Workflow = serde_json::from_str(&request.spec_json).map_err(|error| {
            WorkflowError::BadRequest(format!("invalid workflow JSON: {error}"))
        })?;
        let scope = ScopeFilter::new(
            self.config
                .read()
                .unwrap_or_else(|poison| poison.into_inner())
                .scope
                .clone(),
        )
        .map_err(|error| WorkflowError::BadRequest(error.to_string()))
        .ok();
        let validation = validate(&workflow, scope.as_ref());
        if !validation.is_valid() {
            return Err(WorkflowError::BadRequest(format!(
                "Workflow không hợp lệ: {}",
                validation.errors.join("; ")
            )));
        }

        let store = self
            .store()
            .await
            .ok_or_else(|| WorkflowError::Storage("storage unavailable".to_owned()))?;
        let version = WorkflowVersion {
            name: request.name,
            base_url: request.base_url,
            spec_json: request.spec_json,
            status: "approved".to_owned(),
            approved_at: Some(chrono::Utc::now()),
            ..WorkflowVersion::default()
        };
        store.workflows().save_version(&version).await?;
        serde_json::to_value(&version).map_err(|error| WorkflowError::Storage(error.to_string()))
    }

    /// Runs an approved workflow version. Returns a `ScopeConflict` error when
    /// the workflow still contains out-of-scope requests and the caller has
    /// not explicitly confirmed them.
    pub async fn workflow_run(&self, request: WorkflowRunRequest) -> Result<Value, WorkflowError> {
        let store = self
            .store()
            .await
            .ok_or_else(|| WorkflowError::Storage("storage unavailable".to_owned()))?;
        let version = store
            .workflows()
            .get_version(&request.version_id)
            .await?
            .ok_or_else(|| {
                WorkflowError::NotFound(format!(
                    "workflow version not found: {}",
                    request.version_id
                ))
            })?;

        let workflow: Workflow = serde_json::from_str(&version.spec_json).map_err(|error| {
            WorkflowError::BadRequest(format!("invalid workflow JSON: {error}"))
        })?;
        let scope = ScopeFilter::new(
            self.config
                .read()
                .unwrap_or_else(|poison| poison.into_inner())
                .scope
                .clone(),
        )
        .map_err(|error| WorkflowError::BadRequest(error.to_string()))
        .ok();
        let validation = validate(&workflow, scope.as_ref());
        if !validation.is_valid() {
            return Err(WorkflowError::BadRequest(format!(
                "Workflow không hợp lệ: {}",
                validation.errors.join("; ")
            )));
        }
        if !validation.scope_warnings.is_empty() && !request.confirm_scope_override {
            let urls: Vec<&str> = validation
                .scope_warnings
                .iter()
                .map(|warning| warning.url.as_str())
                .collect();
            return Err(WorkflowError::ScopeConflict(format!(
                "Workflow có {} request ngoài scope: {}. Đánh dấu confirm_scope_override=true để chạy.",
                urls.len(),
                urls.join(", ")
            )));
        }

        let run_id = uuid::Uuid::new_v4().to_string();
        let token = CancellationToken::new();
        self.workflow_tokens
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .insert(run_id.clone(), token.clone());

        let run = WorkflowRun {
            run_id: run_id.clone(),
            version_id: version.id.clone(),
            status: "running".to_owned(),
            ..WorkflowRun::default()
        };
        store.workflows().save_run(&run).await?;

        self.spawn_workflow_execution(version.id, run_id.clone(), workflow, store, token);
        Ok(json!({ "run_id": run_id }))
    }

    fn spawn_workflow_execution(
        &self,
        version_id: String,
        run_id: String,
        workflow: Workflow,
        store: api_tester_storage::SqliteStore,
        token: CancellationToken,
    ) {
        let http = self.http.clone();
        let ws = self.ws_tx.clone();
        let rt = self.runtime.clone();
        let tokens = self.workflow_tokens.clone();

        let results: Arc<std::sync::Mutex<BTreeMap<String, Value>>> =
            Arc::new(std::sync::Mutex::new(BTreeMap::new()));
        let db = store.clone();
        let event_ws = ws.clone();
        let event_rt = rt.clone();

        let runner = WorkflowRunner::new(Arc::new(workflow), http, token, run_id.clone()).on_node(
            move |event| {
                // Stream each node result to the UI and persist progressively.
                if let Ok(text) = serde_json::to_string(&json!({
                    "type": "workflow_node",
                    "run_id": event.run_id,
                    "node_id": event.node_id,
                    "ok": event.ok,
                    "output": event.output,
                    "error": event.error,
                    "duration_ms": event.duration_ms,
                })) {
                    let _ = event_ws.send(text);
                }
                let mut map = results.lock().unwrap_or_else(|poison| poison.into_inner());
                map.insert(
                    event.node_id.clone(),
                    json!({
                        "node_id": event.node_id,
                        "ok": event.ok,
                        "output": event.output,
                        "error": event.error,
                        "duration_ms": event.duration_ms,
                    }),
                );
                let snapshot = serde_json::to_string(&*map).unwrap_or_else(|_| "{}".to_owned());
                let db = db.clone();
                let rt = event_rt.clone();
                rt.spawn(async move {
                    let _ = db
                        .workflows()
                        .update_run(&event.run_id, "running", None, &snapshot)
                        .await;
                });
            },
        );

        rt.spawn(async move {
            let result = runner.run().await;
            let status = match result.status {
                api_tester_workflow::RunStatus::Completed => "completed",
                api_tester_workflow::RunStatus::Failed => "failed",
                api_tester_workflow::RunStatus::Cancelled => "cancelled",
                api_tester_workflow::RunStatus::TimedOut => "timed_out",
            };
            let results_json =
                serde_json::to_string(&result.results).unwrap_or_else(|_| "{}".to_owned());
            let _ = store
                .workflows()
                .update_run(&run_id, status, Some(result.finished_at), &results_json)
                .await;
            if let Ok(text) = serde_json::to_string(&json!({
                "type": "workflow_run",
                "run_id": run_id,
                "version_id": version_id,
                "status": status,
                "error": result.error,
            })) {
                let _ = ws.send(text);
            }
            tokens
                .lock()
                .unwrap_or_else(|poison| poison.into_inner())
                .remove(&run_id);
        });
    }

    pub async fn workflow_cancel(
        &self,
        request: WorkflowCancelRequest,
    ) -> Result<(), WorkflowError> {
        let token = self
            .workflow_tokens
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .get(&request.run_id)
            .cloned();
        match token {
            Some(token) => {
                token.cancel();
                Ok(())
            }
            None => Err(WorkflowError::NotFound(format!(
                "no running workflow with run_id: {}",
                request.run_id
            ))),
        }
    }

    pub async fn workflow_list(&self) -> Result<Value, WorkflowError> {
        let store = self
            .store()
            .await
            .ok_or_else(|| WorkflowError::Storage("storage unavailable".to_owned()))?;
        let versions = store.workflows().list_versions().await?;
        serde_json::to_value(&versions).map_err(|error| WorkflowError::Storage(error.to_string()))
    }

    pub async fn workflow_detail(&self, version_id: &str) -> Result<Value, WorkflowError> {
        let store = self
            .store()
            .await
            .ok_or_else(|| WorkflowError::Storage("storage unavailable".to_owned()))?;
        let version = store
            .workflows()
            .get_version(version_id)
            .await?
            .ok_or_else(|| {
                WorkflowError::NotFound(format!("workflow version not found: {version_id}"))
            })?;
        let runs = store.workflows().list_runs(version_id).await?;
        serde_json::to_value(json!({
            "version": version,
            "runs": runs,
        }))
        .map_err(|error| WorkflowError::Storage(error.to_string()))
    }

    /// Compact, redacted traffic context for the target host (or all hosts when
    /// `host_filter` is `None`). When `keep_query` is true, query strings are
    /// preserved in step paths (needed for security analysis to see params).
    pub async fn build_ai_context(
        &self,
        host_filter: Option<&str>,
        keep_query: bool,
        session_filter: Option<&str>,
    ) -> Result<FlowContext, WorkflowError> {
        use api_tester_ai::{DependencyEdge, SitemapLine, SummaryStep};

        let flows: Vec<api_tester_domain::HttpFlow> = if let Some(sid) = session_filter {
            self.flows_for_session(sid, 1000).await
        } else {
            self.full_flows_for_analysis(1000).await
        };
        let mut flows: Vec<api_tester_domain::HttpFlow> = match host_filter {
            Some(host) => flows
                .into_iter()
                .filter(|flow| flow.host.eq_ignore_ascii_case(host))
                .collect(),
            None => flows,
        };
        flows = api_tester_analysis::filter_for_analysis(&flows);

        let mapper = DependencyMapper::new();
        let graph = mapper.build_graph(&flows);
        let sorted = FlowSequencer.topological_sort(&flows, &graph).flows;

        let label_by_fingerprint: BTreeMap<String, String> = sorted
            .iter()
            .map(|flow| {
                let path = if keep_query {
                    flow.path.clone()
                } else {
                    path_without_query(flow).to_owned()
                };
                (
                    flow.fingerprint(),
                    format!("{} {}", flow.method.as_str(), path),
                )
            })
            .collect();

        let steps: Vec<SummaryStep> = sorted
            .iter()
            .map(|flow| SummaryStep {
                method: flow.method.as_str().to_owned(),
                path: if keep_query {
                    flow.path.clone()
                } else {
                    path_without_query(flow)
                },
                status: flow.response_status,
                request_body: truncate_body(flow.request_body.as_deref()),
                response_body: truncate_body(flow.response_body.as_deref()),
            })
            .collect();

        let dependencies: Vec<DependencyEdge> = mapper
            .build_dependencies(&flows)
            .into_iter()
            .map(|dependency| DependencyEdge {
                source: label_by_fingerprint
                    .get(&dependency.source_flow_id)
                    .cloned()
                    .unwrap_or(dependency.source_flow_id),
                target: label_by_fingerprint
                    .get(&dependency.target_flow_id)
                    .cloned()
                    .unwrap_or(dependency.target_flow_id),
                token_type: serde_json::to_value(&dependency.token.token_type)
                    .ok()
                    .and_then(|value| value.as_str().map(str::to_owned))
                    .unwrap_or_default(),
                location: dependency.usage_location,
            })
            .collect();

        let sitemap: Vec<SitemapLine> = crate::serialization::flatten_sitemap_tree(
            &crate::serialization::build_sitemap_tree(&flows, &std::collections::HashMap::new()),
        )
        .into_iter()
        .map(|host| SitemapLine {
            host: host.host,
            endpoints: host.endpoints,
        })
        .collect();

        Ok(FlowContext {
            steps,
            dependencies,
            sitemap,
        })
    }
}

fn preview_json(
    workflow: Value,
    attempts: usize,
    errors: Vec<String>,
    scope_warnings: Vec<api_tester_workflow::ScopeWarning>,
) -> Value {
    json!({
        "workflow": workflow,
        "attempts": attempts,
        "errors": errors,
        "scope_warnings": scope_warnings,
    })
}

pub(crate) fn strip_code_fences(raw: &str) -> String {
    let trimmed = raw.trim();
    if let Some(rest) = trimmed.strip_prefix("```json") {
        return rest.trim().trim_end_matches("```").trim().to_owned();
    }
    if let Some(rest) = trimmed.strip_prefix("```") {
        return rest.trim().trim_end_matches("```").trim().to_owned();
    }
    trimmed.to_owned()
}

fn truncate_body(body: Option<&str>) -> Option<String> {
    const HEAD_CHARS: usize = 800;
    const TAIL_CHARS: usize = 800;
    let body = body?;
    let trimmed = body.trim();
    if trimmed.is_empty() {
        return None;
    }
    if is_binary_or_hex(trimmed) {
        return None;
    }
    // RSC/Livewire payload streams often CONTAIN html fragments inside their
    // rows; summarizing them as HTML destroys the embedded JSON (and with it
    // every leak the anomaly scanners should catch). Head+tail keeps both.
    if looks_like_html(trimmed) && !is_embedded_payload_stream(trimmed) {
        return Some(summarize_html(trimmed));
    }
    let total = trimmed.chars().count();
    if total <= HEAD_CHARS + TAIL_CHARS {
        return Some(trimmed.to_owned());
    }
    // Keep BOTH ends: leaked secrets routinely sit at the tail of large
    // payloads (e.g. `"password":"..."}],"currentPage":1` at the very end of
    // an RSC stream), so head-only truncation blinded the anomaly scanners.
    let head: String = trimmed.chars().take(HEAD_CHARS).collect();
    let tail: String = trimmed
        .chars()
        .skip(total - TAIL_CHARS)
        .take(TAIL_CHARS)
        .collect();
    Some(format!(
        "{head}\n...[truncated {} chars]...\n{tail}",
        total - HEAD_CHARS - TAIL_CHARS
    ))
}

fn looks_like_html(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    lower.contains("<!doctype") || lower.contains("<html") || lower.contains("<body")
}

/// Embedded framework payload streams: Next.js Flight (script wrapper or raw
/// `id:"..."` rows) and Livewire snapshots. These look like HTML because their
/// rows carry rendered markup, but the valuable content is structured JSON.
fn is_embedded_payload_stream(text: &str) -> bool {
    if text.contains("self.__next_f")
        || text.contains("__NEXT_DATA__")
        || text.contains("wire:snapshot")
    {
        return true;
    }
    // Raw Flight stream: lines like `1:"$Sreact.fragment"` / `3:{...}`.
    text.lines().any(|line| {
        let trimmed = line.trim_start();
        let mut chars = trimmed.chars();
        let starts_digit = chars.next().is_some_and(|c| c.is_ascii_digit());
        starts_digit
            && trimmed
                .find(':')
                .is_some_and(|colon| colon > 0 && colon <= 7)
    })
}

/// Keep semantic HTML signals for AI while dropping scripts, styles and markup.
fn summarize_html(html: &str) -> String {
    use scraper::{Html, Selector};

    let document = Html::parse_document(html);
    let selectors = ["title", "h1", "h2", "h3", "p", "li", "label", "button"];
    let mut parts = Vec::new();
    for selector_text in selectors {
        let Ok(selector) = Selector::parse(selector_text) else {
            continue;
        };
        for element in document.select(&selector) {
            let value = element.text().collect::<Vec<_>>().join(" ");
            let value = value.split_whitespace().collect::<Vec<_>>().join(" ");
            if !value.is_empty() && !parts.contains(&value) {
                parts.push(value);
            }
        }
    }
    if let Ok(selector) = Selector::parse("form") {
        for form in document.select(&selector) {
            let action = form.value().attr("action").unwrap_or("");
            let method = form.value().attr("method").unwrap_or("get");
            if !action.is_empty() {
                parts.push(format!("Form {method} {action}"));
            }
            if let Ok(input_selector) = Selector::parse("input, textarea, select") {
                let fields = form
                    .select(&input_selector)
                    .filter_map(|field| field.value().attr("name"))
                    .collect::<Vec<_>>();
                if !fields.is_empty() {
                    parts.push(format!("Form fields: {}", fields.join(", ")));
                }
            }
        }
    }
    // Next.js often serializes page data in inline React Flight scripts.
    // Keep those data blobs, but ignore external JavaScript bundles.
    if let Ok(selector) = Selector::parse("script:not([src])") {
        for script in document.select(&selector) {
            let value = script.text().collect::<String>();
            if value.contains("self.__next_f.push") || value.contains("__next_f.push") {
                let compact = value.split_whitespace().collect::<Vec<_>>().join(" ");
                if !compact.is_empty() {
                    parts.push(format!("Next.js page data: {compact}"));
                }
            }
        }
    }
    let normalized = parts.join(" | ");
    let mut summary = if normalized.contains("Next.js page data:") {
        summarize_sensitive_html_data(&normalized)
    } else {
        normalized
    };
    if summary.chars().count() > 4000 {
        summary = summary.chars().take(4000).collect();
        summary.push_str(" ...[html summary truncated]");
    }
    summary
}

/// Extract schema and nearby values from large SSR/RSC payloads without sending
/// the entire page dataset to the model.
fn summarize_sensitive_html_data(text: &str) -> String {
    // Do not assume a domain vocabulary. Arbitrary sites can expose useful
    // objects under names such as products, invoices, messages, or records.
    const BUDGET: usize = 3600;
    const SAMPLE_SIZE: usize = 420;
    let compact = text.split_whitespace().collect::<Vec<_>>().join(" ");
    let mut samples = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut offset = 0;
    while offset < compact.len() && samples.len() < 10 {
        let mut end = (offset + SAMPLE_SIZE).min(compact.len());
        while end < compact.len() && !compact.is_char_boundary(end) {
            end += 1;
        }
        let sample = redact_html_data(&compact[offset..end]);
        if !sample.is_empty() && seen.insert(sample.clone()) {
            samples.push(sample);
        }
        if end == compact.len() {
            break;
        }
        offset = end.saturating_sub(80);
        while offset < compact.len() && !compact.is_char_boundary(offset) {
            offset += 1;
        }
    }
    let mut result = format!(
        "HTML data schema/evidence (sampled): {}",
        samples.join(" ... ")
    );
    if result.chars().count() > BUDGET {
        result = result.chars().take(BUDGET).collect();
    }
    result
}

fn redact_html_data(text: &str) -> String {
    let mut output = text.to_owned();
    for key in [
        "password",
        "accessToken",
        "refreshToken",
        "token",
        "secret",
        "authorization",
        "cookie",
    ] {
        let lower = output.to_ascii_lowercase();
        let mut search_from = 0;
        while let Some(found) = lower[search_from..].find(key) {
            let start = search_from + found;
            let tail = &output[start..];
            let Some(colon) = tail.find(':') else { break };
            let value_start = start + colon + 1;
            let value_end = output[value_start..]
                .find([',', '}', ']', '&', ' '])
                .map(|i| value_start + i)
                .unwrap_or(output.len());
            output.replace_range(value_start..value_end, "[REDACTED]");
            search_from = value_start + 10;
        }
    }
    output
}

fn is_binary_or_hex(text: &str) -> bool {
    if text.contains('\0') {
        return true;
    }
    // Hex dump like "00000000  5b ac 10 c4 ..."
    let first_line = text.lines().next().unwrap_or("").trim();
    if first_line.len() >= 10
        && first_line.chars().take(8).all(|c| c.is_ascii_hexdigit())
        && first_line.chars().nth(8) == Some(' ')
        && first_line.chars().nth(9) == Some(' ')
    {
        return true;
    }
    let total = text.chars().count().max(1) as f64;
    let control = text
        .chars()
        .filter(|c| c.is_control() && *c != '\n' && *c != '\r' && *c != '\t')
        .count() as f64;
    control / total > 0.3
}

fn path_without_query(flow: &api_tester_domain::HttpFlow) -> String {
    flow.path.split('?').next().unwrap_or(&flow.path).to_owned()
}

#[cfg(test)]
mod truncate_tests {
    use super::truncate_body;

    #[test]
    fn long_body_keeps_head_and_tail() {
        let mut body = String::from("{\"start\":\"");
        body.push_str(&"a".repeat(5000));
        body.push_str("\",\"password\":\"CNTT66\"}");
        let truncated = truncate_body(Some(&body)).expect("body kept");
        assert!(truncated.contains("[truncated"), "marker present");
        assert!(truncated.ends_with("\"password\":\"CNTT66\"}"), "tail secret preserved: {truncated}");
        assert!(truncated.starts_with("{\"start\":\""), "head preserved");
        assert!(truncated.chars().count() < body.chars().count());
    }

    #[test]
    fn short_body_untouched() {
        assert_eq!(
            truncate_body(Some("{\"id\":1}")).as_deref(),
            Some("{\"id\":1}")
        );
        assert_eq!(truncate_body(Some("   ")), None);
        assert_eq!(truncate_body(None), None);
    }
}

#[cfg(test)]
mod stream_tests {
    use super::{is_embedded_payload_stream, truncate_body};

    #[test]
    fn rsc_stream_is_not_summarized_as_html() {
        let mut body = String::from("1:\"$Sreact.fragment\"\n3:{\"page\":\"contests\",\"html\":\"<html><body>markup</body></html>\"}\n");
        body.push_str(&"x".repeat(6000));
        body.push_str("\n99:{\"password\":\"CNTT66\"}");
        assert!(is_embedded_payload_stream(&body));
        let truncated = truncate_body(Some(&body)).expect("kept");
        assert!(truncated.ends_with("{\"password\":\"CNTT66\"}"));
        assert!(truncated.contains("[truncated"));
    }

    #[test]
    fn plain_html_still_summarized() {
        let html = "<!DOCTYPE html><html><body><h1>Hello</h1><p>World</p></body></html>";
        assert!(!is_embedded_payload_stream(html));
        let summarized = truncate_body(Some(html)).expect("kept");
        assert!(summarized.contains("Hello"));
    }
}