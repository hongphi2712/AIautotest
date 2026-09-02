use std::sync::Arc;

use axum::Json;
use axum::Router;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use serde::Deserialize;
use serde_json::{Value, json};
use tower_http::services::ServeDir;
use tower_http::set_header::SetResponseHeaderLayer;

use crate::security_service::{
    SecurityApproveRequest, SecurityCancelRequest, SecurityConfirmRequest,
    SecurityGenerateRequest, SecurityRunRequest,
};
use crate::serialization::{FlowFilters, FlowReportRequest, FlowSummary, RepeaterRequest};
use crate::state::AppState;
use crate::workflow_service::{
    WorkflowApproveRequest, WorkflowCancelRequest, WorkflowError, WorkflowGenerateRequest,
    WorkflowRunRequest,
};
use crate::ws;

pub type SharedState = Arc<AppState>;

/// Builds the axum router: REST API routes plus the static frontend served for
/// every unmatched path (`fallback_service`), so the UI and API are same-origin.
pub fn router(state: SharedState, ui_dir: String) -> Router {
    Router::new()
        .route("/api/health", get(health))
        .route("/api/flows", get(list_flows))
        .route("/api/flows/{id}", get(flow_detail))
        .route("/api/flows/clear", post(flows_clear))
        .route("/api/sessions", get(list_sessions))
        .route("/api/sessions/start", post(session_start))
        .route("/api/sessions/stop", post(session_stop))
        .route("/api/sessions/{id}", axum::routing::delete(session_delete))
        .route("/api/sessions/clear", post(sessions_clear))
        .route("/api/proxy/start", post(proxy_start))
        .route("/api/proxy/stop", post(proxy_stop))
        .route("/api/proxy/status", get(proxy_status))
        .route("/api/cert/info", get(cert_info))
        .route("/api/cert/install", post(install_ca))
        .route("/api/browser/open", post(open_browser))
        .route("/api/repeater/send", post(repeater_send))
        .route("/api/intercept/enabled", post(intercept_set_enabled))
        .route("/api/intercept/scopes", post(intercept_set_scopes))
        .route("/api/intercept/status", get(intercept_status))
        .route("/api/intercept/list", get(intercept_list))
        .route("/api/intercept/{id}", get(intercept_detail))
        .route("/api/intercept/{id}/forward", post(intercept_forward))
        .route("/api/intercept/{id}/drop", post(intercept_drop))
        .route("/api/intercept/clear", post(intercept_clear))
        .route("/api/analyze/flow", post(analyze_flow))
        .route("/api/sitemap", get(sitemap))
        .route("/api/scope", get(scope).put(update_scope))
        .route("/api/security/scope", get(security_scope).put(update_security_scope))
        .route(
            "/api/sitemap/annotations",
            axum::routing::put(sitemap_upsert_annotation).delete(sitemap_delete_annotation),
        )
        .route("/api/config/reload", post(reload_config))
        .route("/api/ai/config", get(ai_status).put(update_ai_config))
        .route("/api/ai/models", get(ai_models_list))
        .route("/api/ai/prompt-preview", get(ai_prompt_preview))
        .route("/api/ai/flow-summary", post(ai_flow_summary))
        .route("/api/workflow/generate", post(workflow_generate))
        .route("/api/workflow/approve", post(workflow_approve))
        .route("/api/workflow/run", post(workflow_run))
        .route("/api/workflow/cancel", post(workflow_cancel))
        .route("/api/workflows", get(workflows_list))
        .route("/api/workflow/{id}", get(workflow_detail))
        .route("/api/security/generate", post(security_generate))
        .route("/api/security/approve", post(security_approve))
        .route("/api/security/run", post(security_run))
        .route("/api/security/cancel", post(security_cancel))
        .route("/api/security/confirm", post(handle_security_confirm))
        .route("/api/security/plans", get(security_list))
        .route("/api/security/plan/{id}", get(security_detail))
        .route("/api/flows/debug", get(flows_debug))
        .route("/ws", get(ws::ws_handler))
        .fallback_service(ServeDir::new(ui_dir))
        // Never cache the UI/JS so the browser always loads the latest modules
        // (avoids stale-import errors like `invoke` after a Tauri->REST
        // migration); the static UI is small and served locally.
        .layer(SetResponseHeaderLayer::overriding(
            axum::http::header::CACHE_CONTROL,
            axum::http::HeaderValue::from_static("no-store"),
        ))
        .with_state(state)
}

type ApiError = (StatusCode, Json<Value>);

fn fail(message: impl Into<String>) -> ApiError {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({ "error": message.into() })),
    )
}

async fn health(State(state): State<SharedState>) -> Result<Json<Value>, ApiError> {
    state.app_health().await.map(Json).map_err(fail)
}

#[derive(Deserialize)]
struct FiltersQuery {
    method: Option<String>,
    host: Option<String>,
    q: Option<String>,
    session_id: Option<String>,
}

async fn list_flows(
    State(state): State<SharedState>,
    Query(query): Query<FiltersQuery>,
) -> Result<Json<Vec<FlowSummary>>, ApiError> {
    let filters = FlowFilters {
        method: query.method,
        host: query.host,
        q: query.q,
        session_id: query.session_id,
    };
    let flows = state.list_flows(&filters).await.map_err(fail)?;
    Ok(Json(flows))
}

async fn flow_detail(
    State(state): State<SharedState>,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let flow = state.flow_detail(&id).await.map_err(fail)?;
    serde_json::to_value(&flow)
        .map(Json)
        .map_err(|e| fail(e.to_string()))
}

async fn flows_clear(State(state): State<SharedState>) -> Result<Json<Value>, ApiError> {
    state.clear_logs().await.map_err(fail)?;
    Ok(Json(json!({"ok": true})))
}

async fn list_sessions(State(state): State<SharedState>) -> Result<Json<Value>, ApiError> {
    let sessions = state.list_sessions().await.map_err(fail)?;
    serde_json::to_value(&sessions)
        .map(Json)
        .map_err(|e| fail(e.to_string()))
}

#[derive(Deserialize)]
struct SessionStartRequest {
    #[serde(default = "default_session_name")]
    name: String,
    #[serde(default)]
    target_host: String,
}

fn default_session_name() -> String {
    "capture".to_owned()
}

async fn session_start(
    State(state): State<SharedState>,
    Json(body): Json<SessionStartRequest>,
) -> Result<Json<Value>, ApiError> {
    let session = state
        .start_session(body.name, body.target_host)
        .await
        .map_err(fail)?;
    Ok(Json(json!({
        "session_id": session.id,
        "name": session.name,
        "target_host": session.target_host,
        "start_time": session.start_time.to_rfc3339(),
    })))
}

async fn session_stop(State(state): State<SharedState>) -> Result<Json<Value>, ApiError> {
    state.stop_session().await.map_err(fail)?;
    Ok(Json(json!({"ok": true})))
}

async fn session_delete(
    State(state): State<SharedState>,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    state.delete_session(&id).await.map_err(fail)?;
    Ok(Json(json!({"ok": true})))
}

async fn sessions_clear(State(state): State<SharedState>) -> Result<Json<Value>, ApiError> {
    state.clear_all_sessions().await.map_err(fail)?;
    Ok(Json(json!({"ok": true})))
}
async fn proxy_start(State(state): State<SharedState>) -> Result<Json<Value>, ApiError> {
    state
        .start_proxy()
        .await
        .map(|s| Json(json!({"running": s.running, "address": s.address})))
        .map_err(fail)
}

async fn proxy_stop(State(state): State<SharedState>) -> Result<Json<Value>, ApiError> {
    state
        .stop_proxy()
        .await
        .map(|s| Json(json!({"running": s.running, "address": s.address})))
        .map_err(fail)
}

async fn proxy_status(State(state): State<SharedState>) -> Result<Json<Value>, ApiError> {
    let status = state.proxy_status();
    let session_id = state.active_session().await;
    Ok(Json(
        json!({"running": status.running, "address": status.address, "session_id": session_id}),
    ))
}

async fn cert_info(State(state): State<SharedState>) -> Result<Json<Value>, ApiError> {
    let info = state.cert_info();
    Ok(Json(
        json!({"path": info.path, "exists": info.exists, "installed": info.installed}),
    ))
}

async fn install_ca(State(state): State<SharedState>) -> Result<Json<Value>, ApiError> {
    let info = state.install_ca().map_err(fail)?;
    Ok(Json(
        json!({"path": info.path, "exists": info.exists, "installed": info.installed}),
    ))
}

async fn open_browser(State(state): State<SharedState>) -> Result<Json<Value>, ApiError> {
    state.open_browser().await.map_err(fail)?;
    Ok(Json(json!({"ok": true})))
}

async fn repeater_send(
    State(state): State<SharedState>,
    Json(request): Json<RepeaterRequest>,
) -> Result<Json<Value>, ApiError> {
    let response = state.repeater_send(request).await.map_err(fail)?;
    Ok(Json(
        json!({"status": response.status, "length": response.length, "body": response.body, "headers": response.headers}),
    ))
}

#[derive(Deserialize)]
struct EnabledBody {
    enabled: bool,
}

async fn intercept_set_enabled(
    State(state): State<SharedState>,
    Json(body): Json<EnabledBody>,
) -> Result<Json<Value>, ApiError> {
    state.intercept_set_enabled(body.enabled).map_err(fail)?;
    Ok(Json(json!({"ok": true})))
}

#[derive(Deserialize)]
struct ScopesBody {
    intercept_requests: bool,
    intercept_responses: bool,
}

async fn intercept_set_scopes(
    State(state): State<SharedState>,
    Json(body): Json<ScopesBody>,
) -> Result<Json<Value>, ApiError> {
    state
        .intercept_set_scopes(body.intercept_requests, body.intercept_responses)
        .map_err(fail)?;
    Ok(Json(json!({"ok": true})))
}

async fn intercept_status(State(state): State<SharedState>) -> Result<Json<Value>, ApiError> {
    state.intercept_status().map(Json).map_err(fail)
}

async fn intercept_list(State(state): State<SharedState>) -> Result<Json<Value>, ApiError> {
    let list = state.intercept_list().map_err(fail)?;
    serde_json::to_value(&list)
        .map(Json)
        .map_err(|e| fail(e.to_string()))
}

async fn intercept_detail(
    State(state): State<SharedState>,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let entry = state.intercept_detail(&id).map_err(fail)?;
    serde_json::to_value(&entry)
        .map(Json)
        .map_err(|e| fail(e.to_string()))
}

#[derive(Deserialize)]
struct ForwardBody {
    edit: Option<api_tester_proxy::InterceptEdit>,
}

async fn intercept_forward(
    State(state): State<SharedState>,
    Path(id): Path<String>,
    Json(body): Json<ForwardBody>,
) -> Result<Json<Value>, ApiError> {
    let ok = state.intercept_forward(&id, body.edit).map_err(fail)?;
    Ok(Json(json!({"ok": ok})))
}

async fn intercept_drop(
    State(state): State<SharedState>,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let ok = state.intercept_drop(&id).map_err(fail)?;
    Ok(Json(json!({"ok": ok})))
}

async fn intercept_clear(State(state): State<SharedState>) -> Result<Json<Value>, ApiError> {
    state.intercept_clear().map_err(fail)?;
    Ok(Json(json!({"ok": true})))
}

#[derive(Deserialize)]
struct AnalyzeFlowBody {
    #[serde(default)]
    format: String,
    #[serde(default)]
    mode: Option<String>,
}

async fn analyze_flow(
    State(state): State<SharedState>,
    Json(body): Json<AnalyzeFlowBody>,
) -> Result<Json<Value>, ApiError> {
    let request = FlowReportRequest {
        format: body.format,
        mode: body.mode,
    };
    let report = state.flow_report(request).await.map_err(fail)?;
    serde_json::to_value(&report)
        .map(Json)
        .map_err(|error| fail(error.to_string()))
}

async fn sitemap(
    State(state): State<SharedState>,
    Query(query): Query<SitemapQuery>,
) -> Result<Json<Value>, ApiError> {
    let hosts = state.sitemap(query.session_id).await.map_err(fail)?;
    serde_json::to_value(&hosts)
        .map(Json)
        .map_err(|error| fail(error.to_string()))
}

#[derive(Deserialize)]
struct SitemapQuery {
    session_id: Option<String>,
}

async fn scope(State(state): State<SharedState>) -> Result<Json<Value>, ApiError> {
    let scope = state.scope().map_err(fail)?;
    serde_json::to_value(&scope)
        .map(Json)
        .map_err(|error| fail(error.to_string()))
}

#[derive(Debug, Deserialize)]
struct ScopeUpdateRequest {
    #[serde(default)]
    include_hosts: Option<Vec<String>>,
    #[serde(default)]
    exclude_hosts: Option<Vec<String>>,
    #[serde(default)]
    include_paths: Option<Vec<String>>,
    #[serde(default)]
    exclude_paths: Option<Vec<String>>,
}

async fn update_scope(
    State(state): State<SharedState>,
    Json(request): Json<ScopeUpdateRequest>,
) -> Result<Json<Value>, ApiError> {
    let scope = state
        .update_scope(
            request.include_hosts,
            request.exclude_hosts,
            request.include_paths,
            request.exclude_paths,
        )
        .await
        .map_err(fail)?;
    serde_json::to_value(&scope)
        .map(Json)
        .map_err(|error| fail(error.to_string()))
}

async fn security_scope(State(state): State<SharedState>) -> Result<Json<Value>, ApiError> {
    let scope = state.security_scope().map_err(fail)?;
    serde_json::to_value(&scope)
        .map(Json)
        .map_err(|error| fail(error.to_string()))
}

async fn update_security_scope(
    State(state): State<SharedState>,
    Json(request): Json<ScopeUpdateRequest>,
) -> Result<Json<Value>, ApiError> {
    let scope = state
        .update_security_scope(
            request.include_hosts,
            request.exclude_hosts,
            request.include_paths,
            request.exclude_paths,
        )
        .await
        .map_err(fail)?;
    serde_json::to_value(&scope)
        .map(Json)
        .map_err(|error| fail(error.to_string()))
}

#[derive(Debug, Deserialize)]
struct SitemapAnnotationRequest {
    key: String,
    #[serde(default)]
    comment: Option<String>,
    #[serde(default)]
    color: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AiConfigUpdate {
    #[serde(default)]
    api_key: Option<String>,
    #[serde(default)]
    base_url: Option<String>,
    #[serde(default)]
    model: Option<String>,
    #[serde(default)]
    max_tokens: Option<u32>,
    #[serde(default)]
    timeout_secs: Option<u64>,
}

async fn sitemap_upsert_annotation(
    State(state): State<SharedState>,
    Json(request): Json<SitemapAnnotationRequest>,
) -> Result<Json<Value>, ApiError> {
    state
        .sitemap_upsert_annotation(request.key, request.comment, request.color)
        .await
        .map_err(fail)?;
    Ok(Json(json!({"ok": true})))
}

async fn sitemap_delete_annotation(
    State(state): State<SharedState>,
    Json(request): Json<SitemapAnnotationRequest>,
) -> Result<Json<Value>, ApiError> {
    state
        .sitemap_delete_annotation(request.key)
        .await
        .map_err(fail)?;
    Ok(Json(json!({"ok": true})))
}

async fn ai_status(State(state): State<SharedState>) -> Result<Json<Value>, ApiError> {
    Ok(Json(state.ai_status()))
}

async fn ai_prompt_preview(State(state): State<SharedState>) -> Result<Json<Value>, ApiError> {
    let preview = state.ai_prompt_preview().await.map_err(fail)?;
    Ok(Json(preview))
}

#[derive(Deserialize)]
struct FlowSummaryQuery {
    model: Option<String>,
}

async fn ai_flow_summary(
    State(state): State<SharedState>,
    Query(query): Query<FlowSummaryQuery>,
) -> Result<Json<Value>, ApiError> {
    let summary = state.ai_flow_summary(query.model).await.map_err(fail)?;
    Ok(Json(json!({ "summary": summary })))
}

async fn update_ai_config(
    State(state): State<SharedState>,
    Json(body): Json<AiConfigUpdate>,
) -> Result<Json<Value>, ApiError> {
    let result = state
        .update_ai_config(
            body.api_key,
            body.base_url,
            body.model,
            body.max_tokens,
            body.timeout_secs,
        )
        .await
        .map_err(fail)?;
    Ok(Json(result))
}

async fn ai_models_list(State(state): State<SharedState>) -> Result<Json<Value>, ApiError> {
    let models = state.ai_models_list().await.map_err(fail)?;
    Ok(Json(models))
}

async fn reload_config(State(state): State<SharedState>) -> Result<Json<Value>, ApiError> {
    let cfg = state.reload_config().await.map_err(fail)?;
    Ok(Json(cfg))
}

fn workflow_error(error: WorkflowError) -> ApiError {
    let status = match &error {
        WorkflowError::BadRequest(_) => StatusCode::BAD_REQUEST,
        WorkflowError::NotFound(_) => StatusCode::NOT_FOUND,
        WorkflowError::ScopeConflict(_) => StatusCode::CONFLICT,
        WorkflowError::Storage(_) => StatusCode::INTERNAL_SERVER_ERROR,
    };
    (status, Json(json!({ "error": error.to_string() })))
}

async fn workflow_generate(
    State(state): State<SharedState>,
    Json(body): Json<WorkflowGenerateRequest>,
) -> Result<Json<Value>, ApiError> {
    let result = state
        .workflow_generate(body)
        .await
        .map_err(workflow_error)?;
    Ok(Json(result))
}

async fn workflow_approve(
    State(state): State<SharedState>,
    Json(body): Json<WorkflowApproveRequest>,
) -> Result<Json<Value>, ApiError> {
    let result = state.workflow_approve(body).await.map_err(workflow_error)?;
    Ok(Json(result))
}

async fn workflow_run(
    State(state): State<SharedState>,
    Json(body): Json<WorkflowRunRequest>,
) -> Result<Json<Value>, ApiError> {
    let result = state.workflow_run(body).await.map_err(workflow_error)?;
    Ok(Json(result))
}

async fn workflow_cancel(
    State(state): State<SharedState>,
    Json(body): Json<WorkflowCancelRequest>,
) -> Result<Json<Value>, ApiError> {
    state.workflow_cancel(body).await.map_err(workflow_error)?;
    Ok(Json(json!({ "ok": true })))
}

async fn workflows_list(State(state): State<SharedState>) -> Result<Json<Value>, ApiError> {
    let result = state.workflow_list().await.map_err(workflow_error)?;
    Ok(Json(result))
}

async fn workflow_detail(
    State(state): State<SharedState>,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let result = state.workflow_detail(&id).await.map_err(workflow_error)?;
    Ok(Json(result))
}

async fn security_generate(
    State(state): State<SharedState>,
    Json(body): Json<SecurityGenerateRequest>,
) -> Result<Json<Value>, ApiError> {
    let result = state
        .security_generate(body)
        .await
        .map_err(workflow_error)?;
    Ok(Json(result))
}

async fn security_approve(
    State(state): State<SharedState>,
    Json(body): Json<SecurityApproveRequest>,
) -> Result<Json<Value>, ApiError> {
    let result = state.security_approve(body).await.map_err(workflow_error)?;
    Ok(Json(result))
}

async fn security_run(
    State(state): State<SharedState>,
    Json(body): Json<SecurityRunRequest>,
) -> Result<Json<Value>, ApiError> {
    let result = state.security_run(body).await.map_err(workflow_error)?;
    Ok(Json(result))
}

async fn security_cancel(
    State(state): State<SharedState>,
    Json(body): Json<SecurityCancelRequest>,
) -> Result<Json<Value>, ApiError> {
    state.security_cancel(body).await.map_err(workflow_error)?;
    Ok(Json(json!({"ok": true})))
}

async fn handle_security_confirm(
    State(state): State<SharedState>,
    Json(body): Json<SecurityConfirmRequest>,
) -> Result<Json<Value>, ApiError> {
    state.security_confirm(body.run_id, body.test_id, body.approved)
        .await
        .map_err(workflow_error)?;
    Ok(Json(json!({"ok": true})))
}

async fn security_list(State(state): State<SharedState>) -> Result<Json<Value>, ApiError> {
    let result = state.security_list().await.map_err(workflow_error)?;
    Ok(Json(result))
}

async fn security_detail(
    State(state): State<SharedState>,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let result = state.security_detail(&id).await.map_err(workflow_error)?;
    Ok(Json(result))
}

async fn flows_debug(
    State(state): State<SharedState>,
    Query(query): Query<FiltersQuery>,
) -> Result<Json<Value>, ApiError> {
    // Raw flows with session_id for strict CI debugging (bypasses FlowSummary stripping)
    let sid_opt = query.session_id.clone();
    let flows = if let Some(sid) = sid_opt.clone() {
        state.flows_for_session(&sid, 100).await
    } else {
        state.full_flows_for_analysis(100).await
    };
    let debug: Vec<Value> = flows
        .iter()
        .map(|f| {
            json!({
                "id": f.id.to_string(),
                "session_id": f.session_id,
                "method": format!("{:?}", f.method),
                "host": f.host,
                "path": f.path,
                "status": f.response_status,
                "session_match": sid_opt.as_deref().map(|sid| f.session_id == sid).unwrap_or(true)
            })
        })
        .collect();
    Ok(Json(json!({"flows": debug, "count": debug.len()})))
}
