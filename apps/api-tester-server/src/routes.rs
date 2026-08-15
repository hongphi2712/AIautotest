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

use crate::serialization::{FlowFilters, FlowSummary, RepeaterRequest};
use crate::state::AppState;
use crate::ws;

pub type SharedState = Arc<AppState>;

/// Builds the axum router: REST API routes plus the static frontend served for
/// every unmatched path (`fallback_service`), so the UI and API are same-origin.
pub fn router(state: SharedState, ui_dir: String) -> Router {
    Router::new()
        .route("/api/health", get(health))
        .route("/api/flows", get(list_flows))
        .route("/api/flows/{id}", get(flow_detail))
        .route("/api/sessions", get(list_sessions))
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
}

async fn list_flows(
    State(state): State<SharedState>,
    Query(query): Query<FiltersQuery>,
) -> Result<Json<Vec<FlowSummary>>, ApiError> {
    let filters = FlowFilters {
        method: query.method,
        host: query.host,
        q: query.q,
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

async fn list_sessions(State(state): State<SharedState>) -> Result<Json<Value>, ApiError> {
    let sessions = state.list_sessions().await.map_err(fail)?;
    serde_json::to_value(&sessions)
        .map(Json)
        .map_err(|e| fail(e.to_string()))
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
    Ok(Json(
        json!({"running": status.running, "address": status.address}),
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
