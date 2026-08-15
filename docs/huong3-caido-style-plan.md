# Plan Hướng 3 (Caido-style): Tauri → axum + REST + WebSocket + launcher

Status: in progress (P1). Confirmed: web `127.0.0.1:2712`, crate at
`apps/api-tester-server/`, keep 2s poll fallback alongside WebSocket real-time.

Goal: drop Tauri/WebView2 (RAM ~340MB) and serve the existing HTML/JS UI from a
lightweight axum server, matching how Caido (Rust + browser UI) works. The Rust
backend (proxy, intercept, storage, cert) is reused unchanged.

## Architecture

```
Browser (user's default) — opened by the launcher
   │  open::that("http://127.0.0.1:2712")
   ▼
axum server @ 127.0.0.1:2712
   ├─ GET /*          ServeDir("ui/")            (HTML/CSS/JS, unchanged)
   ├─ /api/*          REST JSON                  (one-shot commands)
   └─ /ws             WebSocket                  (real-time flow/proxy/intercept)
state.rs · backend.rs · serialization.rs · dashboard.rs · http_client.rs
Proxy MITM @ 127.0.0.1:8080  (unchanged: cert / CRL / scope / intercept)
```

## B0 — Snapshot
- Commit + push current state (done: `760dbf5`).

## P1 — Scaffold axum + static + launcher
- `apps/api-tester-server/Cargo.toml` (new): package `api-tester-server`;
  deps `axum`, `tower-http`(fs), `futures-util`, `tokio`(full), `open`,
  `serde`, `serde_json` + workspace crates. Remove `tauri`/`tauri-build`
  from workspace; change member `apps/api-tester-server/src-tauri` →
  `apps/api-tester-server`.
- `src/main.rs`: ConfigLoader → AppState::new → bind 127.0.0.1:2712 →
  `open::that("http://127.0.0.1:2712")` → axum::serve.
- `src/routes.rs`: `ServeDir` (ui path via CARGO_MANIFEST_DIR) + `GET /api/health`.
- Move verbatim from `src-tauri/src/`: `state.rs`, `serialization.rs`,
  `dashboard.rs`, `http_client.rs`.

## P2 — Full REST API
- `src/backend.rs`: `impl AppState` async methods (ex-commands, drop
  `#[tauri::command]`/`State`; keep all logic).
- `src/routes.rs` endpoint map:

| Old command | Endpoint |
|---|---|
| app_health | GET /api/health |
| list_flows | GET /api/flows?method=&host=&q= |
| flow_detail | GET /api/flows/{id} |
| list_sessions | GET /api/sessions |
| start_proxy / stop_proxy | POST /api/proxy/start · /stop |
| proxy_status | GET /api/proxy/status |
| cert_info / install_ca | GET /api/cert/info · POST /api/cert/install |
| open_browser | POST /api/browser/open |
| repeater_send | POST /api/repeater/send |
| intercept_set_enabled / scopes | POST /api/intercept/enabled · /scopes |
| intercept_status / list | GET /api/intercept/status · /list |
| intercept_detail | GET /api/intercept/{id} |
| intercept_forward / drop / clear | POST /api/intercept/{id}/forward · /{id}/drop · /clear |

- Handlers: `State<Arc<AppState>>`, JSON via existing serde structs.

## P3 — Frontend invoke → fetch
- `ui/js/api.js`: replace `window.__TAURI__.core.invoke` with
  `api(path, opts)` / `apiPost(path, body)` (fetch JSON).
- Update all 22 call sites: shell.js(2), history.js(2), intercept.js(9),
  proxy-settings.js(5), repeater.js(1), sidebar.js(2). Logic unchanged.
- No npm package in ui/ — coupling is only the global `invoke`.

## P4 — WebSocket real-time (keep 2s poll fallback)
- `src/ws.rs`: `WsMessage` serde enum {Flow(FlowSummary), Intercept, Proxy,
  Health}; `AppState.ws_tx: Arc<broadcast::Sender<WsMessage>>`; route `GET /ws`.
- `dashboard.rs`: DashboardSink gets `ws_tx`; publish Flow on push; proxy
  start/stop → Proxy; intercept change → Intercept.
- `ui/js/ws.js`: WS client → `app:ws-*` events → history prepend + count,
  intercept live re-render, proxy pill live.
- Fallback stays: 2s `list_flows`+`app_health` poll; 1s intercept poll.

## P5 — Cleanup + release + measure
- Delete `src-tauri/`, `package.json`, `package-lock.json`, `node_modules/`,
  `scripts/`, `tauri.conf.json`; clean workspace Cargo.toml + .gitignore.
- `cargo test --workspace` + clippy -D warnings + fmt + node --check.
- Build release → measure exe MB + runtime RAM (no WebView2).
- Update docs.

## Verify per phase
- P1: cargo run → browser opens 2712, UI renders, /api/health JSON.
- P2: curl each endpoint.
- P3: full UI via browser.
- P4: browse → flow appears instantly; intercept live; proxy pill live.
- P5: 223 backend tests, clippy, manual full flow, exe/RAM.

## Done (results)
- P1–P4 committed (953a323, e1a2be3). Tauri removed; axum + REST + WebSocket.
- P5: npm/node tooling deleted; .gitignore cleaned.
- Release build: **102 crates, 189s** (was 348 crates/464s with Tauri).
- Exe: **11.1 MB** (was 17.4 MB).
- Runtime RAM (app process only): **~8 MB** (was ~380 MB incl. WebView2); UI runs in
  the user's browser, so no embedded Chromium.
- WS real-time verified: curl through the proxy captured a flow and the browser
  WebSocket received it instantly (flows 1545 → 1546).

