# Refactor Plan — API-AutoTester architecture cleanup

Status: in progress (Phase 1-4 planned, keep unwired crates, drop the unused
`api-tester-analysis` dep).

Goals: remove duplication, reuse components, fix suboptimal designs, without
changing existing UI/backend behavior.

## Phase 1 — Unify Inspector into one shared component

Problem: `message-viewer` (HTTP history / Intercept) renders its inspector
sidebar inline via `data-role` targets; the Repeater uses `<inspector-panel>`
with structured `sections`. Two implementations, two builders.

Steps:
1. `ui/js/components/message-viewer.js`
   - Replace the inline `.inspector-sidebar` with `<inspector-panel id="inspector">`
     (import `inspector-panel.js`).
   - `render(data)`: drop `attributes/params/cookies/req-headers-list/resp-headers-list`;
     accept `data.inspectorSections` -> `this.inspector.data = { sections }`.
2. `ui/js/components/history.js` `showDetail` + `ui/js/components/intercept.js`
   `showInterceptDetail`: build a `sections` array (request attributes, query
   params, body params, cookies, request headers, response headers) reusing
   `parseQueryParams` / `parseBodyParams` / `parseCookies`, pass via
   `inspectorSections`.
3. `ui/index.html`: point the inspector sidebar CSS at the `inspector-panel`
   host (already styled for the Repeater); drop the old `.inspector-sidebar`
   rule if unused.

Verify: `node --check`; reload — history/intercept inspector still shows
attributes/params/cookies/headers.

## Phase 2 — Remove dead code

1. `ui/js/api.js`: delete `getExtension`, `parseWireResponse` (unused).
2. `ui/js/shell.js`: remove the `app:proxy-status` dispatch (no listener).
3. `apps/api-tester-server/src-tauri/Cargo.toml`: drop the unused
   `api-tester-analysis` dependency.
4. `ui/js/components/repeater.js`: use `contentTypeFromHeaders` instead of the
   inline `.find()` for content-type.
5. Extract `httpStartLine({ method, url, status, reason })` shared by
   `buildMessage` and `renderHttpWire`.

Verify: `node --check`; `cargo build -p api-tester-server`.

## Phase 3 — `app_health` uses a SQL count

Problem: `app_health` calls `all_flows()` (SQL `list_recent(5000)` + buffer
merge + sort) every 2s just to count.

Steps:
1. `crates/storage/src/sqlite.rs`: add `SqliteFlowRepository::count()`
   (`SELECT COUNT(*) FROM flows`).
2. `apps/api-tester-server/src-tauri/src/commands.rs` `app_health`:
   `flows = max(count(), state.buffer.len())` (handles the just-captured race).

Note: dashboard shows the total; history still lists the recent window
(`list_recent(5000)`).

Verify: `cargo test -p api-tester-storage`; `cargo test --workspace`.

## Phase 4 — Merge duplicated Rust

1. `apps/api-tester-server/src-tauri/src/state.rs` + `commands.rs`: unify
   `AppState::store()` and the free `open_store()` lazy-open helper.
2. `crates/proxy/src/server.rs`: extract `capture_ctx(...)` used by both the
   streaming and buffered response paths (two identical `FlowCaptureCtx`
   constructions).

Verify: `cargo test --workspace`; clippy `-D warnings`; fmt.

## Out of scope (noted, not planned)

- Two HTTP clients (hyper upstream vs reqwest repeater) — different needs.
- Repeater sending through the proxy to auto-capture — a feature, later.
- Unwired crates (`scanner`, `query`, `reporting`, `auth`, `application`) —
  kept for later phases; only the unused `analysis` dep is dropped.
