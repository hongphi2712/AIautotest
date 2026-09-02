# Plan Dự Án Lớn — CRAPI-4 Fix Session Wiring Option A (ProxyServer Supplier)

> **Epic:** CRAPI-SEC | **Story:** CRAPI-4 — AI Plan Generation via cliproxy `glm53` (P1, 30m) — mở rộng 45m khi gộp fix wiring  
> **Ngày tạo:** 2026-09-01 | **Trạng thái:** Build Mode — Lưu plan + Triển khai  
> **Stack:** `crates/proxy/src/server.rs:1059` MITM, `crates/capture`, `apps/api-tester-server/src/state.rs:54` + `backend.rs:1106`, `crates/domain/src/scope.rs`, `crates/storage/src/sqlite.rs`  
> **Tài liệu liên quan:** `docs/security-crapi-playwright-direct-plan.md:1` (Jira board), `docs/crapi-deferred-labs.md:1`, `docs/security-crapi-plan.md:1`

---

## 1. Tổng Quan Dự Án Lớn

### 1.1 Bối Cảnh & Vấn Đề

* **Hiện trạng đã verify:** `docker compose --compatibility up -d` 11 containers healthy, `crapi-web 8888`, `chatbot 5500`, `cliproxy 8317 glm53` OK (`node fetch` `glm-5.3`), `AnToanAI Proxy 8080` running. Playwright direct (`helpers/crapi.ts:10` fallback `useProxy=false`) cho labs pass 8/7/0, nhưng flows không qua proxy nên `GET /api/flows?session_id=` và `POST /api/security/generate use_traffic:true` rỗng.
* **Root cause wiring:** `ProxyServer::start` `server.rs:357` luôn tạo `ActiveSession::start("capture")` riêng, `FlowBuilder::new(session.id)` `server.rs:233`, trong khi `AppState.active_session_id` `state.rs:54` là source of truth cho UI. `DashboardSink` `dashboard.rs:56` chỉ persist `flow.session_id` nhận được — mismatch khiến `list_by_session` `sqlite.rs:247` và `buffer.snapshot().filter` `backend.rs:71` trả rỗng.
* **Tác động:** CRAPI-4 block, `build_ai_context` `workflow_service.rs:472` trả `steps:[]` → AI plan generic, không cover crAPI labs. Không ảnh hưởng `full_flows_for_analysis` (global) nhưng sai hoàn toàn session-scoped.

### 1.2 Mục Tiêu

* Mọi flow qua proxy dù `http://127.0.0.1:8888` hay `CONNECT` đều mang `flow.session_id == AppState.active_session_id` khi có session, fallback `capture` khi chưa có session (backward compat).
* `GET /api/flows?session_id=<id>` và `GET /api/sitemap?session_id=<id>` trả đúng isolation, `POST /api/security/generate {use_traffic:true, session_id}` sinh plan session-specific.
* Không phá `GET /api/flows` (no param) global, không phá `proxy/tests`, không thêm dep.

### 1.3 Phạm Vi (Scope)

* **In scope:** CRAPI-4 + fix wiring Option A (ProxyServer supplier strict gate). 2 files proxy + 1 backend.
* **Out of scope:** CRAPI-8 prompt adapt (`_rsc` → `mass_exposure`), CRAPI-6 Repeater cross-check, DEFERRED labs (6 labs `test.skip`).
* **Không thay đổi:** `DashboardSink`, `FlowBuilder` API, `SessionRepository`, `Cargo` deps, `config.json` scope (đã có `127.0.0.1`).

---

## 2. Kiến Trúc

### 2.1 Kiến Trúc Hiện Tại (Trước Fix)

```
AppState.start_session() → id_A → active_session_id=Some(id_A) → store.sessions.save
ProxyServer.start()      → id_capture (random) → session=Some(ActiveSession(id_capture))
spawn_capture()          → FlowBuilder::new(id_capture) → flow.session_id=id_capture → DashboardSink.save → buffer
GET /api/flows?session_id=id_A → list_by_session(id_A) → 0 + buffer.filter(id_A) → 0
```

### 2.2 Kiến Trúc Mục Tiêu (Sau Fix — Option A Strict Gate)

```
AppState.active_session_id ──Arc<Mutex<Option<String>>>──► ProxyServer.session_id_source
                                                          │
ProxyServer.start() ──gate──► if source.is_none() → create capture else None
spawn_capture() (tokio::spawn) ──► lock supplier.clone() ──► if Some(id) → FlowBuilder::new(id) else fallback capture
TeeBody.finalize() ──► spawn_capture(session, session_id_source, ...)
Intercept buffered ──► spawn_capture(session, session_id_source, ...)
```

* **Strict gate:** `source.is_some()` → không tạo orphan row, flows trước `start_session` sẽ drop (hiếm, chấp nhận). **Nới (alternative):** chỉ gate khi `supplier.is_none()` theo `src.lock().await.is_none()` — giữ pre-session buffer.

### 2.3 Component Diagram

```
[AppState] ──active_session_id──► [ProxyServer] ──► [TeeBody] ──► [spawn_capture] ──► [FlowBuilder] ──► [DashboardSink] ──► [SQLite + RingBuffer]
                │                         │                │                     │
                │                         │                └─ session_id_source ──┘
                │                         └─ session (fallback orphan)
                └─ build_proxy() .with_session_id_source(clone)
```

---

## 3. Phân Tích Chi Tiết (Large Project)

### 3.1 RACI

| Role | Người | Trách nhiệm |
|---|---|---|
| Owner | AI | Implement + verify |
| Reviewer | User | Duyệt plan + test manual curl |
| Stakeholder | crAPI lab | Không ảnh hưởng DEFERRED |

### 3.2 Work Breakdown Structure (WBS)

| WBS | Task | File:Line | Est | Priority |
|---|---|---|---|---|
| 3.1 | Thêm field `session_id_source` + init `None` | `server.rs:84-102`, `server.rs:319` | 5m | P0 |
| 3.2 | Thêm builder `with_session_id_source` | `server.rs:341-351` cạnh `with_intercept` | 5m | P0 |
| 3.3 | Mở rộng `TeeBody` field + `new`/`finalize` | `server.rs:163-227` | 5m | P0 |
| 3.4 | Refactor `spawn_capture` 6 args + supplier-first lock | `server.rs:233-267` | 10m | P0 |
| 3.5 | Gate orphan trong `start()` | `server.rs:357-378` | 5m | P0 |
| 3.6 | Sửa `intercept` buffered + streaming branches | `server.rs:814-883` | 5m | P0 |
| 3.7 | Wire `backend.rs:build_proxy` | `backend.rs:1106` | 2m | P0 |
| 3.8 | Verify (cargo + curl + playwright) | — | 10m | P0 |

**Tổng:** ~45m (30m CRAPI-4 + 15m fix wiring).

### 3.3 Milestones & Deliverables

| Milestone | Deliverable | Tiêu chí Done |
|---|---|---|
| M1 | Code fix | `cargo check -p api-tester-proxy -p api-tester-server` pass |
| M2 | Unit + proxy tests | `cargo test --workspace` proxy 7, storage 10, capture 6 xanh |
| M3 | E2E capture | `curl -x 8080` 3 flows → `GET /api/flows?session_id=` ≥3, `sitemap` có tree |
| M4 | AI generate | `POST /api/security/generate {glm53, use_traffic:true, session_id}` → plan 4-8 tests, `errors []` |
| M5 | Board | `docs/security-crapi-playwright-direct-plan.md:108` CRAPI-4 ✅ Done, burndown 5/9 |

### 3.4 Rủi Ro & Mitigation (Risk Register)

| # | Rủi ro | Xác suất | Impact | Mitigation |
|---|---|---|---|---|
| R1 | Lock `Mutex` trong `spawn_capture` giữ qua `await` | Thấp | Deadlock | Clone `Option<String>` dưới lock rồi drop ngay trước `FlowBuilder::capture().await` |
| R2 | Orphan gate drop pre-session flows | Thấp | Mất 1-2 flows trước `start_session` | Chấp nhận (strict) hoặc nới thành `is_none()` check |
| R3 | `record_flow` sai session → `flow_count` lệch | Thấp | UI list `flow_count` sai | Gate `if !is_supplied { record_flow }`, đã có trong pseudocode |
| R4 | `ProxyServer::new` signature break → tests fail | Thấp | CI đỏ | Dùng builder additive, không đổi 7-arg `new()` |
| R5 | Cliproxy `glm53` down | Trung bình | `generate` 500 | Fallback `use_traffic:false` plan generic, đã note |

### 3.5 Giả Định & Ràng Buộc

* `tokio::sync::Mutex` đã có `sync` feature (`Cargo.toml:83`), không thêm dep.
* `state.active_session_id` luôn `Some` sau `POST /api/sessions/start` trước khi traffic.
* Playwright vẫn dùng `useProxy=false` cho labs direct — capture riêng bằng `curl -x` cho CRAPI-4.

---

## 4. Thiết Kế Chi Tiết (Option A)

### 4.1 Field & Init

```rust
// server.rs:84
session_id_source: Option<Arc<tokio::sync::Mutex<Option<String>>>>,
// new():319
session: Arc::new(Mutex::new(None)),
session_id_source: None,
```

### 4.2 Builder

```rust
pub fn with_session_id_source(mut self, source: Arc<tokio::sync::Mutex<Option<String>>>) -> Self {
    self.session_id_source = Some(source); self
}
```

### 4.3 TeeBody

```rust
struct TeeBody { ..., session_id_source: Option<Arc<...>>, }
fn new(..., session_id_source: Option<...>, ctx) -> Self { ... }
fn finalize(&mut self) { spawn_capture(self.session.clone(), self.session_id_source.clone(), ...) }
```

### 4.4 spawn_capture (6 args)

```rust
fn spawn_capture(session, session_id_source, sink, max, ctx, body) {
  tokio::spawn(async move {
    let supplied = if let Some(src)=&session_id_source { src.lock().await.clone() } else { None };
    let (id, is_supplied) = match supplied { Some(s) if !s.trim().is_empty() => (s,true),
      _ => { let g=session.lock().await; let Some(a)=g.as_ref() else {return}; (a.id().to_owned(),false) } };
    let builder = FlowBuilder::new(id, sink, max);
    if builder.capture(parts).await.is_ok() && !is_supplied { session.lock().await.as_ref().unwrap().record_flow().await; }
  });
}
```

### 4.5 Gate Orphan

```rust
// start()
let should_create = self.session_id_source.is_none();
if should_create { ActiveSession::start(...) } else { *self.session.lock().await=None; }
```

### 4.6 Wire

```rust
// backend.rs:1106
ProxyServer::new(...).with_session_id_source(state.active_session_id.clone()).with_intercept(...)
```

---

## 5. Kế Hoạch Triển Khai

### 5.1 Thứ Tự

1. `server.rs` field/init/builder (3.1-3.2) → `TeeBody` (3.3) → `spawn_capture` (3.4) → gate (3.5) → branches (3.6) → `backend.rs` (3.7).
2. Mỗi bước `cargo check` riêng.

### 5.2 Verify (từ checklist read-only)

* **Flows theo session:** `POST /api/sessions/start` → `session_id_4` → `curl -x 8080` 3 flows → `GET /api/flows?session_id=session_id_4` ≥3 (trước fix 0), `GET /api/sitemap?session_id` có tree.
* **Isolation:** Tạo `session_id_B` → traffic mới không lẫn `session_id_4`.
* **Global:** `GET /api/flows` (no param) = A+B, không regression.
* **Generate:** `POST /api/security/generate {use_traffic:true, session_id_4, model:"glm53"}` → plan 4-8 tests, `steps` chứa `identity`/`community` của session đó (trước fix `steps:[]`).
* **Playwright:** `npx playwright test --list` 15 tests, `baseline` 1 passed, `direct` 7 passed/7 skipped giữ nguyên.
* **Unit:** `cargo test --workspace` + `cargo test -p api-tester-server --lib` xanh.

### 5.3 Rollback

* Revert 2 files (`server.rs`, `backend.rs`) → `session_id_source=None` fallback về orphan path cũ. `DashboardSink` không cần revert.

---

## 6. Tiến Độ Jira (sau CRAPI-4)

| Story | Trước | Sau CRAPI-4 |
|---|---|---|
| CRAPI-1 | ✅ Done | ✅ Done |
| CRAPI-2 | ✅ Done | ✅ Done |
| CRAPI-3 | ✅ Done direct | ✅ Done (capture fix) |
| CRAPI-4 | ⏳ To Do | ✅ Done |
| CRAPI-5 | ✅ Done direct | ✅ Done |
| CRAPI-7 | ✅ Done | ✅ Done |
| CRAPI-8 | ⬜ To Do | ⬜ To Do |
| Burndown | 4/9 (44%) | 5/9 (56%) |

---

## 7. Tham Khảo `src` Đã Xác Minh (Large Project)

* `crates/proxy/src/server.rs:84-102,233-267,357-378,814-883` (read-only agents)
* `crates/proxy/src/session.rs:15-38`, `flow.rs:14-46`
* `apps/api-tester-server/src/state.rs:54`, `backend.rs:71-97,449-506,571-580,1074-1133`
* `apps/api-tester-server/src/routes.rs:104-124,345-358`, `security_service.rs:21-125`
* `crates/proxy/Cargo.toml:31`, `Cargo.toml:83` (tokio sync)

---
*Lưu dạng dự án lớn — sẵn sàng triển khai. Tiến độ sẽ cập nhật vào `docs/security-crapi-playwright-direct-plan.md:108` sau mỗi milestone.*
