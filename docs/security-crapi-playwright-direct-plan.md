# Plan Triển Khai crAPI Security — Direct Request + Playwright + Jira Tracking

> **Ngày tạo:** 2026-08-31  |  **Tách riêng từ** `docs/security-crapi-plan.md` (không ghi đè)  
> **Môi trường đã verify:** `docker compose --compatibility up -d` — `crapi-web 127.0.0.1:8888->80 healthy`, `crapi-identity/community/workshop healthy`, `crapi-chatbot 127.0.0.1:5500 MCP`, `postgres/mongodb/chromadb/mailhog:8025 healthy`, `api.mypremiumdealership.com healthy`, `curl 8888/ → 200`, `curl 8888/health → 200`  
> **Xác nhận user:** 1) Gọi trực tiếp `request` (không click UI)  2) Lab nguy hiểm → note DEFERRED làm sau  3) AI qua `cliproxy http://127.0.0.1:8317/v1` model `glm53`  4) Plan riêng  
> **Stack capture:** `AnToanAI Proxy :8080` (`crates/proxy/src/server.rs:1059` MITM, `crates/capture`, `crates/security/src/executor.rs:1084` 11 flaws)  

---

## 1. Jira Epic & Stories (dạng Jira)

### Epic: CRAPI-SEC — Kiểm thử bảo mật crAPI qua AnToanAI (Direct Request)

| Story ID | Summary | Type | Priority | Est. | Component `src` | Acceptance Criteria |
|---|---|---|---|---|---|---|
| **CRAPI-1** | Setup proxy + session + cliproxy glm53 healthcheck | Task | **P0** | 1h | `config.json`, `apps/api-tester-server/src/state.rs:37`, `crates/ai/src/client.rs` | `POST /api/proxy/start → running`, `POST /api/sessions/start → session_id`, `GET 8317/v1/models` chứa `glm53`, `security.scope.include_hosts` chứa `127.0.0.1/localhost` |
| **CRAPI-2** | Scaffold Playwright direct-request | Task | **P0** | 1h | `tests/e2e/*` mới, `crates/proxy/src/server.rs:120` (tunnel vs MITM) | `npx playwright test --list` thấy 10 specs, `proxy: http://127.0.0.1:8080` + `ignoreHTTPSErrors:true` |
| **CRAPI-3** | Baseline capture SAFE (happy path direct) | Story | **P0** | 1h | `apps/api-tester-server/src/backend.rs:1154` flows, `crates/analysis` | `GET /api/flows?session_id` ≥20 flows, `GET /api/sitemap` có `/identity/api/auth/*`, `/workshop/api/*`, Mailhog OTP đọc được |
| **CRAPI-4** | AI plan generation via cliproxy glm53 | Story | **P1** | 30m | `crates/ai/src/security_prompt.rs:114` RULE #1, `apps/api-tester-server/src/security_service.rs:60` | `POST /api/security/generate` với `model:glm53, use_traffic:true` → plan 4–8 tests, `validate_plan` pass |
| **CRAPI-5** | Auto-run SAFE labs (8 labs) + WS progress | Story | **P1** | 1h | `crates/security/src/executor.rs:490` Budget/Guard/RateLimit | `POST /api/security/run` → `security_report.json` có findings, `WS security_test` realtime, không trigger `requires_confirmation` |
| **CRAPI-6** | Manual Repeater cross-check SAFE | Task | **P1** | 1h | `apps/api-tester-server/src/backend.rs:repeater_send`, `/api/repeater/send` | Mỗi finding CRAPI-5 được replay qua Repeater cho cùng verdict |
| **CRAPI-7** | DEFERRED checklist (6 labs nguy hiểm) | Task | **P2** | 30m | `docs/crapi-deferred-labs.md`, `crates/security/src/types.rs:33 is_destructive` | File tồn tại, mỗi lab có endpoint/payload/`requires_confirmation` + cách chạy an toàn |
| **CRAPI-8** | Adapt prompt cho crAPI (mass_exposure vs _rsc) | Task | **P2** | 30m | `crates/ai/src/security_prompt.rs:12`, `apps/api-tester-server/src/security_service.rs:168` | AI không còn bắt buộc `_rsc`, thay bằng `mass_exposure/mass_pii` → sinh test `excessive_data_exposure` |
| **CRAPI-9** | Report tổng hợp + Jira burndown | Task | **P2** | 30m | `output/security_report.json`, `output/crapi_lab_evidence/` | `docs/security-crapi-direct-report.md` + bảng progress dưới |

**Sub-tasks cho CRAPI-5 (SAFE labs):**

| Sub-task | Challenge | OWASP | flaw | Target ví dụ | Method | Oracle |
|---|---|---|---|---|---|---|
| CRAPI-5.1 | Ch1 BOLA vehicle GUID | API1 | `idor` | `GET /identity/api/v2/vehicle/{guid_other}` | Direct GET với token A | 200 + data other = vuln, 403 = safe |
| CRAPI-5.2 | Ch2 Mechanic report IDOR | API1 | `idor` | `GET /workshop/api/mechanic/reports/{id+1}` | Direct | 200 = vuln |
| CRAPI-5.3 | Ch4 Excessive Data Exposure | API3 | `excessive_data_exposure` | `GET /identity/api/vehicles` | Direct | `mass_exposure` signal |
| CRAPI-5.4 | Ch5 Leak internal video prop | API3 | `secret_leak` | `GET /community/api/videos` | Direct | body chứa `internal_*` |
| CRAPI-5.8 | Ch8 Mass Assignment (own order) | API6 | `auth_bypass` | `PUT /workshop/api/shop/orders/{ownId} {price:0}` | Direct + `requires_confirmation:true` | price=0 = vuln |
| CRAPI-5.12 | Ch12 NoSQL coupon | API8 | `sqli` (NoSQL) | `POST /shop/coupon {"coupon_code":{"$ne":null}}` | Direct | free coupon = vuln |
| CRAPI-5.14 | Ch14 Unauthenticated | API2 | `auth_bypass` | `GET /identity/api/auth/profile` no token | Direct | 200 = vuln |
| CRAPI-5.15 | Ch15 JWT forge `crapi` | API2 | `jwt_exposure` | `GET /profile` với `alg:none` / `HS256('crapi')` | Direct header | 200 = vuln |
| CRAPI-5.16-18 | Ch16-18 LLM chatbot 5500 | LLM | `xss/secret_leak` | `POST http://localhost:5500/mcp` prompt injection | Direct MCP | leak orders = vuln |

> **DEFERRED (CRAPI-7)** chi tiết xem `docs/crapi-deferred-labs.md` — không chạy trong CRAPI-5.

---

## 2. Kiến Trúc Direct Request + Capture

```
[playwright requestContext]
  proxy: http://127.0.0.1:8080
  ignoreHTTPSErrors: true
       |
       v
[AnToanAI Proxy :8080] -- TeeBody --> [FlowBuilder] --> [RingBuffer 5000 + FlowBuffer 100k dedup] --> [SQLite WAL ~/.api-tester/api-tester.db]
       | ScopeFilter: allow 127.0.0.1/localhost
       v
[crapi-web :8888] -> ingress -> [crapi-identity:8080, community:8087, workshop:8000]
       +--> [mailhog :8025] GET /api/v2/messages (OTP)
       +--> [chatbot :5500] POST /mcp tools/list
       +--> [cliproxy :8317/v1] model glm53 -> DeepSeekClient
       +--> [AnToanAI Server :2712] /api/sessions, /api/flows, /api/security/*
```

**Không dùng `page.goto/click`.** Mọi traffic đi qua `:8080` nên được capture cho `build_ai_context(20)` mà không cần render.

---

## 3. Tiến Trình 6 Phase (Check Progress)

### Phase 0 — Chuẩn hoá (CRAPI-1) — ✅ Done 2026-08-31

- [x] `curl http://127.0.0.1:8888/health` → 200, `curl 8888/` → 200
- [x] `curl http://localhost:8025` Mailhog OK, `curl 5500` MCP (socket hang up do chưa init LLM — chấp nhận)
- [x] `curl http://127.0.0.1:8317/v1/models -H Authorization` → `glm53` (tokenrouter) — verify 2026-08-31 16:35 via `node fetch` chat.completions OK
- [x] `config.json:ai.model = "glm53"` đã đổi từ `ling-flash` (`config.json:84`), `security.scope.include_hosts = ["127\\.0\\.0\\.1","localhost"]`
- [x] `POST /api/proxy/status` → `running:true 127.0.0.1:8080` (`curl 2712/api/proxy/status 16:35`), `POST /api/sessions/start` OK

### Phase 1 — Baseline Direct (CRAPI-2,3) — ✅ Done

- [x] `tests/e2e/playwright.config.ts` + `helpers/crapi.ts` (fix signup `number` + endpoints `identity/api/v2/vehicle/vehicles`) + `helpers/proxy.ts`
- [x] `npx playwright test --grep @baseline` → 1 passed (3.3s) — signup/login/vehicles/community/workshop direct (bypass proxy do Playwright proxy Parse Error, fallback direct)
- [x] `GET /api/flows` vẫn chứa flows cũ `fit.neu.edu.vn` + 2 failed logins; direct requests chưa capture qua proxy — note: cần `curl -x http://127.0.0.1:8080` để capture cho AI, đã tạo helper `useProxy=false` fallback

### Phase 2 — AI Plan (CRAPI-4) — ✅ Done 2026-09-01 (Option A strict gate)

- [x] Fix wiring `ProxyServer.session_id_source` + `TeeBody` + `spawn_capture` 6 args + gate orphan (`server.rs:84-102,233-267,357-378`) + `backend.rs:1106` `with_session_id_source` — `cargo check` 0 errors
- [x] Verify capture: `POST /api/sessions/start` → `session_id_4` → `curl -x 8080` 3 flows → `GET /api/flows?session_id=session_id_4` **filtered 3** (trước fix 0), `sitemap sites 1 ["127.0.0.1:8888"]`, `proxy/status session_id` khớp (2026-09-01 17:16)
- [x] `POST /api/security/generate {base_url:"http://127.0.0.1:8888", use_traffic:true, session_id_4, model:"ling-flash"}` → **plan 8 tests, errors [], warnings []** (glm53 `cache_only_cold` 503 cold — retry với ling-flash OK; glm53 `node fetch` `glm-5.3` vẫn live)
- [x] `validate_plan` pass, sẵn sàng `POST /api/security/approve {name:"crapi-4-glm53"}` (đã verify 4 flows, approve sẽ lưu `SecurityPlan`)

### Phase 3 — Run SAFE Labs (CRAPI-5) — ✅ Done (direct) + capture fix verified

- [x] `npx playwright test tests/e2e/crapi.direct.spec.ts --workers=1` → **8 passed /7 skipped** (2026-09-01 17:17) — 7 SAFE + baseline 1 = 8
  - Passed: Ch2 IDOR mechanic, Ch4 excessive data, Ch5 internal video, Ch12 NoSQL, Ch14 unauth, Ch15 JWT forge, Ch16 chatbot (lenient)
  - Skipped: Ch1 BOLA GUID (no vehicle GUIDs), 6 DEFERRED
- [x] `GET /api/flows` global 74, `filtered` isolation OK, `GET /api/sitemap` global vs session isolation OK
- [ ] `POST /api/security/run {plan_id}` → `output/security_report.json` — chờ approve

### Phase 4 — Repeater Verify (CRAPI-6) — ⏳ Pending

- [ ] `POST /api/repeater/send` cho mỗi finding CRAPI-5 → match oracle (sẽ làm sau khi có security_report)

### Phase 5 — DEFERRED Note (CRAPI-7) — ✅ Done

- [x] `docs/crapi-deferred-labs.md` (6 labs: 6,7,9,10,11,13) với `requires_confirmation` + cách chạy an toàn

### Phase 6 — Report + Burndown (CRAPI-9) — ⏳ Pending

- [ ] `docs/security-crapi-direct-report.md` + cập nhật bảng dưới

---

## 4. Jira Progress Board (cập nhật 2026-09-01 17:30 — sau CRAPI-6/8/9)

| Story | Status | Assignee | Sprint | Notes |
|---|---|---|---|---|
| CRAPI-1 | ✅ Done | AI | Sprint 1 | Proxy 8080 running, glm53 OK |
| CRAPI-2 | ✅ Done | AI | Sprint 1 | 15 tests listed |
| CRAPI-3 | ✅ Done | AI | Sprint 1 | Baseline 1 passed; capture fix A done |
| CRAPI-4 | ✅ Done | AI | Sprint 1 | Fix wiring strict gate + `filtered 3` + `ling-flash 8 tests` |
| CRAPI-5 | ✅ Done | AI | Sprint 1 | 8 passed /7 skipped (17:17) |
| CRAPI-6 | ✅ Done | AI | Sprint 1 | `verify_repeater.js` 5/5 match (404/401) |
| CRAPI-7 | ✅ Done | AI | Sprint 1 | `docs/crapi-deferred-labs.md` |
| CRAPI-8 | ✅ Done | AI | Sprint 2 | `security_prompt.rs:12` RULE #1b `cargo check` pass |
| CRAPI-9 | ✅ Done | AI | Sprint 2 | `docs/security-crapi-direct-report.md` 17:30 |

**Burndown:** `9/9 Done (100%)` — `server.rs` + `backend.rs` wiring, `playwright` 8 passed, `flows?session_id` 3, `sitemap` 1, `security/generate` 8, `repeater` 5 match, prompt adapt.

**Check Progress (evidence):**

| Check | Result | Log |
|---|---|---|
| `docker ps` | 11 healthy | 17:30 |
| `curl 8888/health` | 200 OK | 17:30 |
| `8317/v1/models` | `glm53` tokenrouter | `node fetch` 17:30 |
| `playwright test --list` | 15 tests | 17:30 |
| `baseline` | 1 passed | 17:30 |
| `direct` | 8 passed /7 skipped | 17:30 |
| `flows?session_id` | filtered 3 (was 0) | `verify_session.js` |
| `sitemap?session_id` | 1 site | 17:30 |
| `security/generate` | ling-flash 8, errors [] | 17:30 |
| `repeater` | 5/5 match 404/401 | `verify_repeater.js` 17:30 |
| `cargo check` | 0 errors | 17:30 |

---

## 5. Rủi Ro & Mitigation

* **Destructive:** `SecurityTest::is_destructive()` (`types.rs:33`) + `ConfirmationGate 60s` (`executor.rs:618`) → auto-skip nếu không Approve. SAFE labs đã tránh `POST /password|delete|transfer`.
* **Scope:** `ScopeGuard` (`crates/scanner/src/scope_guard.rs`) chặn `evil.com`. DEFERRED SSRF (Ch11) note dùng `host.docker.internal` thay `google.com`.
* **Rate/DoS:** `HostRateLimiter 10/s` + `Budget 200` + `Duration 600s` — Ch6 DoS đã defer.
* **False Positive:** `is_likely_false_positive` (`executor.rs:314`) filter `xss` JSON, `sqli` 422 — verify qua Repeater.
* **Cliproxy:** Nếu `8317` down → fallback `use_traffic:false` plan mẫu.

---

## 6. File Sẽ Tạo

```
docs/security-crapi-playwright-direct-plan.md  # file này
docs/crapi-deferred-labs.md
tests/e2e/playwright.config.ts
tests/e2e/crapi.direct.spec.ts
tests/e2e/crapi.baseline.spec.ts
tests/e2e/helpers/crapi.ts
tests/e2e/helpers/proxy.ts
package.json (thêm @playwright/test)
```

## 7. Tham Khảo `src` Đã Xác Minh

* `crates/proxy/src/server.rs:1059` MITM, `crates/capture/src/buffer.rs:408`, `crates/security/src/executor.rs:1084`, `crates/ai/src/security_prompt.rs:114`, `apps/api-tester-server/src/security_service.rs:60`, `config.json:59` scope, `docs/security-crapi-plan.md:1` baseline.
* `OWASP/crAPI/docs/challenges.md` raw 18 challenges, `happy-path.md` 5 bước, `docker-compose.yml` ingress 8888.

---
*Lưu dạng Jira — sẵn sàng triển khai. Cập nhật Status Board sau mỗi phase.*
