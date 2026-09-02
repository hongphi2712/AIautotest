# Plan Triển Khai Test Security — crAPI + AnToanAI

> Ngày tạo: 2026-08-31  
> Môi trường đã verify: `docker compose --compatibility up -d` — `crapi-web (127.0.0.1:8888->80, 8443->443) healthy`, `crapi-workshop/community/identity healthy`, `crapi-chatbot 127.0.0.1:5500`, `postgres/mongodb/chromadb/mailhog healthy`, `api.mypremiumdealership.com healthy`, `curl http://127.0.0.1:8888/ → 200`, `curl /health → 200`.  
> Truy cập: WebApp http://localhost:8888 / https://localhost:8443, Mailhog http://localhost:8025, Chatbot MCP http://localhost:5500  
> Trạng thái: Plan đã lưu — chưa triển khai code.

---

## 1. Bối Cảnh Đã Xác Minh Từ `src`

| Layer | Hiện trạng `src` | Liên quan crAPI |
|---|---|---|
| **Proxy MITM** `crates/proxy/src/server.rs` | `127.0.0.1:8080`, CA `~/.api-tester/certs/ca.crt`, `CRL /ca.crl`, `AcceptAllVerifier`, `max_connections 256`, `Tunnel` nếu out-of-scope | Bắt traffic `crapi-web:8888`, `chatbot:5500`, `api.mypremiumdealership.com` |
| **Capture** `crates/capture/src/buffer.rs` | `RingBuffer 5000` + `FlowBuffer 100k dedup fingerprint METHOD:path:md5(body)` + `PersistenceWriter batch 100 → SQLite WAL` | Lưu flow cho AI `build_ai_context(1000 flows)` |
| **Analysis (passive)** `crates/analysis` | `SecretScanner` (gitleaks + 6 regex + RSC `self.__next_f.push` split), `OverfetchingAnalyzer` (mass_exposure >50, mass_pii >10 emails, RSC leak, password exposure), `CweDetector`, `TokenExtractor` | Phát hiện `excessive_data_exposure / secret_leak / cwe_debug_exposure` không gửi request |
| **Scanner (active generic)** `crates/scanner` | `PayloadSource` 5 skills × 23 payloads (`sqli 6, xss 5, idor 5, jwt 3, auth_bypass 4`), `MutationEngine` (query/body/header/path/cookie, `a.b.c` nested), `Scheduler` worker-pool + `BudgetTracker + HostRateLimiter + ScopeGuard` | Fuzz param tự động |
| **Security Executor (AI-plan)** `crates/security/src/executor.rs` | Plan `SecurityTestPlan {tests: {flaw 11 loại, target method/path, payload/location, oracle, requires_confirmation}}`, `mutate_target` + `check_oracle + SecretScan universal + FalsePositive filter`, `ConfirmationGate 60s` via `oneshot + WS security_confirm` | Core test crAPI. 11 flaws: `jwt_exposure, idor, auth_bypass, xss, sqli, csrf, open_redirect, rate_limit, excessive_data_exposure, secret_leak, cwe_debug_exposure` |
| **AI Prompt** `crates/ai/src/security_prompt.rs` | `SECURITY_SYSTEM_PROMPT` 21 rules, `format_security_context(20 steps)` (redacted), `MAX_ATTEMPTS=3`, post-process RSC injection cho `fit.neu.edu.vn` | Hiện hard-coded `fit` + `_rsc` — cần adapt cho crAPI |
| **Server** `apps/api-tester-server/src/security_service.rs` | `security_generate → chat_json → validate_plan → approve → run → SecurityExecutor(with_events) → WS security_test/security_confirm → output/security_report.json + SQLite SecurityRun` | Flow chính. `security.scope.include_hosts` bắt buộc non-empty |
| **UI** `apps/api-tester-server/ui/js/components/analyzer.js` | Tab Analyzer → Security(AI) `Target URL, session, model, use_traffic → Generate → Approve → Run → findings + confirm banner 60s` + History/Sitemap/Intercept/Repeater | Thực thi lab qua UI |

**Config hiện tại** `config.json`:
```json
security.scope.include_hosts = ["fit\\.neu\\.edu\\.vn","127\\.0\\.0\\.1","localhost"]
security {max_requests 200, timeout 15, per_host 10 RPS, duration 600s, retry 1, concurrency 1}
ai {base_url "http://127.0.0.1:8317/v1", model "ling-flash", api_key "sk-..."}
```

---

## 2. Mục Tiêu Lab crAPI

crAPI (`owasp/crapi`) qua 3 services:

* `crapi-identity` (`/identity/api/v2/user/login`, `/auth/verify`, JWT)
* `crapi-community` (`/community/api/v2/community` + `/user`)
* `crapi-workshop` (`/workshop/api/shop/orders`, `/vehicles`)

| # | Challenge crAPI | OWASP | flaw AnToanAI | Target ví dụ |
|---|---|---|---|---|
| L1 | BOLA — Get vehicle user khác | API1 | `idor` | `GET /identity/api/v2/vehicle/{id}` |
| L2 | BFLA — Mechanic update order customer | API5 | `auth_bypass` | `POST /workshop/api/shop/orders/{id}/status` |
| L3 | BOLA — Community post user khác | API1 | `idor` | `GET /community/api/v2/community/posts/{id}` |
| L4 | Mass Assignment — Set `role=admin` khi signup | API8 | `auth_bypass` + body injection | `POST /identity/api/v2/user/register body:{"role":"admin"}` |
| L5 | Excessive Data Exposure — List vehicles leak PII | API3 | `excessive_data_exposure` | `GET /identity/api/v2/vehicle/vehicles` |
| L6 | JWT none/weak | API2 | `jwt_exposure` + `jwt_attack` | `Authorization: Bearer eyJ...` with `alg:none` |
| L7 | No Rate Limit — Login brute force | API4 | `rate_limit` | `POST /identity/api/v2/user/login` |
| L8 | SQLi | API8 | `sqli` | `GET /community/api/v2/community?q=' OR 1=1--` |
| L9 | XSS — comment/post | API8 | `xss` | `POST /community/api/v2/community/posts body:comment="<svg...>"` |
| L10 | Open Redirect — `callbackUrl` | API8 | `open_redirect` | `GET /identity/api/v2/user/verify?callbackUrl=https://evil.com` |
| L11 | Chatbot MCP `5500` — prompt injection / SSRF | - | `sqli/xss/secret_leak` | `POST http://localhost:5500/mcp` |
| L12 | Mailhog `8025` — verify reset flow | - | `secret_leak` | `GET http://localhost:8025/api/v2/messages` |

---

## 3. Plan 6 Phase (Không tự động phá dữ liệu)

### Phase 0 — Chuẩn hoá môi trường (30 phút)

1. Verify:
   ```powershell
   curl http://127.0.0.1:8888/health
   curl http://127.0.0.1:8888/
   curl http://localhost:8025
   curl http://localhost:5500
   docker ps --filter name=crapi
   ```
2. Cập nhật `~/.api-tester/config.json`:
   ```json
   security.scope.include_hosts = ["127\\.0\\.0\\.1","localhost","crapi-web","api\\.mypremiumdealership\\.com"]
   security {max_requests: 200, per_host_requests_per_sec: 5, duration_budget_secs: 300}
   scope.include_hosts = ["127\\.0\\.0\\.1","localhost"]
   ```
3. Khởi AnToanAI: `cargo run --bin api-tester-server` → UI `http://127.0.0.1:2712`, `POST /api/proxy/start`, `GET /api/cert/info` → install CA, `POST /api/browser/open`.
4. `POST /api/sessions/start {"name":"crapi-baseline","target_host":"127.0.0.1:8888"}`

### Phase 1 — Capture Baseline (passive, 1–2h)

* 1.1 Browser qua proxy, đi happy-path: Register → Login (lấy `accessToken`/`Set-Cookie`), Mailhog OTP, `GET /vehicle/vehicles`, `GET /vehicle/{id}`, Community list/post, Workshop orders, Chatbot MCP enumerate.
* 1.2 Quan sát `Analyzer → Dependencies / Flow Diagram` → token map.
* 1.3 `POST /api/analyze/flow` → check `SecretScanner/Overfetching` flag.

### Phase 2 — AI Security Plan Generation (30 phút)

* 2.1 Analyzer → Security: `Target URL = http://127.0.0.1:8888`, `use_traffic=true`, `session_id=crapi-baseline`, `model=ling-flash`, `POST /api/security/generate` → `build_security_prompt` + `format_security_context(20)`.
* 2.2 Kỳ vọng 4–8 tests. Nếu thiếu lab → repair loop 3 lần.
* 2.3 `Approve` → `POST /api/security/approve` → SQLite `SecurityPlan`.

### Phase 3 — Active Execution Với Guardrail (1h)

* 3.1 `POST /api/security/run` → `SecurityExecutor` per-request `ScopeGuard` + `Budget 200` + `RateLimiter 5/s` + `auth_cookies/headers` inject. Destructive → WS `security_confirm` banner 60s → Reject mặc định.
* 3.2 Theo dõi WS `security_test` realtime. Mỗi response chạy `SecretScanner+Overfetching` universal.
* 3.3 Thu `output/security_report.json`.

### Phase 4 — Lab-by-Lab Manual Deep Dive (2–3h)

Dùng Repeater + Scanner verify từng Finding:

| Lab | Repeater Payload | Oracle |
|---|---|---|
| L1 BOLA vehicle | `GET /identity/api/v2/vehicle/2` với token user A | 200 + VIN khác = vuln |
| L2 BFLA | `POST /workshop/api/shop/orders/1/status` với token customer | 200 = BFLA |
| L4 Mass Assignment | `POST /identity/api/v2/user/register {"role":"admin"}` | response role=admin = vuln |
| L5 Excessive Data | `GET /identity/api/v2/vehicle/vehicles` | `mass_exposure` signals |
| L6 JWT | `GET /profile` với `alg:none` | 200 = vuln |
| L7 Rate Limit | `POST /login` 10 req/2s | không 429 = vuln |

### Phase 5 — Adapt Code Cho crAPI (Optional, <100 LOC)

1. `crates/ai/src/security_prompt.rs` — sửa RULE #1: nếu `ANOMALIES` chứa `mass_exposure|mass_pii|secret_leak` → bắt buộc 1 test `excessive_data_exposure/secret_leak`.
2. `apps/api-tester-server/src/security_service.rs` — post-process RSC chỉ cho `fit`; thêm nhánh crAPI cho `/vehicle/vehicles|/community/posts`.
3. `config.json` — thêm `api\\.mypremiumdealership\\.com` vào scope.
4. Optional thêm skill `mass_assignment` vào `crates/scanner/src/payload_source.rs`.

### Phase 6 — Báo Cáo & Tích Hợp

* `GET /api/sitemap?session_id=...` → export sitemap.
* `output/security_report.json` → `docs/specs/crapi_report.html` (reuse `crates/reporting`).
* Mailhog + Chatbot MCP document riêng.

---

## 4. Rủi Ro & Mitigation

* **Destructive:** `is_destructive()` + 60s auto-skip, luôn Reject khi `POST /password|delete|transfer`.
* **Scope Violation:** `ScopeGuard` chặn `evil.com`, regex escape `\.`.
* **Rate Limit/DoS:** `HostRateLimiter 10/s` + `Budget 200` + `Duration 600s` ngăn flood.
* **False Positive:** `is_likely_false_positive` filter `xss` trên JSON, `sqli` 422. Manual verify qua Repeater.
* **TLS/Proxy:** `8888` HTTP plain, `8443` HTTPS cần CA.

## 5. File Chạm Khi Implement

```
crates/ai/src/security_prompt.rs
crates/security/src/validator.rs
apps/api-tester-server/src/security_service.rs
config.json / ~/.api-tester/config.json
output/security_report.json
```

## 6. Timeline

| Ngày | Việc | Output |
|---|---|---|
| D0 | Phase 0+1 | session crapi-baseline 50+ flows |
| D0 | Phase 2 | 1 approved plan |
| D0 | Phase 3 | security_report.json 4–6 findings |
| D1 | Phase 4 | output/crapi_lab_evidence/L*.json |
| D1 | Phase 5 | PR adapt prompt |
| D1 | Phase 6 | docs/crapi-security-report.md |

## 7. Câu Hỏi Cần Confirm Trước Khi Triển Khai

1. Scope là `127.0.0.1:8888` hay `api.mypremiumdealership.com`?
2. AI `ling-flash @ 127.0.0.1:8317` đã chạy chưa?
3. Auto Approve destructive trên account test riêng hay giữ Reject mặc định?
4. Chatbot MCP `5500` đã có spec tools chưa?

---
*Lưu bởi plan mode — chưa chỉnh code.*
