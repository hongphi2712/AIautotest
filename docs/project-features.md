# AnToanAI - Nền tảng Kiểm thử Bảo mật API Tự động

## Mục lục

1. [Giới thiệu](#1-giới-thiệu)
2. [Kiến trúc hệ thống](#2-kiến-trúc-hệ-thống)
3. [Tính năng chính](#3-tính-năng-chính)
4. [Tính năng đã triển khai](#4-tính-năng-đã-triển-khai)
5. [Tính năng chưa triển khai](#5-tính-năng-chưa-triển-khai)
6. [Công nghệ sử dụng](#6-công-nghệ-sử-dụng)
7. [Đối tượng sử dụng](#7-đối-tượng-sử-dụng)
8. [So sánh với công cụ tương tự](#8-so-sánh-với-công-cụ-tương-tự)

---

## 1. Giới thiệu

**AnToanAI** (An Toàn AI) là nền tảng kiểm thử bảo mật API tự động được hỗ trợ bởi trí tuệ nhân tạo, được viết bằng Rust. Nền tảng kết hợp khả năng bắt giữc HTTP/HTTPS proxy, phân tích traffic thông minh, và phát hiện lỗ hổng tự động với báo cáo bảo mật bằng tiếng Việt.

### Thông tin dự án

| Thông tin | Giá trị |
|-----------|---------|
| Tên dự án | AnToanAI (An Toàn AI) |
| Phiên bản | 0.1.0 |
| Ngôn ngữ chính | Rust (Edition 2024) |
| Giấy phép | MIT |
| Tác giả | API-AutoTester Team |

---

## 2. Kiến trúc hệ thống

### 2.1 Kiến trúc Hexagonal (Ports & Adapters)

```
┌─────────────────────────────────────────────────────────────┐
│                    Ứng dụng (Application)                    │
├─────────────────────────────────────────────────────────────┤
│                      Domain Layer                           │
│  ┌─────────┬──────────┬──────────┬──────────┬────────────┐ │
│  │ domain  │  ports   │   ai     │ analysis │  security  │ │
│  │ capture │  proxy   │ scanner  │ workflow │  reporting  │ │
│  │ auth    │ storage  │  query   │  events  │test-support│ │
│  └─────────┴──────────┴──────────┴──────────┴────────────┘ │
├─────────────────────────────────────────────────────────────┤
│                    Infrastructure Layer                     │
│  ┌─────────┬──────────┬──────────┬──────────┬────────────┐ │
│  │  Axum   │  SQLite  │  Hyper   │  Reqwest │   Tokio    │ │
│  │  Server │  Storage │  Client  │  Client  │   Runtime  │ │
│  └─────────┴──────────┴──────────┴──────────┴────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

### 2.2 Cấu trúc thư mục

```
AnToanAI/
├── apps/
│   ├── api-tester-cli/          # CLI binary (chưa hoàn thiện)
│   └── api-tester-server/       # Axum server + UI
│       ├── src/                 # Rust backend
│       ├── ui/                  # Frontend (Vanilla JS)
│       │   ├── js/              # JavaScript components
│       │   └── css/             # Stylesheets
│       └── examples/
├── crates/                      # 17 library crates
│   ├── domain/                  # Core domain models
│   ├── ports/                   # Trait interfaces
│   ├── proxy/                   # HTTP/HTTPS MITM proxy
│   ├── capture/                 # Traffic buffering
│   ├── analysis/                # Token/param analysis
│   ├── scanner/                 # Vulnerability scanner
│   ├── security/                # AI security test executor
│   ├── ai/                      # DeepSeek/OpenAI client
│   ├── workflow/                # DAG workflow engine
│   ├── storage/                 # SQLite persistence
│   ├── config/                  # Configuration loading
│   ├── events/                  # Event bus
│   ├── query/                   # HTTPQL query engine
│   ├── reporting/               # Report generation
│   ├── auth/                    # Authentication management
│   ├── application/             # Use-case layer
│   └── test-support/            # Test doubles
├── config.json                  # Runtime configuration
├── Cargo.toml                   # Rust workspace
└── docs/                        # Documentation
```

---

## 3. Tính năng chính

### 3.1 MITM HTTP/HTTPS Proxy

- **Bắt giữc traffic**: Proxy server trên port 8080, bắt giữc toàn bộ HTTP/HTTPS traffic từ trình duyệt
- **Chứng chỉ TLS tự động**: Tạo CA certificate và cấp chứng chỉ theo từng host sử dụng rcgen/rustls
- **CRL Support**: Phục vụ Certificate Revocation List tại `/ca.crl`, tương thích Windows schannel
- **Scope filtering**: Include/exclude hosts và paths bằng regex
- **Match & Replace**: Sửa đổi request/response theo regex rules (SetHeader, RemoveHeader, ReplaceBody, ReplaceUrl với capture groups)
- **Intercept controller**: Tạm dừng request để chỉnh sửa/chuyển tiếp/xóa (tương tự Burp Suite)
- **Connection reuse**: Keep-alive, connection pooling, concurrency limiting via semaphore
- **Tunnel pass-through**: Đối với traffic ngoài scope,-proxy forward trực tiếp không MITM

### 3.2 Phân tích Traffic (Security Analysis Engine)

**Phát hiện Secret & Credential:**
- **Secret Scanner**: Kết hợp Gitleaks CLI + Built-in Regex (AWS keys, OpenAI keys, Google API keys, DB URIs, RSA private keys, JWT tokens)
- **CWE Detector**: Map findings sang CWE-215 (Debug Exposure), CWE-209 (Error Messages), CWE-284 (Access Control)
- **Entropy Analysis**: Shannon entropy detection (4.7+ bits/char, 28+ chars) với exclusion cho UUIDs, MD5/SHA hashes
- **Memoization**: LRU cache 4096 entries cho kết quả phân tích

**Phân tích Cấu trúc Response (Overfetching/BOPLA):**
- **Mass Exposure**: Phát hiện response quá lớn, mass entity exposure, mass PII email exposure
- **Pagination Incompleteness**: Phát hiện pagination không đầy đủ
- **Embedded Payload Detection**: Parse Next.js RSC streams (`self.__next_f.push`), `__NEXT_DATA__`, Laravel Livewire `wire:snapshot`
- **Password Exposure**: Phát hiện password lộ trong response
- **Privacy Flag Conflict**: Phát hiện conflict giữa privacy flags và dữ liệu trả về
- **Auto-login QR Detection**: Phát hiện QR code đăng nhập tự động trong HTML
- **Long Text Field Asymmetry**: Phát hiện bất đối xứng giữa text fields dài

**Sensitive Taxonomy:**
- **6 Groups**: Credentials, Tokens, PII Contact, PII Government ID, Payment, Assessment Content
- **Validators**: Luhn checksum cho payment cards, phone format validation, placeholder filtering
- **Custom Keys**: Hỗ trợ `extra_sensitive_keys` tùy chỉnh theo target

**Phân tích Flow:**
- **Token Extractor**: Trích xuất JWT, OAuth, API key, CSRF từ request/response headers và body
- **Dependency Mapper**: Map token dependencies giữa các flows (adjacency list + detailed FlowDependency)
- **Flow Sequencer**: Topological sort (Kahn's algorithm) với cycle detection
- **Flow Graph Builder**: Timeline graph với parent-child edges
- **Param Analyzer**: Phân loại parameter theo type (String, Int, Float, Id, Boolean, UUID, Email, Token, Date) và location (query, JSON body, headers, path)

**Noise Filtering:**
- **Host filtering**: Loại bỏ ad/tracker hosts (dtscout, adsrvr, histats, google-analytics, facebook, cloudflare...)
- **Path filtering**: Loại bỏ static assets (images, CSS, JS, Next.js chunks)
- **Query dedup**: Loại bỏ duplicate query parameters

### 3.3 Quét Lỗ hổng Bảo mật (Security Scan Engine)

**Mutation Planning:**
- **ParamAnalyzer**: Phân tích captured flows để xác định parameters có thể mutate
- **MutationEngine**: Tạo request mutations từ analyzed parameters với multi-location injection:
  - Query parameters (URL-encoded)
  - JSON body (hỗ trợ nested path: `user.id`, `items[0].name`)
  - Headers
  - Path segments
  - Form body / Cookie
- **Deterministic ordering**: Stable sort + optional seed-driven shuffle

**Payload Dictionary (5 Skills):**
- **SQLi**: 6 payloads (tautology, union-based, boolean-based, time-based)
- **XSS**: 5 payloads (script tag, event handler, svg onload, javascript scheme, attribute breakout)
- **IDOR**: 5 payloads (zero, first record, large, negative, leading-zero)
- **JWT Attack**: 3 payloads (alg none + empty sig, guessable sig, alg none + admin role)
- **Auth Bypass**: 4 payloads (admin, true, 1, administrator)

**Execution Engine:**
- **Scan Scheduler**: Worker pool concurrent với configurable concurrency
- **Request Executor**: HTTP client với timeout và bounded retries
- **Budget Tracker**: Request cap + wall-clock budget
- **Rate Limiter**: Per-host token bucket (Governor)
- **Request Dedup**: MD5 fingerprint of method+url+body, auto-clear at 100K
- **Scope Guard**: Enforce scope allowlisting trước khi scan

**Response Verification:**
- **Payload Reflection Detection**: High severity cho sqli/xss
- **SQL Error Pattern Matching**: 6 patterns nhận diện SQL errors
- **5xx Status Detection**: Phát hiện server errors cho SQLi
- **Overfetching Analysis**: Cho skills `excessive_data_exposure`, `rsc_hydration_leak`
- **Secret/CWE Detection**: Cho skills `secret_leak`, `cwe_debug_exposure`

### 3.4 AI Integration

- **DeepSeek Client**: OpenAI-compatible chat completions client (non-streaming, configurable base_url)
- **AI Prompt Builder**: Tạo prompt từ captured traffic với redacted context (không gửi raw secrets)
- **Security Context Builder**: Extended format với PARAMETERS OBSERVED, AUTH OBSERVED, ENDPOINT CATALOG, ANOMALIES OBSERVED
- **Workflow Prompt Generator**: Tạo workflow từ natural language với strict JSON schema
- **Security Prompt Generator**: Tạo security test plan với flaw types (jwt_exposure, idor, auth_bypass, xss, sqli, csrf, open_redirect, rate_limit, excessive_data_exposure, secret_leak, cwe_debug_exposure)
- **Bounded Repair Loops**: AI → parse → validate → retry (tối đa 3 attempts)
- **Token Cost Discipline**: MAX_STEPS_IN_PROMPT=200, MAX_EDGES_IN_PROMPT=200, không gửi token values

### 3.5 Workflow Engine

- **DAG Execution**: Directed acyclic graph với 6 node types
- **Node Types**:
  - `http_request`: HTTP calls với method, path, headers, body, retries, timeout
  - `extract_variable`: JSON path extraction từ node output vào named variables
  - `assert`: Boolean assertions với operators (eq, ne, gt, lt, contains)
  - `delay`: Time delay trong milliseconds
  - `condition`: Boolean branching (true/false output cho `when` edges)
  - `loop`: Iteration over array variables với body_start/body_end range
- **Template Rendering**: `{{variable}}` syntax trong path/headers/body
- **JSONPath Resolver**: Custom JSONPath resolver
- **Validation**: Cycle detection, scope checking, loop validation (nested loops bị từ chối)
- **Per-node Retry**: Configurable retries + exponential backoff
- **Workflow-level Timeout**: Wrap toàn bộ execution trong tokio::time::timeout
- **Cancellation**: CancellationToken checked tại mỗi node boundary
- **Real-time Events**: `on_node` callback fires sau mỗi node execution với duration, output, errors

### 3.6 Web Dashboard (Burp Suite-inspired)

**Architecture:**
- **Single-page Application**: Vanilla JavaScript Web Components, không framework
- **Real-time Updates**: WebSocket push events (new flows, proxy status, intercept queue)
- **35+ REST API Endpoints**: Proxy, Session, Flow, Intercept, Analysis, Sitemap, AI, Workflow, Security, Repeater
- **Static Files**: Phục vụ trực tiếp qua Axum `ServeDir` với `no-store` cache control

**7 Tab Views:**
1. **Dashboard**: Summary stats, session card, findings export, security runs, system log
2. **Target**: Site map tree view, filtering, annotations (colors + comments), context menu
3. **Proxy**: 5 sub-tabs (Intercept, HTTP History, WebSockets History, Match and Replace, Proxy Settings)
4. **Repeater**: Tabbed request editing, Pretty/Raw/Hex views, inspector panel, undo/redo
5. **Scanner**: Placeholder stub
6. **Analyzer**: Flow diagram (Mermaid/Python), Dependencies, Workflow (AI), Security (AI)
7. **Reports**: Placeholder stub

**16 Web Components:**
- `<dashboard-view>`, `<sitemap-view>`, `<intercept-view>`, `<history-view>`, `<proxy-settings-view>`, `<repeater-view>`, `<analyzer-view>`, `<message-viewer>`, `<inspector-panel>`, `<task-sidebar>`, plus core modules (app.js, api.js, shell.js, store.js, ws.js)

**Tính năng bổ sung:**
- **Repeater**: Gửi lại requests với tabbed editing, syntax highlighting, search
- **Session Management**: Start/stop/delete/clear capture sessions
- **Sitemap Annotations**: Ghi chú (colors + comments) cho endpoints
- **CA Certificate Management**: Generate, install trên Windows

---

## 4. Tính năng đã triển khai

### 4.1 Core Infrastructure

| Tính năng | Mô tả | Vị trí |
|-----------|-------|--------|
| HTTP/HTTPS MITM Proxy | Bắt giữc traffic trình duyệt, chứng chỉ TLS tự động | `crates/proxy/` |
| Proxy Certificate Management | Tạo CA, cấp chứng chỉ theo host, cài đặt trên Windows | `crates/proxy/src/cert.rs` |
| HTTP Flow Capture | Buffer Ring, dedup fingerprint, ghi SQLite | `crates/capture/` |
| SQLite Storage | Lưu flows, sessions, workflows, security plans, annotations | `crates/storage/` |
| Domain Models | HttpFlow, Session, Finding, Payload, AppConfig... | `crates/domain/` |
| Port/Adapter Architecture | 9 async traits (FlowRepository, SessionRepository...) | `crates/ports/` |
| Configuration System | config.json, env vars, analysis thresholds | `crates/config/` |
| WebSocket Real-time | Push events flows, intercept, workflow, security | `apps/api-tester-server/src/ws.rs` |
| Event System | Broadcast domain events | `crates/events/` |
| Scope Filtering | Include/exclude host/path bằng regex | `crates/domain/src/scope.rs` |
| Single-instance Lock | File lock chống crash SQLite | `apps/api-tester-server/src/main.rs` |

### 4.2 Analysis Engine

| Tính năng | Mô tả | Vị trí |
|-----------|-------|--------|
| Secret Scanner | Regex + Gitleaks, LRU cache 4096 entries | `crates/analysis/src/secret_scanner.rs` |
| Gitleaks Integration | Pipe stdin/stdout, timeout, binary detection | `crates/analysis/src/gitleaks_scanner.rs` |
| Overfetching Analyzer | Mass exposure, RSC/Next.js/Livewire, sensitive taxonomy | `crates/analysis/src/overfetching.rs` |
| Sensitive Taxonomy | Credentials, PII, payment, gov IDs, custom keys | `crates/analysis/src/sensitive_taxonomy.rs` |
| CWE Detector | CWE-215, CWE-209, CWE-284 | `crates/analysis/src/cwe_detector.rs` |
| Entropy Analysis | Shannon entropy, JSON tree walk | `crates/analysis/src/entropy.rs` |
| Token Extractor | JWT, OAuth, API key, CSRF | `crates/analysis/src/token_extractor.rs` |
| Dependency Mapper | Graph token-flow dependencies | `crates/analysis/src/dependency_mapper.rs` |
| Flow Graph Builder | Timeline graph, parent-child edges | `crates/analysis/src/flow_graph.rs` |
| Flow Sequencer | Topological sort (Kahn's algorithm) | `crates/analysis/src/flow_sequencer.rs` |
| Param Analyzer | Phân loại UUID, email, JWT, date... | `crates/analysis/src/path_analyzer.rs` |
| Noise Filter | Ad/tracker hosts, static assets | `crates/analysis/src/noise.rs` |

### 4.3 Scanner Engine

| Tính năng | Mô tả | Vị trí |
|-----------|-------|--------|
| Scan Scheduler | Worker loop, concurrent, budget, dedup | `crates/scanner/src/scheduler.rs` |
| Mutation Engine | Query, JSON body, header, path, cookie mutation | `crates/scanner/src/mutation_engine.rs` |
| Payload Source | SQLi, XSS, IDOR, JWT, auth bypass | `crates/scanner/src/payload_source.rs` |
| Request Executor | Timeout + retry backoff | `crates/scanner/src/request_executor.rs` |
| Response Verifier | Payload reflection, SQL error, overfetching | `crates/scanner/src/response_verifier.rs` |
| Budget Tracker | Request cap + wall-clock budget | `crates/scanner/src/budget.rs` |
| Request Dedup | Body hash dedup | `crates/scanner/src/dedup.rs` |
| Rate Limiter | Per-host token bucket (Governor) | `crates/scanner/src/rate_limit.rs` |
| Scope Guard | Allowlist enforcement | `crates/scanner/src/scope_guard.rs` |

### 4.4 Security Executor

| Tính năng | Mô tả | Vị trí |
|-----------|-------|--------|
| Security Test Execution | Plan-based, scope check, budget, rate limit | `crates/security/src/executor.rs` |
| Payload Injection | Query, body, header, path, cookie | `crates/security/src/executor.rs` |
| Auth Injection | Cookies + headers từ captured traffic | `crates/security/src/executor.rs` |
| Oracle Checking | Status + body contain matching | `crates/security/src/executor.rs` |
| Secret Scan on Every Response | Universal gitleaks + regex + CWE | `crates/security/src/executor.rs` |
| Verdict/Explanation Engine | Vietnamese + English explanations | `crates/security/src/executor.rs` |

### 4.5 Workflow Engine

| Tính năng | Mô tả | Vị trí |
|-----------|-------|--------|
| Workflow Contract | Workflow, Node, NodeKind, Edge | `crates/workflow/src/contract.rs` |
| Workflow Validation | DAG validation, cycle detection, loop validation | `crates/workflow/src/validation.rs` |
| Workflow Execution | HTTP/extract/assert/condition/delay/loop nodes | `crates/workflow/src/exec.rs` |
| JSONPath Resolver | Trích xuất JSON | `crates/workflow/src/jsonpath.rs` |

### 4.6 AI Integration

| Tính năng | Mô tả | Vị trí |
|-----------|-------|--------|
| DeepSeek Client | Chat + JSON mode, timeout, max_tokens | `crates/ai/src/client.rs` |
| AI Prompt Builder | Flow summary từ captured traffic | `crates/ai/src/prompt.rs` |
| Workflow Prompt Generator | Tạo workflow từ natural language | `crates/ai/src/workflow_prompt.rs` |
| Security Prompt Generator | Tạo security test plan | `crates/ai/src/security_prompt.rs` |

### 4.7 Reporting

| Tính năng | Mô tả | Vị trí |
|-----------|-------|--------|
| Mermaid Diagram Generator | Sơ đồ luồng API | `crates/reporting/src/mermaid.rs` |
| Python Replay Code | Recording + parameterized modes | `crates/reporting/src/python.rs` |

### 4.8 Auth Manager

| Tính năng | Mô tả | Vị trí |
|-----------|-------|--------|
| Login Flow Execution | Multi-step, token extraction, session expiry | `crates/auth/src/manager.rs` |

### 4.9 Server Application

| Tính năng | Mô tả | Vị trí |
|-----------|-------|--------|
| REST API | 35+ routes: flows, sessions, proxy, cert, intercept, repeater, workflow, security... | `apps/api-tester-server/src/routes.rs` |
| State Management | AppState with all operations | `apps/api-tester-server/src/state.rs` |
| Backend | Proxy lifecycle, browser launch, session mgmt | `apps/api-tester-server/src/backend.rs` |
| Workflow Service | Generate via AI, approve, run, cancel | `apps/api-tester-server/src/workflow_service.rs` |
| Security Service | Generate via AI, approve, run, cancel | `apps/api-tester-server/src/security_service.rs` |

### 4.10 UI Components

| Component | Mô tả | Trạng thái |
|-----------|-------|------------|
| Dashboard | Summary stats, session card, findings export | ✅ Hoàn thành |
| Analyzer | Flow diagram, Dependencies, Workflow AI, Security AI | ✅ Hoàn thành |
| HTTP History | Filtering, search, message viewer, send-to-repeater | ✅ Hoàn thành |
| Intercept | Forward/drop/edit, WebSocket polling | ✅ Hoàn thành |
| Repeater | Tabbed request editing, Pretty/Raw/Hex views | ✅ Hoàn thành |
| Proxy Settings | Start/stop, CA cert management, session management | ✅ Hoàn thành |
| Site Map | Tree view, filtering, annotations, context menu | ✅ Hoàn thành |
| Sidebar | Task sidebar with CRUD actions | ✅ Hoàn thành |
| Message Viewer | Request/Response viewer (read-only + editable) | ✅ Hoàn thành |
| Inspector Panel | Collapsible sidebar | ✅ Hoàn thành |
| Editor Undo/Redo | Shared undo/redo manager | ✅ Hoàn thành |
| App Shell | Tab navigation, proxy status polling | ✅ Hoàn thành |
| WebSocket Client | Auto-reconnect | ✅ Hoàn thành |
| API Client | REST API + Tauri bridge | ✅ Hoàn thành |
| State Store | Reactive pub/sub store | ✅ Hoàn thành |

---

## 5. Tính năng chưa triển khai

### 5.1 CLI Application

| Tính năng | Mô tả | Trạng thái |
|-----------|-------|------------|
| CLI Commands | `api-tester-cli` - hiện chỉ in version | 🔲 Stub (28 lines) |
| Proxy CLI | Chạy proxy từ command line | 🔲 Chưa triển khai |
| Capture CLI | Bắt traffic từ CLI | 🔲 Chưa triển khai |
| Analyze CLI | Phân tích traffic từ CLI | 🔲 Chưa triển khai |
| Scan CLI | Quét lỗ hổng từ CLI | 🔲 Chưa triển khai |

### 5.2 UI Stubs

| Tính năng | Mô tả | Trạng thái |
|-----------|-------|------------|
| WebSockets History | Xem lịch sử WebSocket captures | 🔲 Stub trong UI |
| Match and Replace UI | UI quản lý match/replace rules | 🔲 Stub trong UI |
| Scanner UI | UI cho scanner engine | 🔲 Stub trong UI |
| Reports UI | UI xuất báo cáo JSON/HTML/Mermaid | 🔲 Stub trong UI |

### 5.3 Features Chưa Xây (Đề xuất phát triển)

#### A. Core Features

| Tính năng | Mô tả | Ưu tiên |
|-----------|-------|---------|
| **Intruder Engine** | Burp-style payload injection với position markers, attack types (Sniper, Battering Ram, Pitchfork, Cluster Bomb). Tốc độ cao nhờ Rust async runtime (~500+ req/sec, không rate-limit) | 🔴 Cao |
| **OOB (Out-of-Band) Detection** | Tương tự Burp Collaborator - detect SSRF, blind SQLi, blind XSS qua DNS/HTTP callbacks | 🔴 Cao |
| **Content Discovery** | Auto crawl website, discover hidden endpoints, parameters, files (tương tự Burp Pro) | 🔴 Cao |
| **Session Handling Rules** | Tự động refresh token, handle session expiry, macro recording | 🔴 Cao |
| **Host->Keys Profile Layer** | Layer tùy chỉnh sensitive keys theo host (ví dụ: `fit.neu.edu.vn` có keys riêng) | 🟡 Trung bình |

**Chi tiết Content Discovery:**

```
Workflow:
1. Crawl target website (BFS/DFS)
2. Discover:
   ├── Hidden endpoints (admin/, backup/, .env, .git)
   ├── Hidden parameters (fuzz common param names)
   ├── Hidden files (robots.txt, sitemap.xml, .well-known)
   ├── API endpoints (OpenAPI/Swagger detection)
   └── Technology fingerprint (headers, body patterns)
3. Report: Sitemap tree với discovered items marked

Implementation:
- Spider: BFS crawl với scope filtering
- Parameter Fuzzer: Fuzz common param names (id, user, admin, debug)
- File Discovery: Check common files (backup, config, env)
- API Discovery: Parse OpenAPI/Swagger specs
```

**Chi tiết Intruder Engine:**

```
Architecture:
┌─────────────────────────────────────────────────────────────┐
│                    Intruder Engine                           │
├─────────────────────────────────────────────────────────────┤
│  Position Marker Parser                                      │
│  └── Parse request, identify payload positions (§marker§)   │
│                                                             │
│  Attack Modes:                                               │
│  ├── Sniper:     1 position, 1 payload set                  │
│  ├── Battering Ram: N positions, same payload               │
│  ├── Pitchfork:  N positions, N payload sets (parallel)     │
│  └── Cluster Bomb: N positions, N payload sets (cartesian)  │
│                                                             │
│  Payload Processing:                                         │
│  ├── Built-in字典 (SQLi, XSS, IDOR, JWT, Auth Bypass)     │
│  ├── Custom payload lists (file upload)                     │
│  ├── Number range (1-1000, step 1)                          │
│  ├── DateTime range                                          │
│  └── Recursive grep (extract from responses)                │
│                                                             │
│  Execution (Rust-powered):                                   │
│  ├── Tokio async runtime → concurrent requests              │
│  ├── Per-host rate limiting (Governor)                      │
│  ├── Request dedup (MD5 fingerprint)                        │
│  ├── Budget tracker (request cap + wall-clock)              │
│  └── CancellationToken for immediate stop                   │
│                                                             │
│  Results:                                                    │
│  ├── Real-time WebSocket streaming                          │
│  ├── Response diff (highlight differences)                  │
│  ├── Status code distribution                               │
│  ├── Response length distribution                           │
│  └── Error pattern detection                                │
└─────────────────────────────────────────────────────────────┘

Performance (vs Burp Suite):
- Burp Intruder: ~50 requests/sec (rate-limited in Pro)
- AnToanAI Intruder: ~500+ requests/sec (Rust async, no rate limit)
```

**Chi tiết OOB (Out-of-Band) Detection:**

```
Architecture:
┌─────────────────────────────────────────────────────────────┐
│              OOB Detection System                            │
├─────────────────────────────────────────────────────────────┤
│  Callback Infrastructure:                                    │
│  ├── DNS Server (optional, embedded or external)            │
│  │   └── Listen for DNS queries to *.oast.pro               │
│  ├── HTTP Server (optional, embedded or external)           │
│  │   └── Listen for HTTP callbacks                          │
│  └── Unique payload generation                              │
│      └── {random}.oast.pro → track interactions             │
│                                                             │
│  Detection Capabilities:                                     │
│  ├── SSRF: Inject URL → detect HTTP callback                │
│  ├── Blind SQLi: Inject DNS query → detect DNS callback     │
│  ├── Blind XSS: Inject callback URL → detect HTTP callback  │
│  ├── XXE: Inject external entity → detect callback          │
│  ├── RCE: Inject command with callback → detect             │
│  └── File Read: Inject file:// with callback → detect       │
│                                                             │
│  Integration with Scanner:                                   │
│  ├── Pre-scan: Generate unique callback URLs                │
│  ├── During scan: Monitor callback log                      │
│  └── Post-scan: Correlate callbacks with payloads           │
│                                                             │
│  Options:                                                    │
│  ├── Embedded: Run DNS+HTTP server trong AnToanAI           │
│  └── External: Use oast.pro, interactsh.com, burpcollabor  │
└─────────────────────────────────────────────────────────────┘
```

#### B. RAG + CVE Intelligence (Đề xuất mới)

| Tính năng | Mô tả | Ưu tiên |
|-----------|-------|---------|
| **CVE Database Integration** | Kết nối NVD (National Vulnerability Database) API, tự động download và index CVE data | 🔴 Cao |
| **RAG CVE Analysis** | Sử dụng RAG (Retrieval-Augmented Generation) để phân tích CVE liên quan đến target endpoints | 🔴 Cao |
| **Real-time CVE Enrichment** | Tự động làmrich findings với CVE IDs, CVSS scores, exploit availability | 🟡 Trung bình |
| **SBOM Analysis** | Import Software Bill of Materials, detect vulnerable components | 🟡 Trung bình |
| **Vietnamese CVE Database** | Xây dựng database CVE tiếng Việt với hướng dẫn remediation chi tiết | 🟢 Thấp |

**Chi tiết RAG CVE Analysis:**

```
Workflow:
1. Capture traffic → Extract technology fingerprints (headers, body patterns)
2. Query NVD API → Find CVEs matching detected technologies
3. RAG Pipeline → Combine CVE data with captured traffic context
4. AI Analysis → Generate security assessment with:
   - CVE-ID liên quan
   - CVSS score và severity
   - Exploit availability check
   - Remediation guidance (tiếng Việt)
5. Report → Tích hợp findings với CVE intelligence
```

#### C. Advanced Fuzzing Features

| Tính năng | Mô tả | Ưu tiên |
|-----------|-------|---------|
| **OOB (Out-of-Band) Detection** | Tương tự Burp Collaborator - detect SSRF, blind SQLi, blind XSS qua DNS/HTTP callbacks | 🔴 Cao |
| **Payload Generation Engine** | AI-powered payload generation dựa trên context (parameter type, framework, WAF) | 🟡 Trung bình |
| **WAF Detection & Bypass** | Nhận diện WAF (Cloudflare, Akamai, ModSecurity) và auto-generate bypass payloads | 🟡 Trung bình |
| **Smart Fuzzing** | Fuzzing thông minh dựa trên response patterns (nếu 429 → slow down, nếu 200 → explore deeper) | 🟡 Trung bình |

#### C2. UX Features (tham khảo từ Caido & Burp Suite)

| Tính năng | Mô tả | Ưu tiên |
|-----------|-------|---------|
| **Advanced HTTP History Filtering** | Filter builder với AND/OR logic kết hợp nhiều tiêu chí (method, extension, string trong request/response) | 🔴 Cao |
| **Match & Replace Testing** | Test trực tiếp rules trước khi save (tương tự Caido) | 🔴 Cao |
| **Sequencer** | Phân tích session token randomness (entropy, charset, pattern) - tương tự Burp Sequencer | 🟡 Trung bình |
| **Comparer** | Diff hai requests/responses, highlight differences - tương tự Burp Comparer | 🟡 Trung bình |
| **Decoder** | Encode/decode data (Base64, URL, HTML, Hex) - tương tự Burp Decoder | 🟡 Trung bình |
| **Convert/Transform Tools** | CyberChef-like nodes (Base64, MD5, SHA, URL encode, JWT decode) dùng trong Replay và Workflow | 🟡 Trung bình |
| **Remote CLI Connection** | Chạy Axum server trên VPS, kết nối qua browser từ xa | 🟡 Trung bình |
| **Tab Collections** | Tổ chức Repeater tabs thành folders/collections dễ quản lý | 🟢 Thấp |
| **Project Management** | Multi-project support thay vì single session | 🟢 Thấp |

#### D. Integration & Automation

| Tính năng | Mô tả | Ưu tiên |
|-----------|-------|---------|
| **CI/CD Integration** | Export findings sang JSON/SARIF, tích hợp GitHub Actions, GitLab CI | 🔴 Cao |
| **OpenAPI/Postman Import** | Import OpenAPI spec, Postman collections để auto-generate test targets | 🔴 Cao |
| **GraphQL Support** | Hỗ trợ GraphQL API testing (introspection query, query fuzzing) | 🟡 Trung bình |
| **Plugin/Extension System** | Cho phép community contribute skills và custom analyzers | 🟢 Thấp |

#### E. AI-Powered Features

| Tính năng | Mô tả | Ưu tiên |
|-----------|-------|---------|
| **AI Exploit Generation** | Tự động tạo exploit code từ findings (Python/cURL scripts) | 🟡 Trung bình |
| **Context-Aware Testing** | AI phân tích business logic để tạo test cases thông minh hơn | 🟡 Trung bình |
| **Auto-Reproduction** | Tự động reproduce findings để xác nhận (proof-based validation) | 🟡 Trung bình |
| **Risk Scoring** | AI-powered risk scoring dựa trên 220+ data points (tương tự Invicti) | 🟢 Thấp |

#### F. Reporting & Compliance

| Tính năng | Mô tả | Ưu tiên |
|-----------|-------|---------|
| **HTML Report** | Xuất báo cáo HTML chuyên nghiệp với executive summary | 🔴 Cao |
| **SARIF Export** | Xuất sang SARIF format để tích hợp GitHub Code Scanning | 🟡 Trung bình |
| **Compliance Mapping** | Map findings sang OWASP Top 10, OWASP API Top 10, PCI DSS, HIPAA | 🟡 Trung bình |
| **PDF Report** | Xuất báo cáo PDF với charts và statistics | 🟢 Thấp |

---

### 5.4 Roadmap đề xuất

**Phase 6 (Q3 2026):**
- Intruder Engine (position markers, attack types, ~500+ req/sec)
- OOB Detection (DNS/HTTP callbacks)
- Content Discovery (auto crawl, hidden endpoints)
- Session Handling Rules
- HTML Report generation
- Advanced HTTP History Filtering (AND/OR logic)
- Match & Replace Testing

**Phase 7 (Q4 2026):**
- CVE Database Integration (NVD API)
- RAG CVE Analysis
- OpenAPI/Postman Import
- CI/CD Integration (SARIF export)
- Sequencer (session token analysis)
- Comparer (diff requests/responses)
- Decoder (Base64, URL, HTML, Hex)
- Convert/Transform Tools (Base64, MD5, SHA, JWT decode)
- Remote CLI Connection

**Phase 8 (Q1 2027):**
- GraphQL Support
- WAF Detection & Bypass
- AI Exploit Generation
- Plugin/Extension System
- Tab Collections
- Project Management
- Task Scheduling

**Phase 9 (Q2 2027):**
- SBOM Analysis
- Compliance Mapping
- Vietnamese CVE Database
- Risk Scoring Engine

---

## 6. Công nghệ sử dụng

### 6.1 Backend (Rust)

| Thành phần | Công nghệ | Phiên bản |
|------------|-----------|-----------|
| Language | Rust | Edition 2024, rust-version 1.89 |
| Async Runtime | Tokio | 1.x |
| HTTP Framework | Axum | 0.8 |
| HTTP Client | Hyper | 1.0 |
| TLS | rustls + rcgen | 0.23 + 0.13 |
| Database | SQLite (SQLx) | 0.8 |
| Serialization | Serde + serde_json | 1.x |
| CLI | Clap | 4.5 |
| Rate Limiting | Governor | 0.8 |
| Compression | flate2 + brotli | 1.x + 7.x |

### 6.2 Frontend

| Thành phần | Công nghệ |
|------------|-----------|
| Framework | Vanilla JavaScript (Web Components - Custom Elements) |
| Module System | ES Modules (import/export) |
| Build Tool | Không có - files phục vụ trực tiếp qua Axum `ServeDir` |
| Styling | CSS với Custom Properties (CSS Variables) |
| Real-time | WebSocket (auto-reconnect, 3s backoff) |
| State Management | Custom pub/sub store (không framework) |
| Component Architecture | 16 Web Components (`extends HTMLElement`, `customElements.define()`) |

### 6.3 AI Integration

| Thành phần | Công nghệ |
|------------|-----------|
| AI Provider | DeepSeek API (OpenAI-compatible) |
| Model | deepseek-v4-flash |
| Max Tokens | 2000 |
| Timeout | 60s |

---

## 7. Đối tượng sử dụng

### 7.1 Người dùng chính

- **Security Testers & Penetration Testers**: Cần công cụ thay thế Burp Suite/Caido
- **Web Application Developers**: Kiểm tra API của riêng mình
- **Security Researchers**: Phân tích traffic và data exposure
- **Giảng viên & Sinh viên**: Học và giảng dạy web security

### 7.2 Use Cases

1. **Intercepting HTTP/HTTPS Traffic**: Bắt giữc và phân tích traffic từ trình duyệt
2. **Detecting Sensitive Data Leaks**: Phát hiện password, token, PII trong API responses
3. **AI-Assisted Security Testing**: Tự động tạo và thực thi security test plans
4. **Workflow Automation**: Định nghĩa và chạy multi-step API test sequences
5. **Generating Security Reports**: Tạo báo cáo và evidence cho findings
6. **Learning & Teaching**: Học và giảng dạy web security (UI tiếng Việt)

---

## 8. So sánh với công cụ tương tự

### 8.1 So sánh với Burp Suite

| Tiêu chí | AnToanAI | Burp Suite |
|----------|----------|------------|
| Mã nguồn | Open-source (MIT) | Closed-source |
| Giá | Miễn phí | $449/năm (Pro) |
| AI Integration | ✅ DeepSeek/OpenAI | ❌ Không có |
| Vietnamese UI | ✅ Có | ❌ Không có |
| Weight | 11 MB exe, 8 MB RAM | ~300 MB |
| learning Curve | Trung bình | Cao |

### 8.2 So sánh với OWASP ZAP

| Tiêu chí | AnToanAI | OWASP ZAP |
|----------|----------|-----------|
| Ngôn ngữ | Rust | Java |
| AI Integration | ✅ DeepSeek/OpenAI | ❌ Không có |
| Vietnamese UI | ✅ Có | ❌ Không có |
| Weight | 11 MB exe | ~200 MB |
| Performance | Cao | Trung bình |

### 8.3 So sánh với Caido

| Tiêu chí | AnToanAI | Caido |
|----------|----------|-------|
| Mã nguồn | Open-source (MIT) | Closed-source |
| Giá | Miễn phí | $12/tháng |
| AI Integration | ✅ DeepSeek/OpenAI | ❌ Không có |
| Vietnamese UI | ✅ Có | ❌ Không có |
| Workflow Engine | ✅ DAG-based | ❌ Không có |

### 8.4 Điểm độc đáo của AnToanAI

1. **AI-First Security Testing**: Tự động tạo security test plans từ captured traffic
2. **Vietnamese-Language Reporting**: Tất cả verdicts, explanations, remediation bằng tiếng Việt
3. **Lightweight Architecture**: 11 MB executable, 8 MB runtime RAM
4. **Production-Grade Safety**: Mandatory target allowlist, per-host rate limiting, budgets
5. **Clean Architecture**: Hexagonal/ports-and-adapters, zero framework dependencies

---

## 9. Thống kê codebase

| Thành phần | Số lượng |
|------------|----------|
| Rust Crates | 17 library + 2 application |
| Rust Files | ~200 files |
| JavaScript Components | 16 components |
| CSS Files | 9 files |
| REST API Routes | 35+ routes |
| Unit Tests | 100+ tests |
| Integration Tests | 20+ tests |
| Lines of Code (Rust) | ~25,000 lines |
| Lines of Code (JS) | ~5,000 lines |

---

## 10. Kết luận

AnToanAI đã triển khai các tính năng cốt lõi bao gồm MITM proxy, security analysis engine, vulnerability scanner, AI integration, workflow engine và web dashboard. Hệ thống sử dụng kiến trúc Hexagonal với 17 Rust crates và 11 Web Components.

Các tính năng đang trong giai đoạn hoàn thiện bao gồm CLI commands, một số UI views (Scanner, Reports), và các tính năng nâng cao như Intruder Engine, OOB Detection, Content Discovery.

Dự án được xây dựng với các nguyên tắc:
- AI-powered security testing
- Vietnamese-language interface
- Lightweight, high-performance architecture
- Production-grade safety guardrails
- Clean, extensible codebase

---

*Báo cáo được tạo ngày: 24/08/2026*
*Phiên bản: 0.1.0*
