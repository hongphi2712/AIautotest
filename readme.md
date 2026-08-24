# AnToanAI - Nền tảng Kiểm thử Bảo mật API Tự động

---

## 1. Thông tin đề tài

| Thông tin | Giá trị |
|-----------|---------|
| Tên đề tài | AnToanAI - Nền tảng Kiểm thử Bảo mật API Tự động |
| Phiên bản | 0.1.0 |
| Ngôn ngữ chính | Rust (Edition 2024) + JavaScript |
| Giấy phép | MIT |
| Tác giả | API-AutoTester Team |

---

## 2. Mô tả dự án

**AnToanAI** (An Toàn AI) là nền tảng kiểm thử bảo mật API tự động được hỗ trợ bởi trí tuệ nhân tạo, được viết bằng Rust. Hệ thống kết hợp khả năng bắt giữc HTTP/HTTPS proxy, phân tích traffic thông minh, phát hiện lỗ hổng tự động và báo cáo bảo mật bằng tiếng Việt.

**Đặc điểm nổi bật:**
- Mã nguồn mở, miễn phí (thay thế Burp Suite/$449/năm)
- Nhẹ và nhanh (11 MB exe, 8 MB RAM vs Burp 300 MB)
- AI-powered analysis (DeepSeek/OpenAI integration)
- Báo cáo tiếng Việt
- Kiến trúc Hexagonal, dễ mở rộng

---

## 3. Vấn đề giải quyết

| Vấn đề hiện tại | Giải pháp của AnToanAI |
|-----------------|------------------------|
| Burp Suite đắt đỏ ($449/năm Pro) | Mã nguồn mở, miễn phí hoàn toàn |
| Burp Suite nặng, lag (~300 MB RAM) | Rust runtime, chỉ 11 MB exe, 8 MB RAM |
| Không có AI integration | DeepSeek/OpenAI-powered analysis & test plan generation |
| Báo cáo chỉ có tiếng Anh | Vietnamese-language verdicts, explanations, remediation |
| Không có workflow automation | DAG-based workflow engine với 6 node types |
| Fingerprinting thủ công | Auto content discovery, technology detection |
| Thiếu CVE intelligence | RAG CVE Analysis với NVD integration (planned) |
| Intruder bị rate-limit (Burp Free) | Intruder ~500+ req/sec, không rate-limit (Rust async) |

---

## 4. Tính năng chính

### 4.1 Đã triển khai (95%)

#### Core Infrastructure
| Tính năng | Mô tả |
|-----------|-------|
| MITM HTTP/HTTPS Proxy | Bắt giữc traffic trên port 8080, chứng chỉ TLS tự động |
| Certificate Management | Tạo CA, cấp chứng chỉ theo host, cài đặt Windows |
| Flow Capture | Buffer Ring, dedup fingerprint, SQLite storage |
| Scope Filtering | Include/exclude hosts/paths bằng regex |
| Match & Replace | Sửa đổi request/response theo rules |
| Intercept Controller | Tạm dừng request để edit/forward/drop |
| WebSocket Real-time | Push events flows, intercept, workflow |
| Session Management | Start/stop/delete/clear capture sessions |

#### Security Analysis Engine
| Tính năng | Mô tả |
|-----------|-------|
| Secret Scanner | Gitleaks CLI + Built-in Regex (AWS, OpenAI, Google keys) |
| CWE Detector | CWE-215, CWE-209, CWE-284 |
| Overfetching Detector | Mass exposure, RSC/Next.js/Livewire analysis |
| Sensitive Taxonomy | 6 groups (Credentials, PII, Payment...) + validators |
| Entropy Analysis | Shannon entropy detection (4.7+ bits/char) |
| Token Extractor | JWT, OAuth, API key, CSRF extraction |
| Dependency Mapper | Map token dependencies giữa flows |
| Flow Sequencer | Topological sort (Kahn's algorithm) |

#### Vulnerability Scanner
| Tính năng | Mô tả |
|-----------|-------|
| SQLi Scanner | 6 payloads (tautology, union, boolean, time-based) |
| XSS Scanner | 5 payloads (script, event handler, svg, attribute breakout) |
| IDOR Scanner | 5 payloads (zero, first, large, negative, leading-zero) |
| JWT Attack | 3 payloads (alg none, guessable sig, admin role) |
| Auth Bypass | 4 payloads (admin, true, 1, administrator) |
| Budget Tracker | Request cap + wall-clock budget |
| Rate Limiter | Per-host token bucket (Governor) |
| Scope Guard | Enforce scope allowlisting |

#### AI Integration
| Tính năng | Mô tả |
|-----------|-------|
| DeepSeek Client | OpenAI-compatible chat completions |
| Security Test Plans | Auto-generate từ captured traffic |
| Workflow Generation | Tạo workflow từ natural language |
| Bounded Repair Loops | AI → parse → validate → retry (max 3) |

#### Workflow Engine
| Tính năng | Mô tả |
|-----------|-------|
| DAG Execution | 6 node types: http_request, extract, assert, delay, condition, loop |
| Template Rendering | `{{variable}}` syntax trong path/headers/body |
| JSONPath Resolver | Custom JSONPath extraction |
| Validation | Cycle detection, scope checking |

#### Web Dashboard
| Component | Mô tả |
|-----------|-------|
| Dashboard | Summary stats, findings export |
| Target (Sitemap) | Tree view, filtering, annotations |
| Proxy | Intercept, HTTP History, Settings |
| Repeater | Tabbed request editing, Pretty/Raw/Hex |
| Analyzer | Flow diagram, Dependencies, AI Analysis |
| 16 Web Components | Vanilla JS, WebSocket, no framework |

### 4.2 Chưa triển khai (Đề xuất)

| Tính năng | Mô tả | Ưu tiên |
|-----------|-------|---------|
| **Intruder Engine** | Payload injection, ~500+ req/sec (vs Burp ~50) | 🔴 Cao |
| **OOB Detection** | DNS/HTTP callbacks (tương tự Burp Collaborator) | 🔴 Cao |
| **Content Discovery** | Auto crawl, discover hidden endpoints | 🔴 Cao |
| **RAG CVE Analysis** | CVE intelligence với NVD integration | 🔴 Cao |
| **Advanced Filtering** | AND/OR logic cho HTTP History | 🔴 Cao |
| **CI/CD Integration** | SARIF export, GitHub Actions | 🔴 Cao |
| **OpenAPI Import** | Import OpenAPI/Postman specs | 🔴 Cao |
| **Sequencer** | Session token randomness analysis | 🟡 TB |
| **Comparer** | Diff requests/responses | 🟡 TB |
| **Decoder** | Base64, URL, HTML, Hex encoding | 🟡 TB |
| **WAF Detection** | Nhận diện và bypass WAF | 🟡 TB |
| **AI Exploit Gen** | Tự động tạo exploit code | 🟡 TB |

---

## 5. Sơ đồ kiến trúc

### 5.1 Kiến trúc tổng quan

```
┌─────────────────────────────────────────────────────────────────┐
│                      Web Browser (User)                         │
│                        localhost:2712                            │
└─────────────────────────┬───────────────────────────────────────┘
                          │ HTTP/WebSocket
                          ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Web Dashboard (Vanilla JS)                   │
│  ┌──────────┬──────────┬──────────┬──────────┬──────────┐     │
│  │Dashboard │ Sitemap  │ Proxy    │Repeater  │ Analyzer │     │
│  └──────────┴──────────┴──────────┴──────────┴──────────┘     │
└─────────────────────────┬───────────────────────────────────────┘
                          │ REST API (35+ routes)
                          ▼
┌─────────────────────────────────────────────────────────────────┐
│                   Axum Server (Rust)                             │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │                    Application Layer                     │   │
│  │  ┌──────────┬──────────┬──────────┬──────────┐         │   │
│  │  │  Proxy   │ Capture  │ Analysis │ Scanner  │         │   │
│  │  │ (port    │ (buffer, │ (secrets,│ (SQLi,   │         │   │
│  │  │  8080)   │  SQLite) │  OWASP)  │  XSS)    │         │   │
│  │  └──────────┴──────────┴──────────┴──────────┘         │   │
│  │  ┌──────────┬──────────┬──────────┬──────────┐         │   │
│  │  │Workflow  │    AI    │Security  │Reporting │         │   │
│  │  │ (DAG)    │(DeepSeek)│ (plans)  │(Mermaid) │         │   │
│  │  └──────────┴──────────┴──────────┴──────────┘         │   │
│  └─────────────────────────────────────────────────────────┘   │
├─────────────────────────────────────────────────────────────────┤
│                    Domain Layer (17 crates)                      │
│  ┌─────────┬──────────┬──────────┬──────────┬────────────┐    │
│  │ domain  │  ports   │   ai     │ analysis │  security  │    │
│  │ capture │  proxy   │ scanner  │ workflow │  reporting  │    │
│  │ auth    │ storage  │  query   │  events  │test-support│    │
│  └─────────┴──────────┴──────────┴──────────┴────────────┘    │
├─────────────────────────────────────────────────────────────────┤
│                  Infrastructure Layer                            │
│  ┌─────────┬──────────┬──────────┬──────────┬────────────┐    │
│  │  Axum   │  SQLite  │  Hyper   │  Reqwest │   Tokio    │    │
│  │  Server │  Storage │  Client  │  Client  │   Runtime  │    │
│  └─────────┴──────────┴──────────┴──────────┴────────────┘    │
└─────────────────────────────────────────────────────────────────┘
```

### 5.2 Cấu trúc thư mục

```
AnToanAI/
├── apps/
│   ├── api-tester-cli/          # CLI binary (stub)
│   └── api-tester-server/       # Axum server + UI
│       ├── src/                 # Rust backend (10 modules)
│       └── ui/                  # Frontend (Vanilla JS)
│           ├── js/              # 16 Web Components
│           └── styles/          # CSS (tokens, base, features)
├── crates/                      # 17 library crates
│   ├── domain/                  # Core domain models
│   ├── ports/                   # Trait interfaces (9 async traits)
│   ├── proxy/                   # HTTP/HTTPS MITM proxy
│   ├── capture/                 # Traffic buffering
│   ├── analysis/                # Security analysis engine
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

## 6. Công nghệ sử dụng

### 6.1 Backend

| Thành phần | Công nghệ | Phiên bản |
|------------|-----------|-----------|
| Language | Rust | Edition 2024, rust-version 1.89 |
| Async Runtime | Tokio | 1.x |
| HTTP Framework | Axum | 0.8 |
| HTTP Client | Hyper + Reqwest | 1.0 + 0.12 |
| TLS | rustls + rcgen | 0.23 + 0.13 |
| Database | SQLite (SQLx) | 0.8 |
| Serialization | Serde + serde_json | 1.x |
| CLI | Clap | 4.5 |
| Rate Limiting | Governor | 0.8 |
| Compression | flate2 + brotli | 1.x + 7.x |

### 6.2 Frontend

| Thành phần | Công nghệ |
|------------|-----------|
| Framework | Vanilla JavaScript (Web Components) |
| Module System | ES Modules (import/export) |
| Build Tool | Không có (static files via Axum ServeDir) |
| Styling | CSS Custom Properties |
| Real-time | WebSocket (auto-reconnect) |
| Components | 16 Custom Elements |

### 6.3 AI Integration

| Thành phần | Công nghệ |
|------------|-----------|
| AI Provider | DeepSeek API (OpenAI-compatible) |
| Model | deepseek-v4-flash |
| Max Tokens | 2000 |
| Timeout | 60s |

---

## 7. Thống kê codebase

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
| **Tổng** | **~30,000 lines** |

---

## 8. So sánh với công cụ tương tự

| Tiêu chí | AnToanAI | Burp Suite | OWASP ZAP | Caido |
|----------|----------|------------|-----------|-------|
| Mã nguồn | ✅ MIT | ❌ Closed | ✅ Apache | ❌ Closed |
| Giá | Miễn phí | $449/năm | Miễn phí | $12/tháng |
| AI Integration | ✅ DeepSeek | ❌ | ❌ | ❌ |
| Vietnamese UI | ✅ Có | ❌ | ❌ | ❌ |
| Weight | 11 MB | ~300 MB | ~200 MB | ~50 MB |
| Performance | ⭐⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐⭐ |
| Workflow Engine | ✅ DAG | ❌ | ❌ | ❌ |

---

## 9. Kết luận

AnToanAI đã triển khai đầy đủ các tính năng cốt lõi bao gồm MITM proxy, security analysis engine, vulnerability scanner, AI integration, workflow engine và web dashboard. Hệ thống được xây dựng trên kiến trúc Hexagonal với 17 Rust crates, 11 UI components và 46 REST API routes.

**Các tính năng chính đã hoàn thành:**
- MITM HTTP/HTTPS Proxy với certificate management
- Security Analysis Engine (secret scanner, overfetching detector, entropy analysis)
- Vulnerability Scanner (SQLi, XSS, IDOR, JWT, Auth Bypass)
- AI Integration (DeepSeek/OpenAI-powered test plan generation)
- DAG Workflow Engine (6 node types, template rendering)
- Web Dashboard (7 tabs, 11 components, WebSocket real-time)

**Hạn chế hiện tại:**
- CLI mới chỉ có skeleton (chưa có commands)
- Một số UI views chưa có (Scanner, Reports, WebSockets History)
- Chưa có Intruder Engine, OOB Detection, Content Discovery

**Định hướng phát triển:**
- Triển khai Intruder Engine với tốc độ cao (Rust async)
- Thêm OOB Detection (tương tự Burp Collaborator)
- Tích hợp CVE Intelligence (RAG CVE Analysis)
- Cải thiện Reporting (HTML/SARIF export)

---

