# Analysis Upgrade Plan — OverfetchingAnalyzer & Entropy Detection

> Nguồn nghiên cứu: Tavily (EDEFuzz ICSE 2024, tiered PII detection stack,
> entropy false-positive filtering, oversized-payload detector D5).
> Bối cảnh: phát hiện thật từ DB history — `/codelab/contests?_rsc` 349KB chứa
> 6 plaintext passwords + 826 `"email"` mà SecretScanner không flag (đúng thiết kế),
> OverfetchingAnalyzer chỉ bắt một phần.

## Quyết định đã chốt

1. **Entropy ngưỡng bảo thủ**: min-length **28**, **≥ 4.7 bits/char**, kèm loại trừ
   MongoDB ObjectId (24-hex), MD5/SHA-1/SHA-256 (32/40/64-hex), UUID-shaped,
   key family `id/hash/etag/checksum/cursor/...`, cap 20 findings/body.
2. **Phase 3 (account diffing kiểu EDEFuzz) = future work** — cần tích hợp auth crate.
3. Config section: **`[analysis]`** trong config.json, serde defaults → config cũ vẫn chạy.

## Phase 1 — Signals mới (OverfetchingAnalyzer)

- [x] **#1** `AnalysisConfig` (8 ngưỡng default) + `AppConfig.analysis` + validate
      — crates/domain/src/config.rs; exports qua domain/lib.rs ✅
- [x] **#2** Module `entropy.rs`: `shannon_entropy()` + `scan_high_entropy_values()`
      + bộ loại trừ ObjectId/MD5/UUID/key-blocklist, bounded walk 20k nodes
      — crates/analysis/src/entropy.rs (mới) ✅
- [x] **#3** Signal mới trong overfetching.rs:
      - `oversized_response:bytes=N` (>100KB) ✅
      - `mass_pii_exposure:emails=N` (census email regex, >10 unique) ✅
      - `mass_exposure:entities=N` (mảng gốc >50 objects) ✅
      - `high_entropy_value:key=...,len=N` (tier từ #2) ✅
- [x] **#4** Bỏ `take(10)` → bounded 500 item; `nested_entity` chỉ fire khi array
      chứa object; thêm `analyze_with(body, content_type)` (giữ `analyze()` delegate) ✅
- [x] **#4b** Signal `pagination_incomplete:current=N,total=M` + `has_next=true`
      (census regex trên raw body; chỉ fire khi còn trang chưa lấy) ✅
      - Data thật: payload contests 349KB → `pagination_incomplete:current=1,total=2`

## Phase 2 — Plumbing & tích hợp

- [x] **#5** `init_analysis_config()` gọi lúc startup sau `ConfigLoader::load`
      (main.rs); lõi phân tích refactor thành `analyze_with_config(body, ct, &cfg)`
      thuần để test không đụng global state ✅
      - Tests: custom long_text/email/size/entropy thresholds đổi hành vi detect ✅
- [ ] **#6** security_prompt.rs: trigger rule mới → flaw `excessive_data_exposure`
- [x] **#7** Xác minh cuối: 110 tests pass (domain+analysis+server+storage);
      clippy 0 errors; build exe OK (đã tắt server cũ PID 29356);
      fix phụ: thiếu `#[async_trait]` impl AnnotationRepository (storage),
      `.keys()`→`.iter()` BTreeSet (serialization sitemap dở) ✅

## Phase 3 — Khái quát hóa đa site (flat v1) — CHỐT

> Mục tiêu: bỏ hardcode FIT-specific, detector hoạt động với mọi target.
> Research: Datadog Sensitive Data Scanner (từ điển key theo nhóm), Presidio
> (confidence scoring + validation hậu kiểm giảm FP ~80%), PII Crawler
> (Luhn/proximity), TrueFoundry (tiered stack).

- [x] **G1** Module `sensitive_taxonomy.rs` ✅ (6 nhóm + `custom`, builtin excluded
      gồm cursor/pageToken/**className**)
- [x] **G2** Validators: `luhn_valid` / `phone_like` (VN) / `value_is_meaningful`
      (placeholder-filter) ✅
- [x] **G3** `sensitive_field:<nhóm>:key=<k>` + credential collection mở rộng +
      fallback/RSC chuyển taxonomy-driven (legacy alias giữ nguyên) ✅
- [x] **G4** Config flat: `extra_sensitive_keys` (nhóm `custom`, matching bỏ
      separator nên `so_tai_khoan` khớp `soTaiKhoan`) + `excluded_keys` ✅
- [x] **G5** `sensitive_in_collection` (body-shape proxy) ✅
- [x] **G5b — PIVOT theo yêu cầu**: signal chính là **`api_payload_in_html:bytes=N`**
      thuần cấu trúc — HTML/RSC chứa ≥1KB JSON parse được = lỗi render API vào
      HTML, **không phụ thuộc từ điển** (trang tử vi/unknown vocab vẫn bắt).
      Raw `text/x-component` stream được extract qua StreamDeserializer
      (`id:{...}` nối tiếp từng dòng). Dictionary chỉ còn vai trò annotation.
- [ ] **G6** security_prompt triggers — DEFER (user thu gọn scope)
- [x] **G7** Tests: tử-vi unknown-vocab fixture, small-html negative, JSON-API
      negative, taxonomy/validators unit tests; FIT regression pass ✅
      - Fix phụ: serde default `max_entropy_findings`; test RSC escape `\"`

## Future work

- **Nâng cấp lên host profiles**: thiết kế taxonomy hiện tại là phẳng; sau này
  muốn scope từ khóa theo host chỉ cần chèn thêm một lớp tra cứu
  `host→extra_keys` ở rìa (trước khi gọi classify_key) — lõi detector không đổi.
- Metamorphic account diffing (EDEFuzz): 2 account khác quyền → diff response
  cùng endpoint; field chênh lệch = leak. Cần auth crate orchestration.
- Phone VN census (format nhiễu, tạm hoãn).

## Phase 4.5 — Fix từ test thực tế ngoài FIT (truyen-cua-phi.vercel.app + alo.html)

- [x] **F-A: HTML minified 1 dòng** — 25 push `self.__next_f` dồn trên 1 line
      làm `find('(')/rfind(')')` per-line grab toàn bộ doc → parse fail, mất
      100% payload. Fix: `balanced_bracket_end()` — quét từng occurrence
      `self.__next_f.push(`, đếm ngoặc `[` `]` string-aware (bỏ qua ngoặc
      trong `"..."` + escape `\"`). Test: 2 push liền kề + `(` trong markup ✅
- [x] **F-B: Livewire (Laravel Filament)** — `wire:snapshot="{&quot;...&quot;}"`
      HTML-escaped JSON trong attribute chưa được extract → thêm extractor
      thứ 3 (`html_decode` + regex), bắt được 2.1KB component state
      (cartItems/mountedActions) trên alo.html ✅
      - Framework coverage hiện tại: Next App Router (`__next_f`) · Next Pages
        Router (`__NEXT_DATA__`) · raw x-component (Flight rows) · Livewire
        (`wire:snapshot`)
- [x] **F-C: Entropy blocklist đồng bộ taxonomy** — thêm `classname/class_name`
      vào `EXCLUDED_KEY_FRAGMENTS` của entropy (FP CSS class dài) ✅
- [x] Dead code: xóa `try_parse_unescaped_json_chunks` (không còn caller sau
      khi `__next_f` chuyển sang `parse_flight_rows`) ✅
- [x] **F-D: `auth_qr_in_html`** — phát hiện QR ĐĂNG NHẬP TỰ ĐỘNG nhúng trong
      page source (bearer credential sống theo expiry). Điều kiện AND 2 vế để
      precision: text hint (`automatically logged in|scan the qr|auto-login`)
      + inline image ≥200 chars (`data:image/png|svg;base64`). Bắt được trên
      alo.html thật: Moodle LMS NEU `/user/profile.php?id=54045` nhúng QR
      login 612 bytes PNG, expire 10 phút ✅
- [x] **F-E: FP RSC phổ quát** — `__html` (React dangerouslySetInnerHTML) vào
      entropy excluded; bỏ `hidden` khỏi privacy-fragments (UI attribute,
      không phải authz flag). Test lại trang LMS 34KB: signals còn lại toàn
      structural hợp lệ ✅

## FP đã xác nhận (không fix — by design)

- `gitleaks_leak:generic-api-key` trên Cloudflare beacon (`data-cf-beacon`
  token) — public identifier, FP kinh điển của gitleaks defaults
- `data-csrf` Laravel/Livewire trong page của chính session — by design
- `eyJ` trùng trong tên file tĩnh (`...NjeyJcb20....webp`) — trùng ngẫu nhiên

## Phase 4 — Nhóm A (FP·FN) — HOÀN TẤT

> Research: Flight row spec (`<id>:<tag?><payload>`, Smashing Magazine 7/2026 +
> 0xdevalias gist) · Presidio ContextAwareEnhancer (base score + context boost).

- [x] **A1** Boundary matching: fragment ≤4 ký tự chỉ khớp word nguyên vẹn/
      ends_with (qua `key_words` tách separator + camelCase); thêm `prepare`
      vào excluded (`preparedStatement`); `className` FP tự hết ✅
- [x] **A2** JSON numbers: `payment` (Luhn) / `pii_gov_id` (`gov_id_like`
      9–12 digits) / `pii_contact` (phone) nhận number; credential/answer
      vẫn string-only ✅
- [x] **A3** Two-tier render signal: `api_payload_in_html` (Info, structural)
      + `sensitive_payload_in_html` (High, có sensitive_field/exposed context)
      — Presidio-style context boost ✅
- [x] **A4** `embedded_payload_min_bytes` config (default 1024, validate >0) ✅
- [x] **A5** `parse_flight_rows()` đúng Flight spec: quét row-start `digits:`,
      skip tag chữ cái, parse 1 value + `byte_offset()` nhảy qua — sửa bug
      StreamDeserializer thuần đọc nhầm row-id kế tiếp thành Number ✅
      Áp dụng cho cả raw x-component lẫn `__next_f` string items ✅
- [x] **A6** Nhóm `custom` join `exposed_passwords` + `sensitive_in_collection` ✅
- [x] **Bonus fix phát hiện khi test**: Array arm của walk KHÔNG recurse vào
      object con bên trong items (bug từ gốc — nested fields trong mảng chỉ
      được cứu nhờ raw-string scan) → đã thêm recursion ✅
      Fallback presence census thu hẹp còn `answer_content` (chặn FP
      `payment:present` trên key trống) ✅

## Kết quả Phase 4 trên data thật (contests 349KB)

Signals mới so với Phase 3: `sensitive_payload_in_html:bytes=274987` (High),
`sensitive_field:answer_content:key=solution` ×n — **phát hiện mới: lời giải
(solution) bị expose trong trang danh sách**, `sensitive_field:credential:key=password`,
`sensitive_in_collection`, `exposed_passwords_count:6` chính thức vào signals,
`mass_exposure:entities=64`, `nested_entity:contests/problems/signUps`.

## Trạng thái xác minh hiện tại

- `cargo test` (domain + analysis + server): **113 passed** (Phase 4: +14 tests)
- `cargo clippy --all-targets`: 0 errors mới
- Build exe thành công sau khi tắt server cũ; config `[analysis]` được nạp lúc startup
- Data thật (`db_secret_scan --path contests`, payload 349KB):
  - `sensitive_payload_in_html:bytes=274987` (High tier) + `api_payload_in_html` (Info)
  - `sensitive_field:answer_content:key=solution` — lời giải leak (finding mới)
  - `mass_pii_exposure:emails=307`, `exposed_passwords_count:6`,
    `pagination_incomplete:current=1,total=2`, `sensitive_in_collection`
- Full scan 57 flows: cold ~23s / warm cached ~400µs
