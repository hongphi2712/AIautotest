use api_tester_domain::AnalysisConfig;
use regex::Regex;
use serde_json::Value;
use std::collections::{BTreeSet, HashMap, VecDeque};
use std::hash::{DefaultHasher, Hash, Hasher};
use std::sync::{Arc, Mutex, OnceLock};

use crate::entropy;
use crate::sensitive_taxonomy;

/// Per-array item cap for structural checks; full arrays are still counted
/// for mass-exposure and scanned for passwords via string patterns.
const MAX_ITEMS_PER_ARRAY: usize = 500;
/// Hard bound on walked JSON nodes so adversarial payloads stay cheap.
const MAX_WALKED_NODES: usize = 20_000;

static ANALYSIS_CONFIG: OnceLock<AnalysisConfig> = OnceLock::new();
static HOST_PROFILES: OnceLock<HashMap<String, AnalysisConfig>> = OnceLock::new();
static EMAIL_REGEX: OnceLock<Regex> = OnceLock::new();

const OVERFETCH_CACHE_CAPACITY: usize = 1024;

struct OverfetchCache {
    entries: HashMap<u64, Arc<OverfetchingSignal>>,
    order: VecDeque<u64>,
}

static OVERFETCH_CACHE: OnceLock<Mutex<OverfetchCache>> = OnceLock::new();

fn overfetch_cache() -> &'static Mutex<OverfetchCache> {
    OVERFETCH_CACHE.get_or_init(|| {
        Mutex::new(OverfetchCache {
            entries: HashMap::new(),
            order: VecDeque::new(),
        })
    })
}

fn body_hash(body: &str) -> u64 {
    let mut hasher = DefaultHasher::new();
    body.hash(&mut hasher);
    hasher.finish()
}

fn cached_overfetch(body: &str) -> Option<Arc<OverfetchingSignal>> {
    let cache = overfetch_cache().lock().ok()?;
    cache.entries.get(&body_hash(body)).cloned()
}

fn store_overfetch(body: &str, result: Arc<OverfetchingSignal>) {
    let Ok(mut cache) = overfetch_cache().lock() else {
        return;
    };
    let key = body_hash(body);
    if cache.entries.contains_key(&key) {
        return;
    }
    while cache.entries.len() >= OVERFETCH_CACHE_CAPACITY {
        if let Some(old) = cache.order.pop_front() {
            cache.entries.remove(&old);
        } else {
            break;
        }
    }
    cache.entries.insert(key, result);
    cache.order.push_back(key);
}

/// Installs runtime thresholds (call once at startup after loading config).
/// When never called, conservative built-in defaults apply.
pub fn init_analysis_config(config: AnalysisConfig) {
    let _ = ANALYSIS_CONFIG.set(config);
}

pub fn init_host_profiles(profiles: HashMap<String, AnalysisConfig>) {
    let _ = HOST_PROFILES.set(profiles);
}

fn config() -> &'static AnalysisConfig {
    ANALYSIS_CONFIG.get_or_init(AnalysisConfig::default)
}

pub fn config_for_host(host: Option<&str>) -> &'static AnalysisConfig {
    if let Some(h) = host {
        if let Some(map) = HOST_PROFILES.get() {
            for (pattern, cfg) in map {
                if let Ok(re) = Regex::new(pattern) {
                    if re.is_match(h) {
                        return cfg;
                    }
                } else if pattern == h {
                    return cfg;
                }
            }
        }
    }
    config()
}

fn email_regex() -> &'static Regex {
    EMAIL_REGEX.get_or_init(|| {
        Regex::new(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
            .expect("static email pattern is valid")
    })
}

/// Represents structural anomaly signals detected in an HTTP response body.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OverfetchingSignal {
    pub is_suspicious: bool,
    pub detected_signals: Vec<String>,
    pub exposed_passwords: Vec<String>,
}

/// Domain-agnostic structural analyzer for identifying data over-fetching and exposure anomalies.
pub struct OverfetchingAnalyzer;

impl OverfetchingAnalyzer {
    /// Analyzes a response body (JSON or HTML with embedded RSC/SSR payload) for structural anomalies.
    pub fn analyze(body_str: &str) -> OverfetchingSignal {
        if body_str.trim().is_empty() {
            return OverfetchingSignal::default();
        }
        if let Some(hit) = cached_overfetch(body_str) {
            return (*hit).clone();
        }
        let result = Self::analyze_with_config(body_str, None, config());
        store_overfetch(body_str, Arc::new(result.clone()));
        result
    }

    /// Same analysis with optional content-type awareness: binary media types
    /// skip the oversized-response heuristic (their byte size is expected).
    pub fn analyze_with(body_str: &str, content_type: Option<&str>) -> OverfetchingSignal {
        if body_str.trim().is_empty() {
            return OverfetchingSignal::default();
        }
        // For content-type aware, include content_type in hash by concatenating
        let cache_key = if let Some(ct) = content_type {
            format!("{}\0{}", body_str, ct)
        } else {
            body_str.to_owned()
        };
        if let Some(hit) = cached_overfetch(&cache_key) {
            return (*hit).clone();
        }
        let result = Self::analyze_with_config(body_str, content_type, config());
        store_overfetch(&cache_key, Arc::new(result.clone()));
        result
    }

    /// Pure variant taking explicit thresholds — the testable core; public
    /// entry points only supply the runtime/global configuration.
    fn analyze_with_config(
        body_str: &str,
        content_type: Option<&str>,
        cfg: &AnalysisConfig,
    ) -> OverfetchingSignal {
        let mut signal = OverfetchingSignal::default();
        if body_str.trim().is_empty() {
            return signal;
        }
        let mut walk_stats = WalkStats::default();

        // Response-level heuristics first: total payload size.
        if is_size_checkable(content_type)
            && body_str.len() >= cfg.oversized_response_bytes
        {
            signal
                .detected_signals
                .push(format!("oversized_response:bytes={}", body_str.len()));
        }

        let allow_raw_rsc = content_type
            .is_some_and(|ct| ct.to_lowercase().contains("x-component"));
        let json_values = Self::extract_json_payloads(body_str, allow_raw_rsc);
        walk_stats.top_level_is_array = json_values.first().is_some_and(Value::is_array);

        // 1. Phân tích các JSON Object được parse thành công
        for val in &json_values {
            Self::check_structural_anomalies(
                val,
                &mut signal.detected_signals,
                &mut signal.exposed_passwords,
                &mut walk_stats,
                cfg,
            );
        }

        // 2. Phân tích trực tiếp các thẻ script Next.js RSC Stream payload (`self.__next_f.push`)
        Self::analyze_rsc_stream_payloads(
            body_str,
            &mut signal.detected_signals,
            &mut signal.exposed_passwords,
            cfg,
        );

        // 3. Fallback: Nếu JSON parse thất bại và chưa tìm thấy gì, phân tích trực tiếp trên chuỗi unescaped
        if signal.detected_signals.is_empty() && signal.exposed_passwords.is_empty() {
            Self::fallback_string_analysis(
                body_str,
                &mut signal.detected_signals,
                &mut signal.exposed_passwords,
            );
        }

        // Mass-exposure: largest object array seen anywhere in the tree.
        if walk_stats.max_object_array_len > cfg.mass_entity_count {
            signal.detected_signals.push(format!(
                "mass_exposure:entities={}",
                walk_stats.max_object_array_len
            ));
        }

        // PII census: unique emails across the raw body (JSON, RSC, HTML alike).
        let unique_emails = census_unique_emails(body_str);
        if unique_emails > cfg.mass_email_threshold {
            signal
                .detected_signals
                .push(format!("mass_pii_exposure:emails={unique_emails}"));
        }

        // Pagination census: the body itself declares whether more pages exist
        // (`currentPage:1,totalPages:2`, `hasNextPage:true`). Downstream test
        // planning should walk remaining pages before judging exposure.
        signal
            .detected_signals
            .extend(census_pagination(body_str));

        // API-rendered-in-HTML: structured payloads embedded into render
        // surfaces (SSR HTML, Next.js RSC streams) are the root bug class —
        // whatever the UI shows, the full objects ride along. Detected purely
        // structurally so unknown vocabularies (any domain) are covered;
        // `sensitive_field:*` signals annotate WHICH fields look sensitive.
        let embedded_json_bytes: usize = json_values.iter().map(|v| v.to_string().len()).sum();
        let payload_in_html =
            is_render_surface(content_type) && embedded_json_bytes >= cfg.embedded_payload_min_bytes;
        if payload_in_html {
            signal
                .detected_signals
                .push(format!("api_payload_in_html:bytes={embedded_json_bytes}"));
            // Tier High (Presidio-style context boost): the embedded payload
            // actually carries sensitive fields, not just hydration state.
            let has_sensitive_context = signal
                .detected_signals
                .iter()
                .any(|s| s.starts_with("sensitive_field:"))
                || !signal.exposed_passwords.is_empty();
            if has_sensitive_context {
                signal.detected_signals.push(format!(
                    "sensitive_payload_in_html:bytes={embedded_json_bytes}"
                ));
            }
        }

        // Auto-login QR embedded in page source is a BEARER CREDENTIAL: the
        // HTML alone authenticates anyone as the victim until expiry
        // (e.g. Moodle profile "Mobile app" QR, WeChat-style login QRs).
        if is_render_surface(content_type) && has_login_qr(body_str) {
            signal.detected_signals.push("auth_qr_in_html".to_owned());
        }

        // List-vs-detail sharpening: sensitive core fields (credentials,
        // answers, payment, government IDs) inside a COLLECTION-shaped body
        // (top-level array or paginated list) is the textbook BOPLA pattern —
        // listing endpoints must be leaner than detail views.
        let has_sensitive_core = signal.detected_signals.iter().any(|s| {
            s.starts_with("sensitive_field:credential:")
                || s.starts_with("sensitive_field:answer_content:")
                || s.starts_with("sensitive_field:payment:")
                || s.starts_with("sensitive_field:pii_gov_id:")
                || s.starts_with("sensitive_field:custom:")
        });
        let collection_shape = walk_stats.top_level_is_array
            || !census_pagination(body_str).is_empty()
            || body_str.contains("\"items\":[")
            || body_str.contains("\"data\":[");
        if has_sensitive_core && collection_shape {
            signal
                .detected_signals
                .push("sensitive_in_collection".to_owned());
        }

        // Lọc trùng và sắp xếp danh sách mật khẩu bị lộ
        signal.exposed_passwords.sort();
        signal.exposed_passwords.dedup();

        if !signal.exposed_passwords.is_empty() {
            signal.detected_signals.push(format!("exposed_passwords_count:{}", signal.exposed_passwords.len()));
            signal.detected_signals.push(format!("exposed_passwords_list:{:?}", signal.exposed_passwords));
        }

        signal.detected_signals.sort();
        signal.detected_signals.dedup();
        signal.is_suspicious = !signal.detected_signals.is_empty();

        signal
    }

    /// Extracts JSON objects from plain JSON bodies, embedded Next.js RSC /
    /// __NEXT_DATA__ HTML script tags, and (for `text/x-component` streams)
    /// raw `id:{...}` RSC lines that carry objects without any script wrapper.
    fn extract_json_payloads(body: &str, allow_raw_rsc: bool) -> Vec<Value> {
        let mut results = Vec::new();
        let trimmed = body.trim();

        // Direct JSON response
        if (trimmed.starts_with('{') && trimmed.ends_with('}'))
            || (trimmed.starts_with('[') && trimmed.ends_with(']'))
        {
            if let Ok(val) = serde_json::from_str::<Value>(trimmed) {
                results.push(val);
                return results;
            }
        }

        // Next.js App Router (self.__next_f.push) & Pages Router (__NEXT_DATA__)
        // payload parsing. Minified pages put dozens of pushes on ONE line, so
        // occurrences are scanned individually with a string-aware balanced
        // bracket extraction — first-paren/last-paren slicing would grab the
        // whole document and fail to parse.
        if body.contains("self.__next_f") {
            let needle = "self.__next_f.push(";
            let mut search_from = 0usize;
            while let Some(offset) = body[search_from..].find(needle) {
                let push_at = search_from + offset;
                let arg_start = push_at + needle.len();
                let Some(arg_end) = balanced_bracket_end(body, arg_start) else {
                    search_from = push_at + needle.len();
                    continue;
                };
                if let Ok(val) = serde_json::from_str::<Value>(&body[arg_start..arg_end]) {
                    if let Some(arr) = val.as_array() {
                        for item in arr {
                            if let Some(s) = item.as_str() {
                                // Each string item carries Flight rows
                                // (`3:{...}4:{...}`) concatenated.
                                parse_flight_rows(s, &mut results);
                            }
                        }
                    }
                }
                search_from = arg_end;
            }
        }
        if body.contains("__NEXT_DATA__") {
            for line in body.lines() {
                if line.contains("__NEXT_DATA__") {
                    if let Some(start_idx) = line.find('{') {
                        if let Some(end_idx) = line.rfind('}') {
                            let json_candidate = &line[start_idx..=end_idx];
                            if let Ok(val) = serde_json::from_str::<Value>(json_candidate) {
                                results.push(val);
                            }
                        }
                    }
                }
            }
        }

        // Laravel Livewire: component state lives in `wire:snapshot="..."`
        // attributes as HTML-escaped JSON (`&quot;` for quotes). Decode then
        // parse so non-Next.js render surfaces are covered too.
        if body.contains("wire:snapshot") {
            static SNAPSHOT_RE: OnceLock<Regex> = OnceLock::new();
            let snapshot_re = SNAPSHOT_RE.get_or_init(|| {
                Regex::new(r#"wire:snapshot="([^"]*)""#).expect("livewire pattern is valid")
            });
            for caps in snapshot_re.captures_iter(body) {
                let decoded = html_decode(&caps[1]);
                if let Ok(val) = serde_json::from_str::<Value>(&decoded) {
                    results.push(val);
                }
            }
        }

        // Raw RSC stream (`text/x-component`): the whole body is a sequence of
        // Flight rows (`<id>:<payload>`), no script wrapper.
        if allow_raw_rsc && results.is_empty() && !body.contains("self.__next_f") {
            parse_flight_rows(body, &mut results);
        }

        results
    }

    /// Phân tích trực tiếp các mảng chuỗi stream trong thẻ `self.__next_f.push` của Next.js
    fn analyze_rsc_stream_payloads(
        body: &str,
        signals: &mut Vec<String>,
        exposed_passwords: &mut Vec<String>,
        cfg: &AnalysisConfig,
    ) {
        if !body.contains("self.__next_f") {
            return;
        }

        let unescaped = body.replace("\\\"", "\"").replace("\\\\", "\\");

        // Quét tất cả các trường "password":"<value>" trong chuỗi JSON/Payload
        collect_exposed_strings(&unescaped, exposed_passwords);

        // Use shared RSC chunk extractor for per-chunk analysis
        let chunks = crate::rsc_chunks::extract_rsc_chunks(body);
        for chunk_str in &chunks {
            // 🎯 Bất thường 1: Văn bản quá dài nén trong RSC chunk
            if chunk_str.chars().count() > cfg.rsc_chunk_chars {
                signals.push(format!(
                    "rsc_long_text_chunk:len={}",
                    chunk_str.len()
                ));
            }

            let chunk_lower = chunk_str.to_lowercase();
            // 🎯 Bất thường 2: Chứa từ khóa/tiêu đề bài tập hoặc cờ phân quyền
            if chunk_lower.contains("đề bài:") || chunk_lower.contains("de bai:") {
                signals.push("rsc_content_leak:problem_statement_header".to_string());
            }
            if sensitive_taxonomy::fragments_for(
                sensitive_taxonomy::ANSWER_CONTENT,
            )
            .unwrap_or(&[])
            .iter()
            .any(|fragment| chunk_lower.contains(fragment))
            {
                signals.push("rsc_content_leak:answer_content".to_string());
            }
            if chunk_lower.contains("status\":\"private") || chunk_lower.contains("isanswerpublic\":false") {
                signals.push("privacy_flag_conflict:private_status".to_string());
            }
        }
    }

    /// Recursively checks JSON values for domain-agnostic structural anomalies.
    /// Array traversal is bounded (`MAX_ITEMS_PER_ARRAY`, `MAX_WALKED_NODES`)
    /// while array lengths still feed the mass-exposure counter.
    fn check_structural_anomalies(
        val: &Value,
        signals: &mut Vec<String>,
        exposed_passwords: &mut Vec<String>,
        stats: &mut WalkStats,
        cfg: &AnalysisConfig,
    ) {
        if stats.visited >= MAX_WALKED_NODES {
            return;
        }
        stats.visited += 1;
        match val {
            Value::Array(arr) => {
                let object_count = arr.iter().filter(|item| item.is_object()).count();
                stats.max_object_array_len = stats.max_object_array_len.max(object_count);
                for item in arr.iter().take(MAX_ITEMS_PER_ARRAY) {
                    Self::check_object_anomalies(item, signals, exposed_passwords, cfg);
                }
                // Recurse into items so objects nested deeper than the item's
                // top level are analyzed too (duplicate visits dedupe away).
                for item in arr.iter().take(MAX_ITEMS_PER_ARRAY) {
                    if item.is_object() || item.is_array() {
                        Self::check_structural_anomalies(
                            item,
                            signals,
                            exposed_passwords,
                            stats,
                            cfg,
                        );
                    }
                }
            }
            Value::Object(obj) => {
                Self::check_object_anomalies(val, signals, exposed_passwords, cfg);
                for (_k, v) in obj {
                    if v.is_array() || v.is_object() {
                        Self::check_structural_anomalies(
                            v,
                            signals,
                            exposed_passwords,
                            stats,
                            cfg,
                        );
                    }
                }
            }
            _ => {}
        }
    }

    /// Checks an individual object item for structural anomalies:
    /// privacy-flag conflicts, exposed passwords, nested entities with real
    /// child objects, high-entropy credential candidates and long text fields.
    fn check_object_anomalies(item: &Value, signals: &mut Vec<String>, exposed_passwords: &mut Vec<String>, cfg: &AnalysisConfig) {
        let Some(obj) = item.as_object() else { return };

        // 🎯 Metric 1: Privacy Flag Conflict & Exposed Passwords
        for (key, val) in obj {
            let key_lower = key.to_lowercase();
            if key_lower == "password" {
                if let Some(pwd) = val.as_str() {
                    if !pwd.trim().is_empty() {
                        exposed_passwords.push(pwd.to_string());
                    }
                }
            }

            let is_privacy_key = key_lower.contains("private")
                || key_lower.contains("password")
                || key_lower.contains("secret")
                || key_lower.contains("isanswerpublic")
                || key_lower.contains("restricted");
            // "hidden" excluded: it is overwhelmingly a UI attribute
            // (`hidden=true` on elements), not an authorization flag.

            if is_privacy_key {
                let is_restrictive = val == &Value::Bool(true)
                    || val == &Value::Bool(false)
                    || val.as_str() == Some("private")
                    || val.as_str() == Some("hidden");

                if is_restrictive {
                    signals.push(format!("privacy_flag_conflict:{}={}", key, val));
                }
            }
        }

        // 🎯 Metric 1b: Generic sensitive-field taxonomy — fires only when the
        // key matches a group AND the value passes its validator. Credential
        // and custom values join the exposed-password evidence collection.
        for (key, val) in obj {
            let key_lower = key.to_lowercase();
            let Some(group) = sensitive_taxonomy::classify_key(
                &key_lower,
                &cfg.extra_sensitive_keys,
                &cfg.excluded_keys,
            ) else {
                continue;
            };
            // Numeric values only make sense for ID-ish groups; credentials
            // and answers are strings in practice.
            let numeric_text;
            let text: &str = match val {
                Value::String(s) => s,
                Value::Number(n)
                    if matches!(
                        group,
                        sensitive_taxonomy::PAYMENT
                            | sensitive_taxonomy::PII_GOV_ID
                            | sensitive_taxonomy::PII_CONTACT
                    ) =>
                {
                    numeric_text = n.to_string();
                    &numeric_text
                }
                _ => continue,
            };
            let meaningful = match group {
                sensitive_taxonomy::PAYMENT => sensitive_taxonomy::luhn_valid(text),
                sensitive_taxonomy::PII_GOV_ID => sensitive_taxonomy::gov_id_like(text),
                sensitive_taxonomy::PII_CONTACT => {
                    text.contains('@') || sensitive_taxonomy::phone_like(text)
                }
                _ => sensitive_taxonomy::value_is_meaningful(text),
            };
            if !meaningful {
                continue;
            }
            if group == sensitive_taxonomy::CREDENTIAL || group == sensitive_taxonomy::CUSTOM {
                exposed_passwords.push(text.to_owned());
            }
            signals.push(format!("sensitive_field:{group}:key={key}"));
        }

        // 🎯 Metric 2: Nested Entity Exposure — only when the array actually
        // carries child objects; scalar lists (tags, ids...) are not entities.
        for (key, val) in obj {
            if let Some(child_arr) = val.as_array() {
                if child_arr.iter().any(Value::is_object) {
                    signals.push(format!("nested_entity:{}", key));
                }
            }
        }

        // 🎯 Metric 2b: High-entropy credential candidates without a fixed pattern.
        for (key, val) in obj {
            if let Some(text) = val.as_str()
                && entropy::pair_is_candidate(key, text, cfg.entropy_min_length, cfg.entropy_min_bits)
            {
                signals.push(format!(
                    "high_entropy_value:key={},len={}",
                    key,
                    text.chars().count()
                ));
            }
        }

        // 🎯 Metric 3: Text Length Asymmetry
        for (key, val) in obj {
            if let Some(text) = val.as_str() {
                if text.len() > cfg.long_text_bytes {
                    signals.push(format!("long_text_field:{}", key));
                }
            }
        }
    }

    /// Fallback scanner: Xử lý chuỗi thô khi JSON bị cắt ngang/dở dở dang trong thẻ HTML Script.
    fn fallback_string_analysis(body: &str, signals: &mut Vec<String>, exposed_passwords: &mut Vec<String>) {
        let unescaped = body.replace("\\\"", "\"").replace("\\\\", "\\");
        let lowered = unescaped.to_lowercase();

        // Quét cờ bảo mật bị leak trong chuỗi
        if lowered.contains("\"status\":\"private\"") || lowered.contains("\"status\": \"private\"") {
            signals.push("privacy_flag_conflict:status=\"private\"".to_string());
        }
        if lowered.contains("\"isanswerpublic\":false") || lowered.contains("\"isanswerpublic\": false") {
            signals.push("privacy_flag_conflict:isAnswerPublic=false".to_string());
        }

        // Legacy aliases (kept for existing UI/AI consumers) ...
        if lowered.contains("\"problemstatement\"") || unescaped.contains("ĐỀ BÀI:") {
            signals.push("long_text_field:problemStatement".to_string());
        }
        if lowered.contains("\"problem\":{") || lowered.contains("\"problems\":[") {
            signals.push("nested_entity:problem".to_string());
        }

        // ... then generic taxonomy census on the raw string. Presence-only
        // signals stay limited to content groups — payment/gov/contact need a
        // validated VALUE, a bare key mention is a false positive.
        if let Some(fragments) =
            sensitive_taxonomy::fragments_for(sensitive_taxonomy::ANSWER_CONTENT)
        {
            if fragments
                .iter()
                .any(|fragment| lowered.contains(&format!("\"{fragment}\"")))
            {
                signals.push("sensitive_field:answer_content:present".to_owned());
            }
        }
        collect_credential_values(&unescaped, exposed_passwords);
    }
}

/// Raw-string credential extraction for truncated/non-JSON payloads, built
/// from the taxonomy's credential fragments instead of a single literal key.
fn collect_credential_values(unescaped: &str, exposed_passwords: &mut Vec<String>) {
    static CREDENTIAL_RE: OnceLock<Regex> = OnceLock::new();
    let pattern = sensitive_taxonomy::fragments_for(sensitive_taxonomy::CREDENTIAL)
        .unwrap_or(&[])
        .join("|");
    let regex = CREDENTIAL_RE.get_or_init(|| {
        Regex::new(&format!(
            r#"(?i)"(?:{pattern})"\s*:\s*"([^"]*)""#
        ))
        .expect("credential extraction pattern is valid")
    });
    for caps in regex.captures_iter(unescaped) {
        let value = &caps[1];
        if sensitive_taxonomy::value_is_meaningful(value) {
            exposed_passwords.push(value.to_owned());
        }
    }
}

/// Parses React Flight rows out of a text stream: `<rowId>:<tag?><payload>`.
/// Row payloads are JSON values (objects/arrays); `$`-references inside them
/// stay strings and parse fine. After each value the scanner jumps past its
/// consumed bytes (`byte_offset`) so concatenated rows like
/// `3:{"a":1}4:{"b":2}` both survive — a plain streaming pass would misread
/// the next row id as a bare number and stop. Unparseable rows (imports,
/// `T`-text, module refs) are skipped, never fatal.
fn parse_flight_rows(text: &str, results: &mut Vec<Value>) {
    static ROW_START: OnceLock<Regex> = OnceLock::new();
    let row_start = ROW_START.get_or_init(|| {
        Regex::new(r"(?:^|[^0-9A-Za-z])([0-9]{1,6}):").expect("flight row pattern is valid")
    });

    let mut cursor = 0usize;
    while results.len() < 500 {
        let Some(caps) = row_start.captures_at(text, cursor) else {
            return;
        };
        // Full match includes the colon; digits alone would leave it behind.
        let Some(row_id) = caps.get(0) else {
            return;
        };
        let after_colon = row_id.end();
        let mut rest = &text[after_colon..];
        // Optional single-letter row tag (I/J/D/E...) before the payload.
        if rest.starts_with(|c: char| c.is_ascii_uppercase())
            && rest[1..].starts_with(['[', '{', '"'])
        {
            rest = &rest[1..];
        }
        let mut stream = serde_json::Deserializer::from_str(rest).into_iter::<Value>();
        match stream.next() {
            Some(Ok(val)) => {
                if val.is_object() || val.is_array() {
                    results.push(val);
                }
                cursor = after_colon + stream.byte_offset();
            }
            _ => cursor = after_colon,
        }
    }
}

/// Decodes the HTML entities Livewire uses inside attribute values. Order
/// matters: `&amp;` last so double-escapes resolve exactly once.
fn html_decode(text: &str) -> String {
    text.replace("&quot;", "\"")
        .replace("&#039;", "'")
        .replace("&apos;", "'")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
}

/// Returns the index just past the `]` that closes the bracket expression
/// starting at `open_idx` (which must point at `[`). String-aware: brackets
/// inside JSON string literals and `\"` escapes are ignored, so minified
/// single-line pages with many pushes parse correctly.
fn balanced_bracket_end(text: &str, open_idx: usize) -> Option<usize> {
    let bytes = text.as_bytes();
    if bytes.get(open_idx) != Some(&b'[') {
        return None;
    }
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    for (offset, byte) in bytes[open_idx..].iter().enumerate() {
        let idx = open_idx + offset;
        if in_string {
            if escaped {
                escaped = false;
            } else if *byte == b'\\' {
                escaped = true;
            } else if *byte == b'"' {
                in_string = false;
            }
            continue;
        }
        match byte {
            b'"' => in_string = true,
            b'[' => depth += 1,
            b']' => {
                depth -= 1;
                if depth == 0 {
                    return Some(idx + 1);
                }
            }
            _ => {}
        }
    }
    None
}

/// Scans `"password":"<value>"` occurrences out of a raw string payload.
fn collect_exposed_strings(unescaped: &str, exposed_passwords: &mut Vec<String>) {    let mut start = 0;
    let pattern = "\"password\":\"";
    while let Some(pos) = unescaped[start..].find(pattern) {
        let actual_pos = start + pos + pattern.len();
        if let Some(end_pos) = unescaped[actual_pos..].find('"') {
            let pwd = &unescaped[actual_pos..actual_pos + end_pos];
            if !pwd.trim().is_empty() {
                exposed_passwords.push(pwd.to_string());
            }
            start = actual_pos + end_pos + 1;
        } else {
            break;
        }
    }
}

/// Unique, lowercased email count over the raw body. A `BTreeSet` keeps this
/// deterministic; one linear regex pass handles JSON/RSC/HTML alike.
fn census_unique_emails(body: &str) -> usize {
    let mut unique = BTreeSet::new();
    for m in email_regex().find_iter(body) {
        unique.insert(m.as_str().to_lowercase());
    }
    unique.len()
}

static PAGE_TOTAL_RE: OnceLock<Regex> = OnceLock::new();
static HAS_NEXT_PAGE_RE: OnceLock<Regex> = OnceLock::new();

fn page_total_regex() -> &'static Regex {
    PAGE_TOTAL_RE.get_or_init(|| {
        Regex::new(r#""(?:currentPage|page)"\s*:\s*(\d+)\s*,\s*"(?:totalPages|total_pages|lastPage|last_page)"\s*:\s*(\d+)"#)
            .expect("static pagination pattern is valid")
    })
}

fn has_next_page_regex() -> &'static Regex {
    HAS_NEXT_PAGE_RE.get_or_init(|| {
        Regex::new(r#""hasNextPage"\s*:\s*true"#).expect("static hasNextPage pattern is valid")
    })
}

/// Detects server-declared pagination that still has unfetched pages. Only
/// incomplete progress is a signal — `currentPage == total` is healthy.
fn census_pagination(body: &str) -> Vec<String> {
    let mut signals = Vec::new();
    for caps in page_total_regex().captures_iter(body) {
        let (Ok(current), Ok(total)) = (caps[1].parse::<u64>(), caps[2].parse::<u64>()) else {
            continue;
        };
        if total > current {
            signals.push(format!("pagination_incomplete:current={current},total={total}"));
        }
    }
    if has_next_page_regex().is_match(body) {
        signals.push("pagination_incomplete:has_next=true".to_owned());
    }
    signals
}

/// Binary media types are expected to be large; only textual payloads get the
/// oversized-response heuristic.
fn is_size_checkable(content_type: Option<&str>) -> bool {
    match content_type {
        None => true,
        Some(ct) => {
            let lowered = ct.to_lowercase();
            !lowered.starts_with("image/")
                && !lowered.starts_with("font/")
                && !lowered.starts_with("audio/")
                && !lowered.starts_with("video/")
                && lowered != "application/octet-stream"
        }
    }
}

/// Render surfaces where server data is embedded into markup: SSR HTML and
/// React Server Component streams.
fn is_render_surface(content_type: Option<&str>) -> bool {
    content_type.is_some_and(|ct| {
        let lowered = ct.to_lowercase();
        lowered.starts_with("text/html") || lowered.contains("text/x-component")
    })
}

static LOGIN_HINT_RE: OnceLock<Regex> = OnceLock::new();
static QR_DATA_RE: OnceLock<Regex> = OnceLock::new();

fn login_hint_regex() -> &'static Regex {
    LOGIN_HINT_RE.get_or_init(|| {
        Regex::new(r"(?i)(automatically logged in|auto[-_ ]?login|scan (?:the|this) qr)")
            .expect("login-hint pattern is valid")
    })
}

fn qr_data_regex() -> &'static Regex {
    QR_DATA_RE.get_or_init(|| {
        Regex::new(r#"data:image/(?:png|svg\+xml);base64,[A-Za-z0-9+/=]{200,}"#)
            .expect("qr-data pattern is valid")
    })
}

/// Embedded login-QR detector: a page that both *talks about* logging in via
/// QR **and** carries a sizeable inline image is shipping a bearer credential.
/// Requiring both halves keeps it precise — marketing pages mentioning QR
/// codes, or decorative inline images alone, stay silent.
fn has_login_qr(body: &str) -> bool {
    login_hint_regex().is_match(body) && qr_data_regex().is_match(body)
}

/// Shared counters threaded through the recursive structural walk.
#[derive(Default)]
struct WalkStats {
    visited: usize,
    max_object_array_len: usize,
    top_level_is_array: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clean_list_json_not_suspicious() {
        let json_body = r#"[
            {"id": "1", "name": "Contest 1", "createdAt": "2026-08-22"},
            {"id": "2", "name": "Contest 2", "createdAt": "2026-08-22"}
        ]"#;

        let signal = OverfetchingAnalyzer::analyze(json_body);
        assert!(!signal.is_suspicious);
        assert!(signal.detected_signals.is_empty());
    }

    #[test]
    fn test_rest_api_overfetching_anomalies() {
        let json_body = r#"[
            {
                "id": "69803b4d",
                "name": "Python Revenue Analysis",
                "status": "private",
                "isAnswerPublic": false,
                "password": "secret_pass_123",
                "problems": [
                    {"id": "p1", "title": "Problem 1"}
                ],
                "problemStatement": "1. Create a Series from Dictionary with cities and population as follows:\nHanoi: 8.5 million\nHCMC: 9.3 million. Perform additional data aggregation and calculation steps..."
            }
        ]"#;

        let signal = OverfetchingAnalyzer::analyze(json_body);
        assert!(signal.is_suspicious);
        assert!(signal.exposed_passwords.contains(&"secret_pass_123".to_string()));
        assert!(signal.detected_signals.contains(&"exposed_passwords_count:1".to_string()));
    }

    #[test]
    fn test_nextjs_rsc_payload_detection() {
        let rsc_html = r#"
        <!DOCTYPE html><html><body>
        <script>self.__next_f.push([1, "3:{\"name\":\"Contest 1\",\"status\":\"private\",\"isAnswerPublic\":false,\"problems\":[{\"_id\":\"p1\"}],\"problemStatement\":\"1. Create a Series from Dictionary with cities and population as follows:\\n\\nHanoi: 8.5 million...\"}\n"])</script>
        </body></html>
        "#;

        let signal = OverfetchingAnalyzer::analyze(rsc_html);
        assert!(signal.is_suspicious);
        assert!(signal.detected_signals.contains(&"nested_entity:problems".to_string()));
    }

    #[test]
    fn test_truncated_user_snippet_fallback_detection() {
        // Truncated RSC snippet (JSON cut mid-object) must still hit the
        // raw-string fallback rules.
        let user_truncated_snippet = concat!(
            r#"(6-29T04:54:51.503Z\",\"isTemp\":false,\"role\":\"admin\"},"#,
            r#"\"createdAt\":\"2025-09-18T15:30:34.876Z\",\"updatedAt\":\"2025-09-18T15:30:34.876Z\"}],"#,
            r#"\"difficulty\":\"easy\",\"ACPercent\":0,\"ACCount\":0,\"totalSubmissions\":0,"#,
            r#"\"slug\":\"python-revenue-analysis-with-functions-6a8518ccf9259f5d3f335863\",\"sharedWith\":[],"#,
            r#"\"status\":\"private\",\"isAnswerPublic\":false,\"createdBy\":{\"_id\":\"6860c71b7e3751ba29c75cd6","#,
            r#",\"email\":\"quocthai@neu.edu.vn\",\"name\":\"Nguyễn Quốc Thái\",\"loginType\":\"email\",\"status\":\"active","#,
            r#"\"createdAt\":\"2025-06-29T04:54:51.503Z\",\"updatedAt\":\"2025-06-29T04:54:51.503Z\",\"isTemp\":false,\"role\":\"admin\"},"#,
            r#"\"createdAt\":\"2026-08-19T02:45:32.394Z\",\"updatedAt\":\"2026-08-19T02:45:32.394Z\"},\"maxScore\":100},"#,
            r#"{\"index\":15,\"problem\":{\"_id\":\"69803b4dc4b471b1efe07392\",\"name\":\"[PANDAS] - Series Quản Lý Dân Số","#,
            r#"\"problemStatement\":\"1\\\\. Tạo một Series từ Dictionary với các thành phố và dân số của chúng như sau:"#,
            r#"\\n\\n  \\\\* \\\"Hanoi\\\": 8.5 triệu\\n\\n  \\\\* \\\"HCMC\\\": 9.3 triệu\\n\\n\u"#
        );

        let signal = OverfetchingAnalyzer::analyze(user_truncated_snippet);
        assert!(signal.is_suspicious);
        assert!(signal.detected_signals.contains(&"privacy_flag_conflict:status=\"private\"".to_string()));
        assert!(signal.detected_signals.contains(&"privacy_flag_conflict:isAnswerPublic=false".to_string()));
        assert!(signal.detected_signals.contains(&"long_text_field:problemStatement".to_string()));
    }

    #[test]
    fn test_real_contest_html_file() {
        let contest_html_path = "../../contest.html";
        let Ok(content) = std::fs::read_to_string(contest_html_path)
            .or_else(|_| std::fs::read_to_string("contest.html"))
        else {
            return;
        };

        let signal = OverfetchingAnalyzer::analyze(&content);
        println!("\n=== DETECTED SIGNALS FROM REAL contest.html ===");
        for s in &signal.detected_signals {
            println!("  [SIGNAL] {}", s);
        }
        println!("Exposed Passwords Found: {:?}", signal.exposed_passwords);
        println!("===============================================\n");

        assert!(signal.is_suspicious, "contest.html must be detected as suspicious");
        assert_eq!(signal.exposed_passwords.len(), 6, "Must detect all 6 exposed contest passwords");
        for expected in ["clcc66", "aiep17", "123456", "070226", "CNTT66", "KHMT66"] {
            assert!(
                signal.exposed_passwords.iter().any(|pwd| pwd == expected),
                "missing password {expected}"
            );
        }
    }

    #[test]
    fn oversized_response_fires_above_threshold_only() {
        let big = format!("{{\"data\":\"{}\"}}", "x".repeat(101_000));
        let big_signal = OverfetchingAnalyzer::analyze(&big);
        assert!(big_signal
            .detected_signals
            .iter()
            .any(|s| *s == format!("oversized_response:bytes={}", big.len())));

        let small = OverfetchingAnalyzer::analyze(r#"{"data":"tiny"}"#);
        assert!(small
            .detected_signals
            .iter()
            .all(|s| !s.starts_with("oversized_response")));
    }

    #[test]
    fn binary_content_types_skip_size_heuristic() {
        let big = format!("{{\"data\":\"{}\"}}", "x".repeat(101_000));
        let image_signal = OverfetchingAnalyzer::analyze_with(&big, Some("image/png"));
        assert!(
            image_signal
                .detected_signals
                .iter()
                .all(|s| !s.starts_with("oversized_response")),
            "{:?}",
            image_signal.detected_signals
        );

        let json_signal = OverfetchingAnalyzer::analyze_with(&big, Some("application/json"));
        assert!(
            json_signal
                .detected_signals
                .iter()
                .any(|s| s.starts_with("oversized_response"))
        );
    }

    #[test]
    fn mass_email_exposure_counts_unique_addresses_only() {
        let mut body = String::from("{\"signUps\":[");
        for index in 0..11 {
            body.push_str(&format!("{{\"email\":\"user{index}@example.com\"}},"));
        }
        body.push_str("]}");
        let signal = OverfetchingAnalyzer::analyze(&body);
        assert!(
            signal
                .detected_signals
                .iter()
                .any(|s| *s == "mass_pii_exposure:emails=11"),
            "{:?}",
            signal.detected_signals
        );

        // Repeats of one address must not inflate the census.
        let duplicated_entry = "\"a@b.vn\"".to_string();
        let duplicated =
            format!("{{\"list\":[{}]}}", vec![duplicated_entry; 50].join(","));
        let quiet = OverfetchingAnalyzer::analyze(&duplicated);
        assert!(
            quiet
                .detected_signals
                .iter()
                .all(|s| !s.starts_with("mass_pii_exposure")),
            "{:?}",
            quiet.detected_signals
        );

        // A handful of addresses stays below the threshold.
        let few = OverfetchingAnalyzer::analyze(r#"{"team":["x@y.vn","z@y.vn","q@y.vn"]}"#);
        assert!(few
            .detected_signals
            .iter()
            .all(|s| !s.starts_with("mass_pii_exposure")));
    }

    #[test]
    fn mass_entity_exposure_tracks_object_arrays() {
        let items: Vec<String> = (0..51).map(|index| format!("{{\"index\":{index}}}")).collect();
        let body = format!("{{\"contests\":[{}]}}", items.join(","));
        let signal = OverfetchingAnalyzer::analyze(&body);
        assert!(
            signal
                .detected_signals
                .iter()
                .any(|s| *s == "mass_exposure:entities=51"),
            "{:?}",
            signal.detected_signals
        );

        let small_items: Vec<String> = (0..10)
            .map(|index| format!("{{\"index\":{index}}}"))
            .collect();
        let small = OverfetchingAnalyzer::analyze(&format!(
            "{{\"contests\":[{}]}}",
            small_items.join(",")
        ));
        assert!(small
            .detected_signals
            .iter()
            .all(|s| !s.starts_with("mass_exposure")));
    }

    #[test]
    fn nested_entity_requires_child_objects_not_scalars() {
        let scalar_array = OverfetchingAnalyzer::analyze(r#"{"item":{"tags":["a","b","c"]}}"#);
        assert!(scalar_array.detected_signals.is_empty());

        let object_array = OverfetchingAnalyzer::analyze(r#"{"item":{"problems":[{"_id":"p1"}]}}"#);
        assert!(object_array
            .detected_signals
            .iter()
            .any(|s| *s == "nested_entity:problems"));
    }

    #[test]
    fn high_entropy_values_flag_but_identifiers_do_not() {
        let token_body = r#"{"session":{"access_token":"Zx9Qm2Lp7Vb4Kd8Rn3Wj6Hf5Yt1Cs0AgEu"}}"#;
        let flagged = OverfetchingAnalyzer::analyze(token_body);
        assert!(
            flagged
                .detected_signals
                .iter()
                .any(|s| *s == "high_entropy_value:key=access_token,len=34"),
            "{:?}",
            flagged.detected_signals
        );

        let ids_body = r#"{"record":{"_id":"6860c71b7e3751ba29c75cd6","etag":"d41d8cd98f00b204e9800998ecf8427e"}}"#;
        let quiet = OverfetchingAnalyzer::analyze(ids_body);
        assert!(
            quiet
                .detected_signals
                .iter()
                .all(|s| !s.starts_with("high_entropy_value")),
            "{:?}",
            quiet.detected_signals
        );
    }

    #[test]
    fn structural_scan_reaches_beyond_first_ten_array_items() {
        let mut items = Vec::new();
        for index in 0..15 {
            let statement = if index == 12 {
                format!("\"problemStatement\":\"{}\"", "đề".repeat(200))
            } else {
                "\"problemStatement\":\"short\"".to_string()
            };
            items.push(format!("{{\"id\":{index},{statement}}}"));
        }
        let body = format!("{{\"problems\":[{}]}}", items.join(","));
        let signal = OverfetchingAnalyzer::analyze(&body);
        assert!(
            signal
                .detected_signals
                .iter()
                .any(|s| *s == "long_text_field:problemStatement"),
            "12th item must be scanned: {:?}",
            signal.detected_signals
        );
    }

    #[test]
    fn incomplete_pagination_is_flagged_with_page_numbers() {
        let body = r#"{"contests":[{"name":"A"}],"currentPage":1,"totalPages":2}"#;
        let signal = OverfetchingAnalyzer::analyze(body);
        assert!(
            signal
                .detected_signals
                .iter()
                .any(|s| *s == "pagination_incomplete:current=1,total=2"),
            "{:?}",
            signal.detected_signals
        );
    }

    #[test]
    fn completed_pagination_is_not_a_signal() {
        let done = OverfetchingAnalyzer::analyze(r#"{"items":[],"currentPage":2,"totalPages":2}"#);
        assert!(done
            .detected_signals
            .iter()
            .all(|s| !s.starts_with("pagination_incomplete")));

        let single = OverfetchingAnalyzer::analyze(r#"{"items":[],"currentPage":1,"totalPages":1}"#);
        assert!(single
            .detected_signals
            .iter()
            .all(|s| !s.starts_with("pagination_incomplete")));
    }

    #[test]
    fn has_next_page_boolean_is_flagged() {
        let more = OverfetchingAnalyzer::analyze(r#"{"items":[1,2],"hasNextPage":true}"#);
        assert!(more
            .detected_signals
            .iter()
            .any(|s| *s == "pagination_incomplete:has_next=true"));

        let end = OverfetchingAnalyzer::analyze(r#"{"items":[1,2],"hasNextPage":false}"#);
        assert!(end
            .detected_signals
            .iter()
            .all(|s| !s.starts_with("pagination_incomplete")));
    }

    #[test]
    fn custom_long_text_threshold_changes_detection() {
        let body = r#"{"item":{"bio":"moderately sized text value"}}"#;
        let strict = AnalysisConfig {
            long_text_bytes: 10,
            ..AnalysisConfig::default()
        };
        assert!(OverfetchingAnalyzer::analyze_with_config(body, None, &strict)
            .detected_signals
            .iter()
            .any(|s| *s == "long_text_field:bio"));
        assert!(!OverfetchingAnalyzer::analyze(body)
            .detected_signals
            .iter()
            .any(|s| s == "long_text_field:bio"));
    }

    #[test]
    fn custom_email_and_size_thresholds_change_detection() {
        let three_emails = r#"{"team":["a@x.vn","b@x.vn","c@x.vn"]}"#;
        let sensitive = AnalysisConfig {
            mass_email_threshold: 2,
            oversized_response_bytes: 10,
            ..AnalysisConfig::default()
        };
        let signal = OverfetchingAnalyzer::analyze_with_config(three_emails, None, &sensitive);
        assert!(signal
            .detected_signals
            .iter()
            .any(|s| *s == "mass_pii_exposure:emails=3"));
        // The tiny fixture itself crosses the lowered size threshold.
        assert!(signal
            .detected_signals
            .iter()
            .any(|s| s.starts_with("oversized_response")));

        // Defaults keep the same body quiet on both heuristics.
        let quiet = OverfetchingAnalyzer::analyze(three_emails);
        assert!(quiet
            .detected_signals
            .iter()
            .all(|s| !s.starts_with("mass_pii_exposure")
                && !s.starts_with("oversized_response")));
    }

    #[test]
    fn custom_entropy_floor_flags_shorter_candidates() {
        let body = r#"{"session":{"access_token":"Zx9Qm2Lp7Vb4Kd8Rn3Wj6Hf5Yt1Cs0AgEu"}}"#;
        let relaxed = AnalysisConfig {
            entropy_min_length: 12,
            ..AnalysisConfig::default()
        };
        assert!(OverfetchingAnalyzer::analyze_with_config(body, None, &relaxed)
            .detected_signals
            .iter()
            .any(|s| s.starts_with("high_entropy_value:key=access_token")));

        // Raising the floor beyond the measured entropy silences the same value.
        let raised = AnalysisConfig {
            entropy_min_bits: 5.9,
            ..AnalysisConfig::default()
        };
        assert!(!OverfetchingAnalyzer::analyze_with_config(body, None, &raised)
            .detected_signals
            .iter()
            .any(|s| s.starts_with("high_entropy_value")));
    }

    #[test]
    fn runtime_config_installation_is_idempotent_and_safe() {
        // Startup calls this once; calling again must never panic (first write wins).
        api_tester_domain::AnalysisConfig::default();
        let before = OverfetchingAnalyzer::analyze(r#"{"a":1}"#);
        init_analysis_config(AnalysisConfig::default());
        let after = OverfetchingAnalyzer::analyze(r#"{"a":1}"#);
        assert_eq!(before.detected_signals, after.detected_signals);
    }

    #[test]
    fn numeric_values_validate_for_id_groups_only() {
        // Government ID as a JSON number passes the digit validator.
        let gov = OverfetchingAnalyzer::analyze(r#"{"citizen":{"cccd":123456789012}}"#);
        assert!(gov
            .detected_signals
            .iter()
            .any(|s| *s == "sensitive_field:pii_gov_id:key=cccd"));

        // Luhn-valid card as a number fires; invalid digits do not.
        let card = OverfetchingAnalyzer::analyze(r#"{"payment":{"card_number":4111111111111111}}"#);
        assert!(card
            .detected_signals
            .iter()
            .any(|s| *s == "sensitive_field:payment:key=card_number"));
        let bad_card = OverfetchingAnalyzer::analyze(r#"{"payment":{"card_number":4111111111111112}}"#);
        assert!(bad_card
            .detected_signals
            .iter()
            .all(|s| !s.starts_with("sensitive_field:payment")));

        // Credentials as numbers are ignored — too noisy.
        let numeric_password = OverfetchingAnalyzer::analyze(r#"{"user":{"password":123456}}"#);
        assert!(numeric_password
            .detected_signals
            .iter()
            .all(|s| !s.starts_with("sensitive_field:credential")));
    }

    #[test]
    fn custom_group_joins_evidence_and_collection_checks() {
        let cfg = AnalysisConfig {
            extra_sensitive_keys: vec!["so_tai_khoan".into()],
            ..AnalysisConfig::default()
        };
        let body = r#"[{"account":{"soTaiKhoan":"0123456789AA"}}]"#;
        let signal = OverfetchingAnalyzer::analyze_with_config(body, None, &cfg);
        assert!(
            signal
                .detected_signals
                .iter()
                .any(|s| *s == "sensitive_field:custom:key=soTaiKhoan"),
            "signals={:?} exposed={:?}",
            signal.detected_signals,
            signal.exposed_passwords
        );
        assert!(signal.detected_signals.contains(&"sensitive_in_collection".to_owned()));
        assert!(signal.exposed_passwords.contains(&"0123456789AA".to_owned()));
    }

    #[test]
    fn flight_rows_parse_concatenated_payloads_and_skip_text() {
        // Real Flight wire sample (row ids, tags, $-refs, text row with a
        // digit-colon inside that must NOT become a row start).
        let body = concat!(
            "1:I[\"./x.js\",[\"c/main.js\"],\"default\"]\n",
            "2:J[\"$\",\"article\",null,{\"children\":\"$1\"}]\n",
            "0:D{\"name\":\"RootLayout\",\"env\":\"Server\"}\n",
            "3:{\"user\":{\"password\":\"CNTT66\"}}\n",
            "4:T18,\"plain 12:30 text\"\n",
            "5:{\"next\":{\"pwd\":\"aiep17\"}}\n",
            "6:{\"pad\":\"{}\"}\n"
        )
        .replace("{}", "x".repeat(1200).as_str());
        let signal = OverfetchingAnalyzer::analyze_with(&body, Some("text/x-component"));
        assert!(
            signal
                .detected_signals
                .iter()
                .any(|s| s.starts_with("api_payload_in_html:")),
            "{:?}",
            signal.detected_signals
        );
        // Both credential objects across concatenated rows were reached.
        for expected in ["CNTT66", "aiep17"] {
            assert!(
                signal.exposed_passwords.iter().any(|pwd| pwd == expected),
                "missing {expected} in {:?}",
                signal.exposed_passwords
            );
        }
        assert!(signal
            .detected_signals
            .iter()
            .any(|s| *s == "sensitive_field:credential:key=password"));
    }

    #[test]
    fn minified_single_line_html_with_many_pushes_extracts_all() {
        // Real-world shape: whole document on one line, parens in surrounding
        // markup, two pushes back to back with different payloads.
        let body = concat!(
            r#"<html><body>(ghi chú) <script>self.__next_f.push([1,"3:{\"story\":\"{}\",\"pwd\":\"CNTT66\"}"])</script>"#,
            r#"<script>self.__next_f.push([1,"5:{\"chap\":1,\"email\":\"reader@x.vn\"}"])</script></body></html>"#
        )
        .replace("{}", "truyện dài".repeat(80).as_str());

        let signal = OverfetchingAnalyzer::analyze_with(&body, Some("text/html; charset=utf-8"));
        assert!(
            signal
                .detected_signals
                .iter()
                .any(|s| s.starts_with("api_payload_in_html")),
            "both pushes must extract on a single-line page: {:?}",
            signal.detected_signals
        );
        assert!(
            signal
                .exposed_passwords
                .iter()
                .any(|pwd| pwd == "CNTT66"),
            "{:?}",
            signal.exposed_passwords
        );
        assert!(signal
            .detected_signals
            .iter()
            .any(|s| *s == "sensitive_field:pii_contact:key=email"));
    }

    #[test]
    fn livewire_snapshot_attributes_extract_as_api_payload() {
        // Laravel Livewire shape (as seen in a real Filament page dump):
        // HTML-escaped JSON inside wire:snapshot attributes.
        let filler = "giỏ hàng chi tiết ".repeat(70);
        let body = r#"<div wire:snapshot="{&quot;data&quot;:&quot;@FILLER@&quot;,&quot;memo&quot;:{&quot;id&quot;:&quot;abc123&quot;}}" wire:ignore></div>"#
            .replace("@FILLER@", &filler);
        let signal = OverfetchingAnalyzer::analyze_with(&body, Some("text/html; charset=utf-8"));
        assert!(
            signal
                .detected_signals
                .iter()
                .any(|s| s.starts_with("api_payload_in_html")),
            "livewire snapshots must count as embedded API payload: {:?}",
            signal.detected_signals
        );
    }

    #[test]
    fn embedded_login_qr_is_flagged_as_credential() {
        // Real Moodle profile "Mobile app" shape: login hint + inline QR PNG.
        let fake_qr = format!("data:image/png;base64,{}", "iVBORw0KGgo".repeat(30));
        let body = format!(
            r#"<dd><p>Scan the QR code with your mobile app and you will be automatically logged in. The QR code will expire in 10 minutes.</p><img src="{fake_qr}"></dd>"#
        );
        let signal = OverfetchingAnalyzer::analyze_with(&body, Some("text/html; charset=utf-8"));
        assert!(signal
            .detected_signals
            .iter()
            .any(|s| *s == "auth_qr_in_html"));

        // Half conditions stay silent: QR without login text, text without QR.
        let qr_only =
            OverfetchingAnalyzer::analyze_with(&format!(r#"<img src="{fake_qr}">"#), Some("text/html"));
        assert!(qr_only
            .detected_signals
            .iter()
            .all(|s| *s != "auth_qr_in_html"));

        let text_only = OverfetchingAnalyzer::analyze_with(
            "<p>Scan the QR code with your mobile app and you will be automatically logged in.</p>",
            Some("text/html"),
        );
        assert!(text_only
            .detected_signals
            .iter()
            .all(|s| *s != "auth_qr_in_html"));
    }

    #[test]
    fn sensitive_payload_tier_requires_sensitive_context() {
        let filler = "nội dung thường ".repeat(80);
        let benign = format!(
            r#"<html><script>self.__next_f.push([1,"3:{{\"thien_ban\":\"{filler}\"}}"])</script></html>"#
        );
        let info_only = OverfetchingAnalyzer::analyze_with(&benign, Some("text/x-component"));
        assert!(info_only
            .detected_signals
            .iter()
            .any(|s| s.starts_with("api_payload_in_html")));
        assert!(info_only
            .detected_signals
            .iter()
            .all(|s| !s.starts_with("sensitive_payload_in_html")));

        let leaky = r#"<html><script>self.__next_f.push([1,"3:{\"password\":\"CNTT66\",\"pad\":\"{}\"}"])</script></html>"#
            .replace("{}", "x".repeat(1100).as_str());
        let high = OverfetchingAnalyzer::analyze_with(&leaky, Some("text/x-component"));
        assert!(high
            .detected_signals
            .iter()
            .any(|s| s.starts_with("sensitive_payload_in_html")));
    }

    #[test]
    fn api_payload_in_html_fires_on_unknown_vocabulary() {
        // A fortune-telling site: field names no dictionary knows. The bug
        // class is structural — a big API payload riding inside the render.
        let filler = "lá số tử vi chi tiết ".repeat(60);
        // Real RSC streams escape the inner JSON quotes at the JS-string level.
        let body = format!(
            r#"<html><script>self.__next_f.push([1,"3:{{\"thien_ban\":\"{filler}\",\"ngay_sinh\":\"1990-01-01\",\"so_thich\":\"cau-long\"}}"])</script></html>"#
        );
        let signal = OverfetchingAnalyzer::analyze_with(&body, Some("text/x-component"));
        assert!(
            signal
                .detected_signals
                .iter()
                .any(|s| s.starts_with("api_payload_in_html:bytes=")),
            "structural detection must fire without any keyword match: {:?}",
            signal.detected_signals
        );
    }

    #[test]
    fn small_plain_html_pages_are_not_flagged_as_api_payloads() {
        let tiny = r#"<html><head><title>hi</title></head><body>static text</body></html>"#;
        let signal = OverfetchingAnalyzer::analyze_with(tiny, Some("text/html; charset=utf-8"));
        assert!(signal
            .detected_signals
            .iter()
            .all(|s| !s.starts_with("api_payload_in_html")));

        // JSON APIs are not render surfaces even when large.
        let big_json = OverfetchingAnalyzer::analyze_with(
            &format!("{{\"data\":\"{}\"}}", "y".repeat(2000)),
            Some("application/json"),
        );
        assert!(big_json
            .detected_signals
            .iter()
            .all(|s| !s.starts_with("api_payload_in_html")));
    }
}
