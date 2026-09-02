use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::DomainError;

pub const DEFAULT_PROXY_HOST: &str = "127.0.0.1";
pub const DEFAULT_PROXY_PORT: u16 = 8080;
pub const DEFAULT_BUFFER_SIZE: usize = 100_000;
pub const DEFAULT_BUFFER_MAX_BYTES: usize = 0;
pub const DEFAULT_BUFFER_DEDUP_LIMIT: usize = 100_000;
pub const DEFAULT_SCANNER_CONCURRENCY: usize = 50;
pub const DEFAULT_REQUEST_TIMEOUT_SECONDS: f64 = 30.0;

const DEFAULT_SKILLS: &[&str] = &["sqli", "xss", "idor", "jwt_attack", "auth_bypass"];
const DEFAULT_NOISE_HOSTS: &[&str] = &[
    r"google\.com",
    r"googleapis\.com",
    r"gstatic\.com",
    r"googleadservices\.com",
    r"googlesyndication\.com",
    r"googletagmanager\.com",
    r"google-analytics\.com",
    r"googleusercontent\.com",
    r"gvt1\.com",
    r"gvt2\.com",
    r"youtube\.com",
    r"ytimg\.com",
    r"doubleclick\.net",
    r"facebook\.com",
    r"fbcdn\.net",
    r"cloudflareinsights\.com",
    r"tynt\.com",
    r"scorecardresearch\.com",
    r"quantserve\.com",
    r"outbrain\.com",
    r"taboola\.com",
    r"criteo\.com",
    r"adnxs\.com",
    r"pubmatic\.com",
    r"rubiconproject\.com",
];
const DEFAULT_NOISE_PATHS: &[&str] = &[
    r".*\.(png|jpg|jpeg|gif|webp|svg|ico|jfif|css|js|woff2?|ttf|eot|map)$",
    r"/_next/static/",
    r"/cdn-cgi/",
    r"favicon",
    r"beacon\.min\.js",
    r"/assets/generated/",
];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProxyConfig {
    #[serde(default = "default_proxy_host")]
    pub host: String,
    #[serde(default = "default_proxy_port")]
    pub port: u16,
    #[serde(default)]
    pub ssl_cert_dir: Option<PathBuf>,
    /// Maximum captured body size in bytes; larger bodies are truncated.
    #[serde(default = "default_max_body_bytes")]
    pub max_body_bytes: usize,
    /// When false (default) upstream TLS certificates are not verified, which
    /// is required for HTTPS interception. Keep off for MITM capture.
    #[serde(default = "default_upstream_verify_tls")]
    pub upstream_verify_tls: bool,
    /// Upper bound on concurrent client connections handled by the proxy.
    #[serde(default = "default_max_connections")]
    pub max_connections: usize,
    /// Idle keep-alive timeout in seconds for client connections.
    #[serde(default = "default_idle_timeout_secs")]
    pub idle_timeout_secs: u64,
}

pub const DEFAULT_MAX_BODY_BYTES: usize = 10 * 1024 * 1024;
pub const DEFAULT_UPSTREAM_VERIFY_TLS: bool = false;
pub const DEFAULT_MAX_CONNECTIONS: usize = 256;
pub const DEFAULT_IDLE_TIMEOUT_SECS: u64 = 60;

fn default_proxy_host() -> String {
    DEFAULT_PROXY_HOST.to_owned()
}

const fn default_proxy_port() -> u16 {
    DEFAULT_PROXY_PORT
}

const fn default_max_body_bytes() -> usize {
    DEFAULT_MAX_BODY_BYTES
}

const fn default_upstream_verify_tls() -> bool {
    DEFAULT_UPSTREAM_VERIFY_TLS
}

const fn default_max_connections() -> usize {
    DEFAULT_MAX_CONNECTIONS
}

const fn default_idle_timeout_secs() -> u64 {
    DEFAULT_IDLE_TIMEOUT_SECS
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            host: default_proxy_host(),
            port: default_proxy_port(),
            ssl_cert_dir: None,
            max_body_bytes: default_max_body_bytes(),
            upstream_verify_tls: default_upstream_verify_tls(),
            max_connections: default_max_connections(),
            idle_timeout_secs: default_idle_timeout_secs(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BrowserConfig {
    #[serde(default = "default_profile_dir")]
    pub profile_dir: PathBuf,
}

fn default_profile_dir() -> PathBuf {
    dirs_home().join(".api-tester").join("chrome-profile")
}

fn dirs_home() -> PathBuf {
    std::env::var_os("USERPROFILE")
        .or_else(|| std::env::var_os("HOME"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
}

impl Default for BrowserConfig {
    fn default() -> Self {
        Self {
            profile_dir: default_profile_dir(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BufferConfig {
    #[serde(default = "default_buffer_size")]
    pub max_size: usize,
    #[serde(default = "default_true")]
    pub dedup_enabled: bool,
    /// Approximate byte cap for the in-memory buffer; zero disables the cap.
    #[serde(default = "default_buffer_max_bytes")]
    pub max_bytes: usize,
    /// Upper bound for the deduplication fingerprint set before it is reset.
    #[serde(default = "default_buffer_dedup_limit")]
    pub dedup_limit: usize,
}

const fn default_buffer_size() -> usize {
    DEFAULT_BUFFER_SIZE
}

const fn default_buffer_max_bytes() -> usize {
    DEFAULT_BUFFER_MAX_BYTES
}

const fn default_buffer_dedup_limit() -> usize {
    DEFAULT_BUFFER_DEDUP_LIMIT
}

const fn default_true() -> bool {
    true
}

impl Default for BufferConfig {
    fn default() -> Self {
        Self {
            max_size: default_buffer_size(),
            dedup_enabled: true,
            max_bytes: default_buffer_max_bytes(),
            dedup_limit: default_buffer_dedup_limit(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ScannerConfig {
    #[serde(default = "default_scanner_concurrency")]
    pub max_concurrent_requests: usize,
    #[serde(default = "default_request_timeout")]
    pub request_timeout: f64,
    #[serde(default = "default_skills")]
    pub enabled_skills: Vec<String>,
}

fn default_scanner_concurrency() -> usize {
    DEFAULT_SCANNER_CONCURRENCY
}

fn default_request_timeout() -> f64 {
    DEFAULT_REQUEST_TIMEOUT_SECONDS
}

fn default_skills() -> Vec<String> {
    DEFAULT_SKILLS
        .iter()
        .map(|skill| (*skill).to_owned())
        .collect()
}

impl Default for ScannerConfig {
    fn default() -> Self {
        Self {
            max_concurrent_requests: default_scanner_concurrency(),
            request_timeout: default_request_timeout(),
            enabled_skills: default_skills(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OastConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_oast_server")]
    pub server: String,
}

fn default_oast_server() -> String {
    "oast.pro".to_owned()
}

impl Default for OastConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            server: default_oast_server(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScopeConfig {
    #[serde(default)]
    pub include_hosts: Vec<String>,
    #[serde(default = "default_noise_hosts")]
    pub exclude_hosts: Vec<String>,
    #[serde(default)]
    pub include_paths: Vec<String>,
    #[serde(default = "default_noise_paths")]
    pub exclude_paths: Vec<String>,
}

fn default_noise_hosts() -> Vec<String> {
    DEFAULT_NOISE_HOSTS
        .iter()
        .map(|pattern| (*pattern).to_owned())
        .collect()
}

fn default_noise_paths() -> Vec<String> {
    DEFAULT_NOISE_PATHS
        .iter()
        .map(|pattern| (*pattern).to_owned())
        .collect()
}

impl Default for ScopeConfig {
    fn default() -> Self {
        Self {
            include_hosts: Vec::new(),
            exclude_hosts: default_noise_hosts(),
            include_paths: Vec::new(),
            exclude_paths: default_noise_paths(),
        }
    }
}

fn default_security_max_requests() -> u64 {
    200
}

fn default_security_timeout() -> u64 {
    15
}

fn default_security_per_host_rps() -> u32 {
    10
}

fn default_security_duration_budget() -> Option<u64> {
    Some(600)
}

fn default_security_retry_limit() -> u32 {
    1
}

fn default_security_concurrency() -> usize {
    1
}

/// Configuration for the intrusive security engine. Guardrails: mandatory
/// `include_hosts` allowlist, hard request / wall-clock budget, per-host rate
/// limit, retry, and concurrency.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SecurityConfig {
    /// Own scope copy — separate from the proxy capture scope. At least one
    /// `include_hosts` pattern is required at run time.
    #[serde(default)]
    pub scope: ScopeConfig,
    /// Hard cap on actual HTTP requests sent (incl. retries).
    #[serde(default = "default_security_max_requests")]
    pub max_requests: u64,
    /// Per-request timeout in seconds (including retry attempts).
    #[serde(default = "default_security_timeout")]
    pub timeout_secs: u64,
    /// Per-host request rate cap (requests per second, 0 = unlimited).
    #[serde(default = "default_security_per_host_rps")]
    pub per_host_requests_per_sec: u32,
    /// Optional wall-clock budget for the whole security run.
    #[serde(default = "default_security_duration_budget")]
    pub duration_budget_secs: Option<u64>,
    /// Retries per request before considering it failed.
    #[serde(default = "default_security_retry_limit")]
    pub retry_limit: u32,
    /// Concurrency for sending requests (1 = sequential).
    #[serde(default = "default_security_concurrency")]
    pub concurrency: usize,
    /// Max tokens for the AI model when generating security plans (higher = more tests).
    #[serde(default = "default_security_ai_max_tokens")]
    pub ai_max_tokens: u32,
}

fn default_security_ai_max_tokens() -> u32 {
    200_000
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            scope: ScopeConfig::default(),
            max_requests: default_security_max_requests(),
            timeout_secs: default_security_timeout(),
            per_host_requests_per_sec: default_security_per_host_rps(),
            duration_budget_secs: default_security_duration_budget(),
            retry_limit: default_security_retry_limit(),
            concurrency: default_security_concurrency(),
            ai_max_tokens: default_security_ai_max_tokens(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum MatchConditionType {
    #[default]
    Always,
    Header,
    PathPattern,
    BodyRegex,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MatchCondition {
    #[serde(rename = "type", default)]
    pub kind: MatchConditionType,
    #[serde(default)]
    pub header: Option<String>,
    #[serde(default)]
    pub pattern: Option<String>,
}

impl Default for MatchCondition {
    fn default() -> Self {
        Self {
            kind: MatchConditionType::Always,
            header: None,
            pattern: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReplaceActionType {
    SetHeader,
    RemoveHeader,
    ReplaceBody,
    ReplaceUrl,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReplaceAction {
    #[serde(rename = "type")]
    pub kind: ReplaceActionType,
    #[serde(default)]
    pub header: Option<String>,
    #[serde(default)]
    pub value: Option<String>,
    #[serde(default)]
    pub pattern: Option<String>,
    #[serde(default)]
    pub replacement: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum RuleDirection {
    Request,
    Response,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MatchRule {
    pub name: String,
    pub direction: RuleDirection,
    pub r#match: MatchCondition,
    pub action: ReplaceAction,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AiConfig {
    /// DeepSeek API key. Prefer the `DEEPSEEK_API_KEY` environment variable;
    /// when absent this value is used. Never logged or returned to the UI.
    #[serde(default)]
    pub api_key: Option<String>,
    #[serde(default = "default_ai_base_url")]
    pub base_url: String,
    #[serde(default = "default_ai_model")]
    pub model: String,
    /// Hard cap on model output tokens per call to bound cost.
    #[serde(default = "default_ai_max_tokens")]
    pub max_tokens: u32,
    #[serde(default = "default_ai_timeout_secs")]
    pub timeout_secs: u64,
}

pub const DEFAULT_AI_BASE_URL: &str = "http://127.0.0.1:8317/v1";
pub const DEFAULT_AI_MODEL: &str = "ox-alpha";
pub const DEFAULT_AI_MAX_TOKENS: u32 = 200_000;
pub const DEFAULT_AI_TIMEOUT_SECS: u64 = 180;




fn default_ai_base_url() -> String {
    DEFAULT_AI_BASE_URL.to_owned()
}

fn default_ai_model() -> String {
    DEFAULT_AI_MODEL.to_owned()
}

const fn default_ai_max_tokens() -> u32 {
    DEFAULT_AI_MAX_TOKENS
}

const fn default_ai_timeout_secs() -> u64 {
    DEFAULT_AI_TIMEOUT_SECS
}

/// Thresholds for the response-analysis pipeline (overfetching heuristics,
/// PII census, entropy-based secret candidates). Tuned conservatively against
/// real captures; every field has a default so existing configs keep working.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AnalysisConfig {
    /// A JSON string field longer than this many bytes is flagged as long text.
    #[serde(default = "default_long_text_bytes")]
    pub long_text_bytes: usize,
    /// A Next.js RSC stream chunk longer than this many chars is flagged.
    #[serde(default = "default_rsc_chunk_chars")]
    pub rsc_chunk_chars: usize,
    /// A response body larger than this many bytes suggests over-fetching or
    /// missing pagination (aligns with published network-layer studies).
    #[serde(default = "default_oversized_response_bytes")]
    pub oversized_response_bytes: usize,
    /// More unique email addresses than this in one body indicates mass PII exposure.
    #[serde(default = "default_mass_email_threshold")]
    pub mass_email_threshold: usize,
    /// An array holding more objects than this indicates mass entity exposure.
    #[serde(default = "default_mass_entity_count")]
    pub mass_entity_count: usize,
    /// Minimum value length before entropy is considered for a candidate.
    #[serde(default = "default_entropy_min_length")]
    pub entropy_min_length: usize,
    /// Minimum Shannon entropy (bits per char) for a secret candidate. Random
    /// machine-generated tokens land around 4.7-5.5; human text stays below 4.0.
    #[serde(default = "default_entropy_min_bits")]
    pub entropy_min_bits: f64,
    /// Hard cap on high-entropy findings reported per body.
    #[serde(default = "default_max_entropy_findings")]
    pub max_entropy_findings: usize,
    /// Extra key fragments classified as `custom` sensitive fields — the flat
    /// multi-site extension point (e.g. `so_tai_khoan` for a banking target).
    #[serde(default)]
    pub extra_sensitive_keys: Vec<String>,
    /// Key fragments never treated as sensitive even if they contain a builtin
    /// sensitive substring; merged with the built-in benign blocklist.
    #[serde(default)]
    pub excluded_keys: Vec<String>,
    /// Minimum embedded-JSON size (bytes) on an HTML/RSC render surface before
    /// it counts as an API-payload-in-HTML finding.
    #[serde(default = "default_embedded_payload_min_bytes")]
    pub embedded_payload_min_bytes: usize,
}

pub const DEFAULT_LONG_TEXT_BYTES: usize = 300;
pub const DEFAULT_RSC_CHUNK_CHARS: usize = 400;
pub const DEFAULT_OVERSIZED_RESPONSE_BYTES: usize = 100_000;
pub const DEFAULT_MASS_EMAIL_THRESHOLD: usize = 10;
pub const DEFAULT_MASS_ENTITY_COUNT: usize = 50;
pub const DEFAULT_ENTROPY_MIN_LENGTH: usize = 28;
pub const DEFAULT_ENTROPY_MIN_BITS: f64 = 4.7;
pub const DEFAULT_MAX_ENTROPY_FINDINGS: usize = 20;
pub const DEFAULT_EMBEDDED_PAYLOAD_MIN_BYTES: usize = 1024;

fn default_long_text_bytes() -> usize {
    DEFAULT_LONG_TEXT_BYTES
}

fn default_rsc_chunk_chars() -> usize {
    DEFAULT_RSC_CHUNK_CHARS
}

fn default_oversized_response_bytes() -> usize {
    DEFAULT_OVERSIZED_RESPONSE_BYTES
}

fn default_mass_email_threshold() -> usize {
    DEFAULT_MASS_EMAIL_THRESHOLD
}

fn default_mass_entity_count() -> usize {
    DEFAULT_MASS_ENTITY_COUNT
}

fn default_entropy_min_length() -> usize {
    DEFAULT_ENTROPY_MIN_LENGTH
}

fn default_entropy_min_bits() -> f64 {
    DEFAULT_ENTROPY_MIN_BITS
}

const fn default_max_entropy_findings() -> usize {
    DEFAULT_MAX_ENTROPY_FINDINGS
}

const fn default_embedded_payload_min_bytes() -> usize {
    DEFAULT_EMBEDDED_PAYLOAD_MIN_BYTES
}

impl Default for AnalysisConfig {
    fn default() -> Self {
        Self {
            long_text_bytes: default_long_text_bytes(),
            rsc_chunk_chars: default_rsc_chunk_chars(),
            oversized_response_bytes: default_oversized_response_bytes(),
            mass_email_threshold: default_mass_email_threshold(),
            mass_entity_count: default_mass_entity_count(),
            entropy_min_length: default_entropy_min_length(),
            entropy_min_bits: default_entropy_min_bits(),
            max_entropy_findings: default_max_entropy_findings(),
            extra_sensitive_keys: Vec::new(),
            excluded_keys: Vec::new(),
            embedded_payload_min_bytes: default_embedded_payload_min_bytes(),
        }
    }
}

impl Default for AiConfig {
    fn default() -> Self {
        Self {
            api_key: Some("sk-matkhaucuatoi123456".to_owned()),
            base_url: default_ai_base_url(),
            model: default_ai_model(),
            max_tokens: default_ai_max_tokens(),
            timeout_secs: default_ai_timeout_secs(),
        }
    }
}


#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AppConfig {
    #[serde(default)]
    pub proxy: ProxyConfig,
    #[serde(default)]
    pub browser: BrowserConfig,
    #[serde(default)]
    pub buffer: BufferConfig,
    #[serde(default)]
    pub scanner: ScannerConfig,
    #[serde(default)]
    pub oast: OastConfig,
    #[serde(default)]
    pub scope: ScopeConfig,
    #[serde(default)]
    pub security: SecurityConfig,
    #[serde(default)]
    pub analysis: AnalysisConfig,
    #[serde(default)]
    pub ai: AiConfig,
    #[serde(default)]
    pub match_replace_rules: Vec<MatchRule>,
    #[serde(default)]
    pub host_profiles: std::collections::HashMap<String, AnalysisConfig>,
    #[serde(default = "default_log_level")]
    pub log_level: String,
    #[serde(default = "default_output_dir")]
    pub output_dir: PathBuf,
}

fn default_log_level() -> String {
    "INFO".to_owned()
}

fn default_output_dir() -> PathBuf {
    PathBuf::from("./output")
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            proxy: ProxyConfig::default(),
            browser: BrowserConfig::default(),
            buffer: BufferConfig::default(),
            scanner: ScannerConfig::default(),
            oast: OastConfig::default(),
            scope: ScopeConfig::default(),
            security: SecurityConfig::default(),
            analysis: AnalysisConfig::default(),
            ai: AiConfig::default(),
            match_replace_rules: Vec::new(),
            host_profiles: std::collections::HashMap::new(),
            log_level: default_log_level(),
            output_dir: default_output_dir(),
        }
    }
}

impl AppConfig {
    pub fn validate(&self) -> Result<(), DomainError> {
        if self.proxy.port < 1024 {
            return Err(DomainError::InvalidValue(
                "proxy.port must be between 1024 and 65535".to_owned(),
            ));
        }
        if !(100..=10_000_000).contains(&self.buffer.max_size) {
            return Err(DomainError::InvalidValue(
                "buffer.max_size must be between 100 and 10000000".to_owned(),
            ));
        }
        if !(1..=500).contains(&self.scanner.max_concurrent_requests) {
            return Err(DomainError::InvalidValue(
                "scanner.max_concurrent_requests must be between 1 and 500".to_owned(),
            ));
        }
        if self.scanner.request_timeout < 1.0 {
            return Err(DomainError::InvalidValue(
                "scanner.request_timeout must be at least 1 second".to_owned(),
            ));
        }
        if self.ai.timeout_secs == 0 {
            return Err(DomainError::InvalidValue(
                "ai.timeout_secs must be at least 1 second".to_owned(),
            ));
        }
        // max_tokens can be 0 to omit max_tokens from request body (e.g. for ox-alpha)

        if self.security.max_requests == 0 {
            return Err(DomainError::InvalidValue(
                "security.max_requests must be greater than zero".to_owned(),
            ));
        }
        if self.security.timeout_secs == 0 {
            return Err(DomainError::InvalidValue(
                "security.timeout_secs must be at least 1 second".to_owned(),
            ));
        }
        if self.security.concurrency == 0 || self.security.concurrency > 4 {
            return Err(DomainError::InvalidValue(
                "security.concurrency must be between 1 and 4".to_owned(),
            ));
        }
        let analysis = &self.analysis;
        if analysis.long_text_bytes == 0
            || analysis.rsc_chunk_chars == 0
            || analysis.oversized_response_bytes == 0
            || analysis.mass_email_threshold == 0
            || analysis.mass_entity_count == 0
            || analysis.entropy_min_length == 0
            || analysis.max_entropy_findings == 0
            || analysis.embedded_payload_min_bytes == 0
        {
            return Err(DomainError::InvalidValue(
                "analysis thresholds must be greater than zero".to_owned(),
            ));
        }
        if !(0.0..=8.0).contains(&analysis.entropy_min_bits) {
            return Err(DomainError::InvalidValue(
                "analysis.entropy_min_bits must be between 0 and 8 bits per char".to_owned(),
            ));
        }
        Ok(())
    }

    pub fn analysis_for_host(&self, host: &str) -> &AnalysisConfig {
        for (pattern, cfg) in &self.host_profiles {
            if let Ok(re) = regex::Regex::new(pattern) {
                if re.is_match(host) {
                    return cfg;
                }
            } else if pattern == host {
                return cfg;
            }
        }
        &self.analysis
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn analysis_config_defaults_are_conservative() {
        let config = AnalysisConfig::default();
        assert_eq!(config.long_text_bytes, 300);
        assert_eq!(config.rsc_chunk_chars, 400);
        assert_eq!(config.oversized_response_bytes, 100_000);
        assert_eq!(config.mass_email_threshold, 10);
        assert_eq!(config.mass_entity_count, 50);
        assert_eq!(config.entropy_min_length, 28);
        assert!((config.entropy_min_bits - 4.7).abs() < f64::EPSILON);
        assert_eq!(config.max_entropy_findings, 20);
        assert_eq!(config.embedded_payload_min_bytes, DEFAULT_EMBEDDED_PAYLOAD_MIN_BYTES);
        assert!(config.extra_sensitive_keys.is_empty());
        assert!(config.excluded_keys.is_empty());
    }

    #[test]
    fn analysis_config_defaults_apply_on_empty_json() {
        let config: AnalysisConfig = serde_json::from_str("{}").unwrap();
        assert_eq!(config, AnalysisConfig::default());
    }

    #[test]
    fn app_config_with_analysis_section_round_trips() {
        let json = r#"{"analysis": {"entropy_min_bits": 5.0, "mass_email_threshold": 25}}"#;
        let config: AppConfig = serde_json::from_str(json).unwrap();
        assert!((config.analysis.entropy_min_bits - 5.0).abs() < f64::EPSILON);
        assert_eq!(config.analysis.mass_email_threshold, 25);
        // Unspecified fields fall back to defaults.
        assert_eq!(config.analysis.long_text_bytes, DEFAULT_LONG_TEXT_BYTES);
        config.validate().unwrap();

        let encoded = serde_json::to_string(&config).unwrap();
        let decoded: AppConfig = serde_json::from_str(&encoded).unwrap();
        assert_eq!(config, decoded);
    }

    #[test]
    fn zero_analysis_thresholds_are_rejected() {
        for (field, value) in [
            ("long_text_bytes", "0"),
            ("oversized_response_bytes", "0"),
            ("mass_entity_count", "0"),
            ("max_entropy_findings", "0"),
        ] {
            let json = format!(r#"{{"analysis": {{"{field}": {value}}}}}"#);
            let config: AppConfig = serde_json::from_str(&json).unwrap();
            assert!(
                config.validate().is_err(),
                "{field}=0 must fail validation"
            );
        }
    }

    #[test]
    fn entropy_min_bits_out_of_range_is_rejected() {
        let json = r#"{"analysis": {"entropy_min_bits": 9.0}}"#;
        let config: AppConfig = serde_json::from_str(json).unwrap();
        assert!(config.validate().is_err());
    }
}
