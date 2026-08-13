use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::DomainError;

pub const DEFAULT_PROXY_HOST: &str = "127.0.0.1";
pub const DEFAULT_PROXY_PORT: u16 = 8080;
pub const DEFAULT_BUFFER_SIZE: usize = 100_000;
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
    r"youtube\.com",
    r"doubleclick\.net",
    r"facebook\.com",
    r"fbcdn\.net",
    r"cloudflareinsights\.com",
];
const DEFAULT_NOISE_PATHS: &[&str] = &[
    r".*\.(png|jpg|jpeg|gif|webp|svg|ico|jfif|css|js|woff2?|ttf|eot|map)$",
    r"/_next/static/",
    r"/cdn-cgi/",
    r"favicon",
];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProxyConfig {
    #[serde(default = "default_proxy_host")]
    pub host: String,
    #[serde(default = "default_proxy_port")]
    pub port: u16,
    #[serde(default)]
    pub ssl_cert_dir: Option<PathBuf>,
}

fn default_proxy_host() -> String {
    DEFAULT_PROXY_HOST.to_owned()
}

const fn default_proxy_port() -> u16 {
    DEFAULT_PROXY_PORT
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            host: default_proxy_host(),
            port: default_proxy_port(),
            ssl_cert_dir: None,
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
}

const fn default_buffer_size() -> usize {
    DEFAULT_BUFFER_SIZE
}

const fn default_true() -> bool {
    true
}

impl Default for BufferConfig {
    fn default() -> Self {
        Self {
            max_size: default_buffer_size(),
            dedup_enabled: true,
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
    pub match_replace_rules: Vec<MatchRule>,
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
            match_replace_rules: Vec::new(),
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
        Ok(())
    }
}
