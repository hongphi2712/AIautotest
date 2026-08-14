use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::DomainError;
use crate::config::ScopeConfig;

fn new_id() -> String {
    Uuid::new_v4().to_string()
}

fn now_utc() -> DateTime<Utc> {
    Utc::now()
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ScanJobStatus {
    Queued,
    Running,
    Completed,
    Failed,
    Cancelled,
}

fn default_scope() -> ScopeConfig {
    ScopeConfig::default()
}

fn default_true() -> bool {
    true
}

const fn default_request_timeout_secs() -> u64 {
    30
}

/// Configuration for one scan run. Enforces the security guardrails: scope,
/// budgets, rate limits, dry-run and deduplication.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScanConfig {
    #[serde(default = "default_scope")]
    pub scope: ScopeConfig,
    #[serde(default)]
    pub enabled_skills: Vec<String>,
    /// Upper bound of payloads applied to a single parameter.
    #[serde(default = "default_payload_limit")]
    pub payload_limit_per_param: usize,
    /// Retries per request before it is considered failed.
    #[serde(default)]
    pub retry_limit: u32,
    #[serde(default = "default_request_timeout_secs")]
    pub request_timeout_secs: u64,
    /// Optional wall-clock budget in seconds for the whole run.
    #[serde(default)]
    pub duration_budget_secs: Option<u64>,
    /// Dry-run: enumerate mutations without sending any request.
    #[serde(default)]
    pub dry_run: bool,
    #[serde(default = "default_true")]
    pub dedup_enabled: bool,
    /// Per-host request rate cap (requests per second).
    #[serde(default = "default_per_host_rate")]
    pub per_host_requests_per_sec: u32,
}

const fn default_payload_limit() -> usize {
    20
}

const fn default_per_host_rate() -> u32 {
    0
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            scope: default_scope(),
            enabled_skills: Vec::new(),
            payload_limit_per_param: default_payload_limit(),
            retry_limit: 0,
            request_timeout_secs: default_request_timeout_secs(),
            duration_budget_secs: None,
            dry_run: false,
            dedup_enabled: true,
            per_host_requests_per_sec: default_per_host_rate(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScanJob {
    #[serde(default = "new_id")]
    pub id: String,
    #[serde(default)]
    pub session_id: Option<String>,
    pub status: ScanJobStatus,
    #[serde(default = "now_utc")]
    pub created_at: DateTime<Utc>,
    #[serde(default)]
    pub started_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub finished_at: Option<DateTime<Utc>>,
    pub request_budget: u64,
    pub max_concurrency: u32,
    #[serde(default)]
    pub seed: Option<u64>,
    #[serde(default)]
    pub config: ScanConfig,
    /// Number of requests already sent; used for resumable scans.
    #[serde(default)]
    pub requests_sent: u64,
}

impl ScanJob {
    pub fn new(request_budget: u64, max_concurrency: u32) -> Result<Self, DomainError> {
        if request_budget == 0 {
            return Err(DomainError::InvalidValue(
                "scan request_budget must be greater than zero".to_owned(),
            ));
        }
        if max_concurrency == 0 {
            return Err(DomainError::InvalidValue(
                "scan max_concurrency must be greater than zero".to_owned(),
            ));
        }
        Ok(Self {
            id: new_id(),
            session_id: None,
            status: ScanJobStatus::Queued,
            created_at: now_utc(),
            started_at: None,
            finished_at: None,
            request_budget,
            max_concurrency,
            seed: None,
            config: ScanConfig::default(),
            requests_sent: 0,
        })
    }
}
