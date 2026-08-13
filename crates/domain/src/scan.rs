use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::DomainError;

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
        })
    }
}
