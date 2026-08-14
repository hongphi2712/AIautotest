use serde::{Deserialize, Serialize};

use crate::HttpFlow;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum DomainEvent {
    FlowCaptured {
        flow_id: String,
        session_id: String,
    },
    ScanCompleted {
        job_id: String,
        session_id: Option<String>,
        findings_count: usize,
    },
}

impl DomainEvent {
    pub fn flow_captured(flow: &HttpFlow) -> Self {
        Self::FlowCaptured {
            flow_id: flow.id.clone(),
            session_id: flow.session_id.clone(),
        }
    }

    pub fn scan_completed(job_id: &str, session_id: Option<&str>, findings_count: usize) -> Self {
        Self::ScanCompleted {
            job_id: job_id.to_owned(),
            session_id: session_id.map(str::to_owned),
            findings_count,
        }
    }
}
