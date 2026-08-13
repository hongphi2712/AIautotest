use serde::{Deserialize, Serialize};

use crate::HttpFlow;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum DomainEvent {
    FlowCaptured { flow_id: String, session_id: String },
}

impl DomainEvent {
    pub fn flow_captured(flow: &HttpFlow) -> Self {
        Self::FlowCaptured {
            flow_id: flow.id.clone(),
            session_id: flow.session_id.clone(),
        }
    }
}
