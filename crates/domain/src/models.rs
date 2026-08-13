use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

fn new_id() -> String {
    Uuid::new_v4().to_string()
}

fn now_utc() -> DateTime<Utc> {
    Utc::now()
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum InjectionLocation {
    Query,
    BodyJson,
    BodyForm,
    Header,
    Path,
    Cookie,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ParamType {
    Int,
    Float,
    String,
    Boolean,
    Email,
    Token,
    Id,
    Uuid,
    Date,
    Enum,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AnalyzedParam {
    pub name: String,
    #[serde(rename = "type")]
    pub param_type: ParamType,
    pub location: InjectionLocation,
    #[serde(default)]
    pub sample_value: Option<Value>,
    #[serde(default)]
    pub enum_values: Vec<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TokenType {
    Jwt,
    SessionCookie,
    Csrf,
    ApiKey,
    OauthAccess,
    OauthRefresh,
    CustomHeader,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExtractedToken {
    #[serde(rename = "type")]
    pub token_type: TokenType,
    pub value: String,
    #[serde(default)]
    pub source_flow_id: String,
    #[serde(default)]
    pub location: String,
    #[serde(default)]
    pub json_path: Option<String>,
    #[serde(default)]
    pub header_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FlowDependency {
    pub source_flow_id: String,
    pub target_flow_id: String,
    pub token: ExtractedToken,
    pub usage_location: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Payload {
    pub value: String,
    pub location: InjectionLocation,
    pub param_name: String,
    pub skill_name: String,
    #[serde(default)]
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "UPPERCASE")]
pub enum Severity {
    Info,
    Warning,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Finding {
    #[serde(default = "new_id")]
    pub id: String,
    pub title: String,
    pub description: String,
    pub severity: Severity,
    pub skill_name: String,
    #[serde(default)]
    pub flow_id: String,
    #[serde(default)]
    pub flow_path: String,
    #[serde(default)]
    pub flow_method: String,
    #[serde(default)]
    pub payload_value: Option<String>,
    #[serde(default)]
    pub payload_description: Option<String>,
    #[serde(default)]
    pub evidence: Option<String>,
    #[serde(default)]
    pub remediation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Session {
    #[serde(default = "new_id")]
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub target_host: String,
    #[serde(default = "now_utc")]
    pub start_time: DateTime<Utc>,
    #[serde(default)]
    pub end_time: Option<DateTime<Utc>>,
    #[serde(default)]
    pub flow_count: u64,
    #[serde(default)]
    pub notes: String,
}

impl Session {
    pub fn duration_seconds_at(&self, now: DateTime<Utc>) -> f64 {
        let end = self.end_time.unwrap_or(now);
        (end - self.start_time).num_milliseconds() as f64 / 1000.0
    }
}

impl Default for Session {
    fn default() -> Self {
        Self {
            id: new_id(),
            name: String::new(),
            target_host: String::new(),
            start_time: now_utc(),
            end_time: None,
            flow_count: 0,
            notes: String::new(),
        }
    }
}
