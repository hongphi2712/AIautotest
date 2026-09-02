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

impl TokenType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Jwt => "jwt",
            Self::SessionCookie => "session_cookie",
            Self::Csrf => "csrf",
            Self::ApiKey => "api_key",
            Self::OauthAccess => "oauth_access",
            Self::OauthRefresh => "oauth_refresh",
            Self::CustomHeader => "custom_header",
        }
    }
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

/// A user annotation (comment + highlight color) attached to a sitemap URL.
/// The key is `{scheme}://{host}{path}` with the query string stripped.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SitemapAnnotation {
    pub key: String,
    #[serde(default)]
    pub comment: Option<String>,
    #[serde(default)]
    pub color: Option<String>,
    #[serde(default = "now_utc")]
    pub updated_at: DateTime<Utc>,
}

/// Highlight colors available for sitemap annotations (Burp-style palette).
pub const SITEMAP_ANNOTATION_COLORS: &[&str] = &[
    "red", "orange", "yellow", "green", "cyan", "blue", "pink", "magenta", "gray",
];

/// A saved workflow version (the full workflow spec stored as JSON).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkflowVersion {
    pub id: String,
    pub name: String,
    pub version: i64,
    pub base_url: String,
    /// Serialised `Workflow` contract JSON.
    pub spec_json: String,
    /// `draft` or `approved`.
    pub status: String,
    #[serde(default = "now_utc")]
    pub created_at: DateTime<Utc>,
    #[serde(default)]
    pub approved_at: Option<DateTime<Utc>>,
}

impl Default for WorkflowVersion {
    fn default() -> Self {
        Self {
            id: new_id(),
            name: String::new(),
            version: 1,
            base_url: String::new(),
            spec_json: String::new(),
            status: "draft".to_owned(),
            created_at: now_utc(),
            approved_at: None,
        }
    }
}

/// A workflow run (execution) persisted across nodes and finished.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkflowRun {
    pub run_id: String,
    /// References `WorkflowVersion.id`.
    pub version_id: String,
    #[serde(default = "now_utc")]
    pub started_at: DateTime<Utc>,
    #[serde(default)]
    pub finished_at: Option<DateTime<Utc>>,
    /// `queued`, `running`, `completed`, `failed`, `cancelled`, `timed_out`.
    pub status: String,
    /// JSON object keyed by node id with per-node results.
    pub results_json: String,
}

impl Default for WorkflowRun {
    fn default() -> Self {
        Self {
            run_id: new_id(),
            version_id: String::new(),
            started_at: now_utc(),
            finished_at: None,
            status: "queued".to_owned(),
            results_json: "{}".to_owned(),
        }
    }
}

/// A security test plan generated by AI (full plan JSON).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecurityPlan {
    pub id: String,
    pub name: String,
    pub base_url: String,
    /// Serialised `SecurityTestPlan` JSON.
    pub plan_json: String,
    /// `draft` or `approved`.
    pub status: String,
    #[serde(default = "now_utc")]
    pub created_at: DateTime<Utc>,
    #[serde(default)]
    pub approved_at: Option<DateTime<Utc>>,
}

impl Default for SecurityPlan {
    fn default() -> Self {
        Self {
            id: new_id(),
            name: String::new(),
            base_url: String::new(),
            plan_json: String::new(),
            status: "draft".to_owned(),
            created_at: now_utc(),
            approved_at: None,
        }
    }
}

/// A security plan execution run.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecurityRun {
    pub run_id: String,
    /// References `SecurityPlan.id`.
    pub plan_id: String,
    #[serde(default = "now_utc")]
    pub started_at: DateTime<Utc>,
    #[serde(default)]
    pub finished_at: Option<DateTime<Utc>>,
    /// `running`, `completed`, `failed`, `cancelled`, `timed_out`.
    pub status: String,
    /// JSON array of `Finding` / `SecurityFinding`.
    pub findings_json: String,
}

impl Default for SecurityRun {
    fn default() -> Self {
        Self {
            run_id: new_id(),
            plan_id: String::new(),
            started_at: now_utc(),
            finished_at: None,
            status: "queued".to_owned(),
            findings_json: "[]".to_owned(),
        }
    }
}
