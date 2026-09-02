//! Workflow contract: the strict JSON schema the AI must produce and the
//! execution engine consumes. Node types are type-tagged (`"type"` field) and
//! serialise exactly as `{ "type": "http_request", "config": {...} }`.

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const DEFAULT_TIMEOUT_SECS: u64 = 300;
pub const DEFAULT_NODE_TIMEOUT_SECS: u64 = 15;
pub const DEFAULT_MAX_ITERATIONS: u32 = 10;

fn default_method() -> String {
    "GET".to_owned()
}

const fn default_timeout_secs() -> u64 {
    DEFAULT_TIMEOUT_SECS
}

const fn default_node_timeout_secs() -> u64 {
    DEFAULT_NODE_TIMEOUT_SECS
}

const fn default_retries() -> u32 {
    0
}

const fn default_delay_ms() -> u64 {
    0
}

const fn default_max_iterations() -> u32 {
    DEFAULT_MAX_ITERATIONS
}

/// A directed acyclic workflow: nodes do work, edges define ordering and
/// (condition) branching.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Workflow {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub base_url: String,
    #[serde(default)]
    pub nodes: Vec<Node>,
    #[serde(default)]
    pub edges: Vec<Edge>,
    /// Whole-workflow timeout in seconds.
    #[serde(default = "default_timeout_secs")]
    pub timeout_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Node {
    pub id: String,
    #[serde(flatten)]
    pub kind: NodeKind,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum NodeKind {
    HttpRequest { config: HttpRequestConfig },
    ExtractVariable { config: ExtractVariableConfig },
    Assert { config: AssertConfig },
    Delay { config: DelayConfig },
    Condition { config: ConditionConfig },
    Loop { config: LoopConfig },
}

impl NodeKind {
    pub fn type_name(&self) -> &'static str {
        match self {
            Self::HttpRequest { .. } => "http_request",
            Self::ExtractVariable { .. } => "extract_variable",
            Self::Assert { .. } => "assert",
            Self::Delay { .. } => "delay",
            Self::Condition { .. } => "condition",
            Self::Loop { .. } => "loop",
        }
    }

    /// Whether this node produces a boolean result used for `when` branching.
    pub fn is_boolean(&self) -> bool {
        matches!(self, Self::Condition { .. } | Self::Assert { .. })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HttpRequestConfig {
    #[serde(default = "default_method")]
    pub method: String,
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub headers: Vec<(String, String)>,
    #[serde(default)]
    pub body: Option<String>,
    /// Extra retries beyond the first attempt (transient failures only).
    #[serde(default = "default_retries")]
    pub retries: u32,
    #[serde(default = "default_node_timeout_secs")]
    pub timeout_secs: u64,
}

impl Default for HttpRequestConfig {
    fn default() -> Self {
        Self {
            method: default_method(),
            path: String::new(),
            headers: Vec::new(),
            body: None,
            retries: default_retries(),
            timeout_secs: default_node_timeout_secs(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ExtractVariableConfig {
    /// Where to read from, e.g. `login.response.body` or `var.something`.
    pub source: String,
    /// JSON path into the resolved value, e.g. `$.access_token`.
    #[serde(default)]
    pub path: String,
    /// Variable name to bind the extracted value to.
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AssertConfig {
    pub source: String,
    #[serde(default)]
    pub path: String,
    /// Comparison operator: `eq`, `ne`, `gt`, `lt`, `contains`.
    #[serde(default = "default_operator")]
    pub operator: String,
    pub expected: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ConditionConfig {
    pub source: String,
    #[serde(default)]
    pub path: String,
    #[serde(default = "default_operator")]
    pub operator: String,
    pub value: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DelayConfig {
    #[serde(default = "default_delay_ms")]
    pub ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LoopConfig {
    /// Variable holding the array to iterate over.
    pub source: String,
    /// Per-iteration variable name available to the loop body.
    pub item: String,
    #[serde(default = "default_max_iterations")]
    pub max_iterations: u32,
    /// First node id of the loop body (executed once per item).
    pub body_start: String,
    /// Last node id of the loop body (inclusive).
    pub body_end: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Edge {
    pub from: String,
    pub to: String,
    /// Branch filter: `"true"` / `"false"` — only valid on edges leaving a
    /// `condition` node. Absent means the edge is always taken.
    #[serde(default)]
    pub when: Option<String>,
}

fn default_operator() -> String {
    "eq".to_owned()
}

impl Workflow {
    pub fn node(&self, id: &str) -> Option<&Node> {
        self.nodes.iter().find(|node| node.id == id)
    }
}

#[cfg(test)]
mod tests {
    use super::{NodeKind, Workflow};
    use serde_json::json;

    #[test]
    fn example_contract_round_trips() {
        let json = json!({
            "name": "Login and fetch profile",
            "base_url": "https://api.example.com",
            "nodes": [
                {
                    "id": "login",
                    "type": "http_request",
                    "config": {
                        "method": "POST",
                        "path": "/api/login"
                    }
                },
                {
                    "id": "extract_token",
                    "type": "extract_variable",
                    "config": {
                        "source": "login.response.body",
                        "path": "$.access_token",
                        "name": "access_token"
                    }
                }
            ],
            "edges": [
                { "from": "login", "to": "extract_token" }
            ]
        });

        let workflow: Workflow = serde_json::from_value(json.clone()).expect("valid workflow");
        assert_eq!(workflow.name, "Login and fetch profile");
        assert_eq!(workflow.nodes.len(), 2);
        assert!(matches!(
            workflow.nodes[0].kind,
            NodeKind::HttpRequest { .. }
        ));
        assert!(matches!(
            workflow.nodes[1].kind,
            NodeKind::ExtractVariable { .. }
        ));
        assert_eq!(workflow.edges[0].from, "login");

        let round = serde_json::to_value(&workflow).unwrap();
        // The serialised form keeps the type-tagged shape for the AI contract.
        assert_eq!(round["nodes"][0]["type"], "http_request");
        assert_eq!(round["nodes"][0]["config"]["method"], "POST");
    }

    #[test]
    fn all_node_types_deserialize() {
        let json = json!({
            "name": "all",
            "nodes": [
                { "id": "a", "type": "http_request", "config": { "method": "GET", "path": "/" } },
                { "id": "b", "type": "extract_variable", "config": { "source": "a.response.body", "path": "$.x", "name": "x" } },
                { "id": "c", "type": "assert", "config": { "source": "b.output", "operator": "eq", "expected": 1 } },
                { "id": "d", "type": "delay", "config": { "ms": 10 } },
                { "id": "e", "type": "condition", "config": { "source": "b.output", "operator": "eq", "value": 1 } },
                { "id": "f", "type": "loop", "config": { "source": "var.items", "item": "it", "body_start": "a", "body_end": "a" } }
            ],
            "edges": []
        });
        let workflow: Workflow = serde_json::from_value(json).unwrap();
        let names: Vec<&str> = workflow.nodes.iter().map(|n| n.kind.type_name()).collect();
        assert_eq!(
            names,
            vec![
                "http_request",
                "extract_variable",
                "assert",
                "delay",
                "condition",
                "loop"
            ]
        );
    }

    #[test]
    fn missing_config_fields_default() {
        let json = json!({
            "name": "minimal",
            "nodes": [{ "id": "a", "type": "http_request", "config": { "path": "/x" } }],
            "edges": []
        });
        let workflow: Workflow = serde_json::from_value(json).unwrap();
        match &workflow.nodes[0].kind {
            NodeKind::HttpRequest { config } => {
                assert_eq!(config.method, "GET");
                assert_eq!(config.timeout_secs, 15);
            }
            _ => panic!("expected http_request"),
        }
        assert_eq!(workflow.timeout_secs, 300);
    }
}
