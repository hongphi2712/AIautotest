//! Workflow-generation prompts: strict JSON contract (no free code) plus an
//! optional compact traffic context and a bounded repair hint. The system
//! prompt is stable (cached prefix); only the user message varies.

use crate::prompt::format_context;

use crate::prompt::FlowContext;

const WORKFLOW_SYSTEM_PROMPT: &str = r#"You are an API workflow designer for a security testing tool. Convert a natural-language
request into ONE STRICT JSON object describing a workflow. Output ONLY that JSON object —
no commentary, no markdown code fences, no explanation. The response must be parseable as
a single JSON object.

WORKFLOW SCHEMA (the only shape allowed):
{
  "name": string,
  "base_url": string,
  "timeout_secs": number (optional, default 300),
  "nodes": [ { "id": string, "type": "<node type>", "config": { ... } } ],
  "edges": [ { "from": "<node id>", "to": "<node id>", "when": "true"|"false" (optional, only on edges leaving a condition node) } ]
}

NODE TYPES and their configs:
- http_request: {
    "method": "GET"|"POST"|"PUT"|"DELETE"|...,
    "path": "/api/...",
    "headers": [["Header-Name", "value"], ...] (optional),
    "body": "raw or JSON string" (optional),
    "retries": number (optional, default 0),
    "timeout_secs": number (optional, default 15)
  }
- extract_variable: {
    "source": "<node_id>.response.body" | "<node_id>.response.status" | "<node_id>.response.json" | "<node_id>.output" | "var.<name>",
    "path": "$.json.path" (optional, e.g. $.access_token),
    "name": "variable_name"
  }
- assert: { "source": "...", "path": "$.optional", "operator": "eq"|"ne"|"gt"|"lt"|"contains", "expected": <value> }
- delay: { "ms": number }
- condition: { "source": "...", "path": "$.optional", "operator": "eq"|"ne"|"gt"|"lt"|"contains", "value": <value> }
- loop: { "source": "var.<array_variable>", "item": "item_var", "max_iterations": number, "body_start": "<node id>", "body_end": "<node id>" }

RULES:
- The edge graph MUST be a DAG — no cycles. Loops are expressed with the loop node, never with graph cycles.
- Every source must reference a node that runs before it, or a variable produced earlier by an extract_variable (or the loop item variable).
- Use {{variable}} templates inside path/headers/body to inject captured variables.
- For a loop, the loop node itself and the body nodes are connected by edges: loop -> body_start, body_end -> next node after the loop.
- Keep it minimal: only the requests/steps asked for."#;

const WORKFLOW_EXAMPLE: &str = r#"EXAMPLE (request: "Login to the API, take the access_token, call /profile, then /orders and check status code is 200."):
{
  "name": "Login and fetch orders",
  "base_url": "https://api.example.com",
  "nodes": [
    { "id": "login", "type": "http_request", "config": { "method": "POST", "path": "/api/login", "headers": [["Content-Type", "application/json"]], "body": "{\"username\":\"admin\",\"password\":\"pass\"}" } },
    { "id": "extract_token", "type": "extract_variable", "config": { "source": "login.response.body", "path": "$.access_token", "name": "access_token" } },
    { "id": "profile", "type": "http_request", "config": { "method": "GET", "path": "/api/profile", "headers": [["Authorization", "Bearer {{access_token}}"]] } },
    { "id": "orders", "type": "http_request", "config": { "method": "GET", "path": "/api/orders", "headers": [["Authorization", "Bearer {{access_token}}"]] } },
    { "id": "check", "type": "assert", "config": { "source": "orders.response.status", "operator": "eq", "expected": 200 } }
  ],
  "edges": [
    { "from": "login", "to": "extract_token" },
    { "from": "extract_token", "to": "profile" },
    { "from": "profile", "to": "orders" },
    { "from": "orders", "to": "check" }
  ]
}"#;

/// The final system/user pair for workflow generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkflowPrompt {
    pub system: String,
    pub user: String,
}

/// Builds the workflow-generation prompt. `context` is an optional compact,
/// redacted traffic summary (never raw bodies/token values). `repair_hint`
/// carries the previous validation errors for the bounded repair loop.
pub fn build_workflow_prompt(
    request: &str,
    base_url: &str,
    context: Option<&FlowContext>,
    repair_hint: Option<&str>,
) -> WorkflowPrompt {
    let system = format!("{WORKFLOW_SYSTEM_PROMPT}\n\n{WORKFLOW_EXAMPLE}\n");

    let mut user = String::with_capacity(1024);
    user.push_str(&format!("Request: {request}\n"));
    user.push_str(&format!("Base URL: {base_url}\n\n"));

    if let Some(context) = context {
        user.push_str("Captured traffic summary for reference (keep the Base URL above):\n");
        user.push_str(&format_context(context, 100));
        user.push('\n');
    }

    if let Some(repair_hint) = repair_hint {
        user.push_str("\nYour previous response was invalid. Fix ALL of these issues and return the corrected workflow JSON only:\n");
        user.push_str(repair_hint);
        user.push('\n');
    } else {
        user.push_str("Respond with the workflow JSON object only.");
    }

    WorkflowPrompt { system, user }
}

#[cfg(test)]
mod tests {
    use super::build_workflow_prompt;
    use crate::prompt::FlowContext;

    #[test]
    fn prompt_contains_schema_and_request() {
        let prompt = build_workflow_prompt(
            "Login and call /profile",
            "https://api.example.com",
            None,
            None,
        );
        assert!(prompt.system.contains("http_request"));
        assert!(prompt.system.contains("extract_variable"));
        assert!(prompt.system.contains("WORKFLOW SCHEMA"));
        assert!(prompt.user.contains("Login and call /profile"));
        assert!(prompt.user.contains("https://api.example.com"));
        assert!(prompt.user.contains("workflow JSON object only"));
    }

    #[test]
    fn prompt_includes_context_and_repair_hint() {
        let context = FlowContext::default();
        let prompt =
            build_workflow_prompt("x", "https://a.b", Some(&context), Some("1. unknown node"));
        assert!(prompt.user.contains("Captured traffic summary"));
        assert!(prompt.user.contains("previous response was invalid"));
        assert!(prompt.user.contains("1. unknown node"));
    }

    #[test]
    fn prompt_never_contains_secrets() {
        let prompt = build_workflow_prompt("x", "https://a.b", None, None);
        assert!(!prompt.system.contains("Bearer eyJ"));
        assert!(!prompt.user.contains("Bearer eyJ"));
    }
}
