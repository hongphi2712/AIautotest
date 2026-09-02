//! Edge-driven execution engine for workflows. Executes nodes in dependency
//! order with `when`-based branching, variable capture, per-node
//! retry/timeout, workflow-level timeout and cancellation. Every node result
//! is recorded and optionally streamed to the UI.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

use api_tester_ports::{HttpClient, HttpRequest, HttpResponse};
use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::{Value, json};
use tokio_util::sync::CancellationToken;

use crate::contract::{
    AssertConfig, ConditionConfig, DelayConfig, ExtractVariableConfig, HttpRequestConfig,
    LoopConfig, Node, NodeKind, Workflow,
};
use crate::jsonpath;
use crate::validation::{join_url, reachable_between};

/// Runtime state: bound variables and per-node results.
#[derive(Debug, Default)]
pub struct RunState {
    pub vars: BTreeMap<String, Value>,
    pub node_results: BTreeMap<String, NodeResult>,
}

#[derive(Debug, Clone, Serialize)]
pub struct NodeResult {
    pub node_id: String,
    pub ok: bool,
    pub output: Value,
    pub error: Option<String>,
    pub duration_ms: u64,
}

/// Streamed to the UI after every node execution.
#[derive(Debug, Clone, Serialize)]
pub struct NodeEvent {
    pub run_id: String,
    pub node_id: String,
    pub ok: bool,
    pub output: Value,
    pub error: Option<String>,
    pub duration_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RunStatus {
    Completed,
    Failed,
    Cancelled,
    TimedOut,
}

#[derive(Debug, Clone, Serialize)]
pub struct RunResult {
    pub status: RunStatus,
    pub error: Option<String>,
    pub started_at: DateTime<Utc>,
    pub finished_at: DateTime<Utc>,
    pub results: BTreeMap<String, NodeResult>,
}

#[derive(Debug, thiserror::Error)]
pub enum WorkflowError {
    #[error("node {node_id}: {message}")]
    Node { node_id: String, message: String },
    #[error("workflow cancelled")]
    Cancelled,
    #[error("transport error: {0}")]
    Transport(String),
}

impl WorkflowError {
    pub fn is_cancelled(&self) -> bool {
        matches!(self, Self::Cancelled)
    }
}

/// Runs a workflow through an `HttpClient` port (real or mock).
pub struct WorkflowRunner {
    workflow: Arc<Workflow>,
    client: Arc<dyn HttpClient>,
    cancel: CancellationToken,
    run_id: String,
    on_node: Option<Arc<dyn Fn(NodeEvent) + Send + Sync>>,
}

impl WorkflowRunner {
    pub fn new(
        workflow: Arc<Workflow>,
        client: Arc<dyn HttpClient>,
        cancel: CancellationToken,
        run_id: impl Into<String>,
    ) -> Self {
        Self {
            workflow,
            client,
            cancel,
            run_id: run_id.into(),
            on_node: None,
        }
    }

    /// Registers a callback fired after each node execution.
    pub fn on_node(mut self, callback: impl Fn(NodeEvent) + Send + Sync + 'static) -> Self {
        self.on_node = Some(Arc::new(callback));
        self
    }

    /// Runs the workflow to completion, cancellation or timeout.
    pub async fn run(self) -> RunResult {
        let started_at = Utc::now();
        let mut state = RunState::default();
        let outcome = tokio::time::timeout(
            Duration::from_secs(self.workflow.timeout_secs.max(1)),
            self.run_into(&mut state),
        )
        .await;
        let finished_at = Utc::now();

        let (status, error) = match outcome {
            Ok(Ok(())) => (RunStatus::Completed, None),
            Ok(Err(error)) if error.is_cancelled() => {
                (RunStatus::Cancelled, Some(error.to_string()))
            }
            Ok(Err(error)) => (RunStatus::Failed, Some(error.to_string())),
            Err(_) => (
                RunStatus::TimedOut,
                Some(format!(
                    "workflow timed out after {}s",
                    self.workflow.timeout_secs
                )),
            ),
        };
        RunResult {
            status,
            error,
            started_at,
            finished_at,
            results: state.node_results,
        }
    }

    async fn run_into(&self, state: &mut RunState) -> Result<(), WorkflowError> {
        if self.workflow.nodes.is_empty() {
            return Err(WorkflowError::Node {
                node_id: String::new(),
                message: "workflow has no nodes".to_owned(),
            });
        }
        // Static in-degree over all edges; a node runs once every incoming
        // edge that *fires* has been consumed.
        let mut in_degree: HashMap<String, usize> = self
            .workflow
            .nodes
            .iter()
            .map(|node| (node.id.clone(), 0))
            .collect();
        for edge in &self.workflow.edges {
            *in_degree.entry(edge.to.clone()).or_default() += 1;
        }

        let mut queue: VecDeque<String> = self
            .workflow
            .nodes
            .iter()
            .filter(|node| in_degree.get(&node.id) == Some(&0))
            .map(|node| node.id.clone())
            .collect();
        queue.make_contiguous().sort_by_key(|id| self.index_of(id));

        let mut seen = HashSet::new();
        while let Some(id) = queue.pop_front() {
            if seen.contains(&id) {
                continue;
            }
            seen.insert(id.clone());
            self.check_cancelled()?;
            let Some(node) = self.workflow.node(&id).cloned() else {
                continue;
            };
            if let NodeKind::Loop { config } = &node.kind {
                let fired = self.run_loop(&node, config, state).await?;
                for target in fired {
                    self.decrement(&mut in_degree, &mut queue, &target);
                }
                continue;
            }
            let (fired, failed) = self.execute_node(&node, state).await?;
            if let Some(message) = failed {
                return Err(WorkflowError::Node {
                    node_id: id.clone(),
                    message,
                });
            }
            for target in fired {
                self.decrement(&mut in_degree, &mut queue, &target);
            }
        }
        Ok(())
    }

    fn decrement(
        &self,
        in_degree: &mut HashMap<String, usize>,
        queue: &mut VecDeque<String>,
        target: &str,
    ) {
        if let Some(degree) = in_degree.get_mut(target) {
            *degree = degree.saturating_sub(1);
            if *degree == 0 && !queue.iter().any(|q| q == target) {
                queue.push_back(target.to_owned());
            }
        }
    }

    fn check_cancelled(&self) -> Result<(), WorkflowError> {
        if self.cancel.is_cancelled() {
            Err(WorkflowError::Cancelled)
        } else {
            Ok(())
        }
    }

    fn index_of(&self, id: &str) -> usize {
        self.workflow
            .nodes
            .iter()
            .position(|node| node.id == id)
            .unwrap_or(usize::MAX)
    }

    /// Executes a non-loop node, records the result and returns the successor
    /// ids whose edge conditions passed. Returns `(fired, failure_message)`.
    async fn execute_node(
        &self,
        node: &Node,
        state: &mut RunState,
    ) -> Result<(Vec<String>, Option<String>), WorkflowError> {
        self.check_cancelled()?;
        let started = Instant::now();
        let outcome: Result<Value, WorkflowError> = match &node.kind {
            NodeKind::HttpRequest { config } => self.run_http(config, state).await,
            NodeKind::ExtractVariable { config } => self.run_extract(config, state),
            NodeKind::Assert { config } => self.run_assert(config, &node.id, state),
            NodeKind::Condition { config } => self.run_condition(config, state),
            NodeKind::Delay { config } => self.run_delay(config).await,
            NodeKind::Loop { .. } => unreachable!("loops are handled by the runner"),
        };

        let (output, error) = match outcome {
            Ok(output) => (output, None),
            Err(error) => (Value::Null, Some(error.to_string())),
        };
        let duration_ms = started.elapsed().as_millis() as u64;
        let ok = error.is_none();
        let node_result = NodeResult {
            node_id: node.id.clone(),
            ok,
            output: output.clone(),
            error,
            duration_ms,
        };
        state
            .node_results
            .insert(node.id.clone(), node_result.clone());
        self.emit(node_result);

        let fired = self.next_nodes(node, &output);
        Ok((
            fired,
            state
                .node_results
                .get(&node.id)
                .and_then(|r| r.error.clone()),
        ))
    }

    fn next_nodes(&self, node: &Node, output: &Value) -> Vec<String> {
        let bool_out = output.as_bool().unwrap_or(false);
        self.workflow
            .edges
            .iter()
            .filter(|edge| edge.from == node.id)
            .filter(|edge| match &edge.when {
                None => true,
                Some(when) => {
                    if when == "true" {
                        bool_out
                    } else {
                        !bool_out
                    }
                }
            })
            .map(|edge| edge.to.clone())
            .collect()
    }

    fn emit(&self, result: NodeResult) {
        if let Some(callback) = &self.on_node {
            callback(NodeEvent {
                run_id: self.run_id.clone(),
                node_id: result.node_id,
                ok: result.ok,
                output: result.output,
                error: result.error,
                duration_ms: result.duration_ms,
            });
        }
    }

    // --- node runners ---

    async fn run_http(
        &self,
        config: &HttpRequestConfig,
        state: &RunState,
    ) -> Result<Value, WorkflowError> {
        let method = config.method.trim().to_uppercase();
        let path = self.render(&config.path, state);
        let url = join_url(&self.workflow.base_url, &path);
        let headers = config
            .headers
            .iter()
            .map(|(name, value)| (name.clone(), self.render(value, state)))
            .collect();
        let body = config
            .body
            .as_ref()
            .map(|body| self.render(body, state).into_bytes());
        let request = HttpRequest {
            method,
            url,
            headers,
            body,
        };

        let timeout = Duration::from_secs(config.timeout_secs.max(1));
        let mut attempt = 0u32;
        loop {
            match tokio::time::timeout(timeout, self.client.send(request.clone())).await {
                Ok(Ok(response)) => return Ok(response_value(response)),
                Ok(Err(error)) => {
                    attempt += 1;
                    if attempt > config.retries {
                        return Err(WorkflowError::Transport(error.to_string()));
                    }
                }
                Err(_) => {
                    attempt += 1;
                    if attempt > config.retries {
                        return Err(WorkflowError::Node {
                            node_id: String::new(),
                            message: format!("request timed out after {}s", timeout.as_secs()),
                        });
                    }
                }
            }
            tokio::time::sleep(Duration::from_millis(50 * u64::from(attempt))).await;
            self.check_cancelled()?;
        }
    }

    fn run_extract(
        &self,
        config: &ExtractVariableConfig,
        state: &mut RunState,
    ) -> Result<Value, WorkflowError> {
        let value = self.resolve_source(&config.source, state)?;
        let value = self.apply_path(&value, &config.path)?;
        state.vars.insert(config.name.clone(), value.clone());
        Ok(value)
    }

    fn run_assert(
        &self,
        config: &AssertConfig,
        node_id: &str,
        state: &RunState,
    ) -> Result<Value, WorkflowError> {
        let value = self.resolve_source(&config.source, state)?;
        let value = self.apply_path(&value, &config.path)?;
        let passed = self.compare(&config.operator, &value, &config.expected)?;
        if !passed {
            return Err(WorkflowError::Node {
                node_id: node_id.to_owned(),
                message: format!(
                    "assert failed: {} {} {} (got {value})",
                    config.source, config.operator, config.expected
                ),
            });
        }
        Ok(Value::Bool(true))
    }

    fn run_condition(
        &self,
        config: &ConditionConfig,
        state: &RunState,
    ) -> Result<Value, WorkflowError> {
        let value = self.resolve_source(&config.source, state)?;
        let value = self.apply_path(&value, &config.path)?;
        Ok(Value::Bool(self.compare(
            &config.operator,
            &value,
            &config.value,
        )?))
    }

    async fn run_delay(&self, config: &DelayConfig) -> Result<Value, WorkflowError> {
        if config.ms > 0 {
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_millis(config.ms)) => {}
                _ = self.cancel.cancelled() => return Err(WorkflowError::Cancelled),
            }
        }
        Ok(json!({ "ms": config.ms }))
    }

    async fn run_loop(
        &self,
        node: &Node,
        config: &LoopConfig,
        state: &mut RunState,
    ) -> Result<Vec<String>, WorkflowError> {
        let started = Instant::now();
        let source = self.resolve_source(&config.source, state)?;
        let items = match source {
            Value::Array(items) => items,
            _ => {
                return Err(WorkflowError::Node {
                    node_id: node.id.clone(),
                    message: format!("loop source is not an array: {}", config.source),
                });
            }
        };
        let total = items.len();
        let iterations = total.min(config.max_iterations as usize);
        for item in items.into_iter().take(iterations) {
            self.check_cancelled()?;
            state.vars.insert(config.item.clone(), item);
            self.run_range(&config.body_start, &config.body_end, state)
                .await?;
        }
        state.vars.remove(&config.item);

        let node_result = NodeResult {
            node_id: node.id.clone(),
            ok: true,
            output: json!({ "iterations": iterations, "items": total }),
            error: None,
            duration_ms: started.elapsed().as_millis() as u64,
        };
        state
            .node_results
            .insert(node.id.clone(), node_result.clone());
        self.emit(node_result);

        // Continue from the loop body exit.
        let body_end = self.workflow.node(&config.body_end).cloned();
        let last_output = body_end
            .as_ref()
            .and_then(|n| state.node_results.get(&n.id))
            .map(|r| r.output.clone())
            .unwrap_or_else(|| Value::Null);
        Ok(match body_end {
            Some(end) => self.next_nodes(&end, &last_output),
            None => Vec::new(),
        })
    }

    /// Executes the DAG slice from `from` to `to` (inclusive) once.
    async fn run_range(
        &self,
        from: &str,
        to: &str,
        state: &mut RunState,
    ) -> Result<(), WorkflowError> {
        let mut body_ids: HashSet<String> = reachable_between(&self.workflow, from, to)
            .into_iter()
            .map(|node| node.id.clone())
            .collect();
        body_ids.insert(from.to_owned());
        body_ids.insert(to.to_owned());

        let mut in_degree: HashMap<String, usize> =
            body_ids.iter().map(|id| (id.clone(), 0)).collect();
        for edge in &self.workflow.edges {
            if body_ids.contains(&edge.from) && body_ids.contains(&edge.to) {
                *in_degree.entry(edge.to.clone()).or_default() += 1;
            }
        }

        let mut queue: VecDeque<String> = body_ids
            .iter()
            .filter(|id| in_degree.get(*id) == Some(&0))
            .cloned()
            .collect();
        let mut starts: Vec<String> = queue.drain(..).collect();
        starts.sort_by_key(|id| self.index_of(id));
        queue.extend(starts);

        let mut seen = HashSet::new();
        while let Some(id) = queue.pop_front() {
            if seen.contains(&id) {
                continue;
            }
            seen.insert(id.clone());
            self.check_cancelled()?;
            let Some(node) = self.workflow.node(&id).cloned() else {
                continue;
            };
            if matches!(node.kind, NodeKind::Loop { .. }) {
                return Err(WorkflowError::Node {
                    node_id: node.id.clone(),
                    message: "nested loops are not supported".to_owned(),
                });
            }
            let (fired, failed) = self.execute_node(&node, state).await?;
            if let Some(message) = failed {
                return Err(WorkflowError::Node {
                    node_id: id.clone(),
                    message,
                });
            }
            for target in fired {
                if body_ids.contains(&target) {
                    self.decrement(&mut in_degree, &mut queue, &target);
                }
            }
            if id == to {
                break;
            }
        }
        Ok(())
    }

    // --- source resolution & helpers ---

    fn resolve_source(&self, source: &str, state: &RunState) -> Result<Value, WorkflowError> {
        let trimmed = source.trim();
        if let Some(name) = trimmed.strip_prefix("var.") {
            return state
                .vars
                .get(name)
                .cloned()
                .ok_or_else(|| WorkflowError::Node {
                    node_id: String::new(),
                    message: format!("unknown variable: {name}"),
                });
        }
        if let Some((head, tail)) = trimmed.split_once('.') {
            if let Some(node_result) = state.node_results.get(head) {
                let mut value = node_result.output.clone();
                for token in tail.split('.') {
                    if token.is_empty() {
                        return Err(WorkflowError::Node {
                            node_id: String::new(),
                            message: format!("bad source path: {trimmed}"),
                        });
                    }
                    value = key_lookup(&value, token).ok_or_else(|| WorkflowError::Node {
                        node_id: String::new(),
                        message: format!("source path not found: {trimmed}"),
                    })?;
                }
                return Ok(value);
            }
        }
        state
            .vars
            .get(trimmed)
            .cloned()
            .ok_or_else(|| WorkflowError::Node {
                node_id: String::new(),
                message: format!("unknown source: {trimmed}"),
            })
    }

    fn apply_path(&self, value: &Value, path: &str) -> Result<Value, WorkflowError> {
        let path = path.trim();
        if path.is_empty() {
            return Ok(value.clone());
        }
        let mut candidate = value.clone();
        if let Value::String(text) = &candidate {
            if let Ok(parsed) = serde_json::from_str::<Value>(text) {
                candidate = parsed;
            }
        }
        jsonpath::resolve(&candidate, path)
            .cloned()
            .ok_or_else(|| WorkflowError::Node {
                node_id: String::new(),
                message: format!("json path not found: {path}"),
            })
    }

    fn compare(&self, operator: &str, left: &Value, right: &Value) -> Result<bool, WorkflowError> {
        let result = match operator {
            "eq" => left == right,
            "ne" => left != right,
            "gt" => number(left) > number(right),
            "lt" => number(left) < number(right),
            "contains" => match left {
                Value::Array(items) => items.contains(right),
                Value::String(text) => right.as_str().is_some_and(|needle| text.contains(needle)),
                _ => false,
            },
            other => {
                return Err(WorkflowError::Node {
                    node_id: String::new(),
                    message: format!("unknown operator: {other}"),
                });
            }
        };
        Ok(result)
    }

    fn render(&self, template: &str, state: &RunState) -> String {
        static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
        let re = RE.get_or_init(|| regex::Regex::new(r"\{\{\s*([A-Za-z0-9_.]+)\s*\}\}").unwrap());
        re.replace_all(template, |captures: &regex::Captures<'_>| {
            let name = &captures[1];
            if let Some(value) = state.vars.get(name) {
                value_to_string(value)
            } else {
                String::new()
            }
        })
        .into_owned()
    }
}

fn value_to_string(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        other => other.to_string(),
    }
}

fn number(value: &Value) -> f64 {
    match value {
        Value::Number(n) => n.as_f64().unwrap_or(0.0),
        Value::String(s) => s.parse::<f64>().unwrap_or(0.0),
        _ => 0.0,
    }
}

fn key_lookup(value: &Value, key: &str) -> Option<Value> {
    match value {
        Value::Object(map) => map
            .get(key)
            .or_else(|| {
                map.iter()
                    .find(|(k, _)| k.eq_ignore_ascii_case(key))
                    .map(|(_, v)| v)
            })
            .cloned(),
        Value::Array(items) => key
            .parse::<usize>()
            .ok()
            .and_then(|i| items.get(i))
            .cloned(),
        _ => None,
    }
}

fn response_value(response: HttpResponse) -> Value {
    let headers: BTreeMap<String, String> = response.headers.into_iter().collect();
    let body = String::from_utf8_lossy(&response.body).into_owned();
    let parsed = serde_json::from_str::<Value>(&body).ok();
    json!({
        "response": {
            "status": response.status,
            "headers": headers,
            "body": body,
            "json": parsed,
        }
    })
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use api_tester_ports::HttpResponse;
    use api_tester_test_support::MockHttpClient;
    use tokio_util::sync::CancellationToken;

    use super::{RunStatus, WorkflowRunner};
    use crate::contract::{
        AssertConfig, ConditionConfig, Edge, ExtractVariableConfig, HttpRequestConfig, LoopConfig,
        Node, NodeKind, Workflow,
    };

    fn client() -> Arc<MockHttpClient> {
        Arc::new(MockHttpClient::default())
    }

    fn request(id: &str, method: &str, path: &str, headers: Vec<(&str, &str)>) -> Node {
        Node {
            id: id.to_owned(),
            kind: NodeKind::HttpRequest {
                config: HttpRequestConfig {
                    method: method.to_owned(),
                    path: path.to_owned(),
                    headers: headers
                        .into_iter()
                        .map(|(k, v)| (k.to_owned(), v.to_owned()))
                        .collect(),
                    ..HttpRequestConfig::default()
                },
            },
        }
    }

    fn edge(from: &str, to: &str) -> Edge {
        Edge {
            from: from.to_owned(),
            to: to.to_owned(),
            when: None,
        }
    }

    fn edge_when(from: &str, to: &str, when: &str) -> Edge {
        Edge {
            from: from.to_owned(),
            to: to.to_owned(),
            when: Some(when.to_owned()),
        }
    }

    fn workflow(nodes: Vec<Node>, edges: Vec<Edge>) -> Arc<Workflow> {
        Arc::new(Workflow {
            name: "test".to_owned(),
            base_url: "https://api.example.com".to_owned(),
            nodes,
            edges,
            timeout_secs: 30,
        })
    }

    fn ok_json(status: u16, body: &str) -> HttpResponse {
        HttpResponse {
            status,
            headers: vec![("content-type".to_owned(), "application/json".to_owned())],
            body: body.as_bytes().to_vec(),
        }
    }

    async fn run(wf: Arc<Workflow>, http: Arc<MockHttpClient>) -> super::RunResult {
        WorkflowRunner::new(wf, http, CancellationToken::new(), "run-test")
            .run()
            .await
    }

    #[test]
    fn template_rendering() {
        let runner = WorkflowRunner::new(
            workflow(vec![], vec![]),
            client(),
            CancellationToken::new(),
            "r",
        );
        let state = super::RunState {
            vars: [("token".to_owned(), serde_json::json!("abc"))].into(),
            node_results: Default::default(),
        };
        assert_eq!(runner.render("/x/{{token}}", &state), "/x/abc");
        assert_eq!(runner.render("/x/{{ missing }}", &state), "/x/");
    }

    #[tokio::test]
    async fn linear_login_extract_profile() {
        let http = client();
        http.push(ok_json(200, r#"{"access_token":"tok_abc"}"#));
        http.push(ok_json(200, r#"{"id":1}"#));

        let wf = workflow(
            vec![
                request("login", "POST", "/api/login", vec![]),
                Node {
                    id: "extract".to_owned(),
                    kind: NodeKind::ExtractVariable {
                        config: ExtractVariableConfig {
                            source: "login.response.body".to_owned(),
                            path: "$.access_token".to_owned(),
                            name: "token".to_owned(),
                        },
                    },
                },
                request(
                    "profile",
                    "GET",
                    "/api/profile",
                    vec![("Authorization", "Bearer {{token}}")],
                ),
            ],
            vec![edge("login", "extract"), edge("extract", "profile")],
        );

        let result = run(wf, http).await;
        assert_eq!(result.status, RunStatus::Completed, "{:?}", result.error);

        // The profile request must have been sent with the captured token.
        let mut profile = None;
        for response in result.results.values() {
            if response.node_id == "profile" {
                profile = Some(response);
            }
        }
        let profile = profile.expect("profile node result");
        assert!(profile.ok);
        assert_eq!(profile.output["response"]["status"], 200);
    }

    #[tokio::test]
    async fn assert_failure_fails_run() {
        let http = client();
        http.push(ok_json(201, "{}"));
        let wf = workflow(
            vec![
                request("login", "POST", "/api/login", vec![]),
                Node {
                    id: "assert".to_owned(),
                    kind: NodeKind::Assert {
                        config: AssertConfig {
                            source: "login.response.status".to_owned(),
                            path: String::new(),
                            operator: "eq".to_owned(),
                            expected: serde_json::json!(200),
                        },
                    },
                },
            ],
            vec![edge("login", "assert")],
        );
        let result = run(wf, http).await;
        assert_eq!(result.status, RunStatus::Failed);
        assert!(result.error.unwrap_or_default().contains("assert failed"));
    }

    #[tokio::test]
    async fn condition_branches() {
        let http = client();
        http.push(ok_json(200, "{}"));
        let wf = workflow(
            vec![
                request("login", "POST", "/api/login", vec![]),
                Node {
                    id: "cond".to_owned(),
                    kind: NodeKind::Condition {
                        config: ConditionConfig {
                            source: "login.response.status".to_owned(),
                            path: String::new(),
                            operator: "eq".to_owned(),
                            value: serde_json::json!(200),
                        },
                    },
                },
                request("ok_branch", "GET", "/api/ok", vec![]),
                request("bad_branch", "GET", "/api/bad", vec![]),
            ],
            vec![
                edge("login", "cond"),
                edge_when("cond", "ok_branch", "true"),
                edge_when("cond", "bad_branch", "false"),
            ],
        );
        let result = run(wf, http).await;
        assert_eq!(result.status, RunStatus::Completed);
        assert!(result.results.contains_key("ok_branch"));
        assert!(!result.results.contains_key("bad_branch"));
    }

    #[tokio::test]
    async fn loop_iterates_over_items() {
        let http = client();
        http.push(ok_json(200, r#"{"items":[{"id":1},{"id":2},{"id":3}]}"#));
        for _ in 0..3 {
            http.push(ok_json(200, "{}"));
        }
        let wf = workflow(
            vec![
                request("fetch", "GET", "/api/items", vec![]),
                Node {
                    id: "extract".to_owned(),
                    kind: NodeKind::ExtractVariable {
                        config: ExtractVariableConfig {
                            source: "fetch.response.json".to_owned(),
                            path: "$.items".to_owned(),
                            name: "items".to_owned(),
                        },
                    },
                },
                Node {
                    id: "loop".to_owned(),
                    kind: NodeKind::Loop {
                        config: LoopConfig {
                            source: "var.items".to_owned(),
                            item: "it".to_owned(),
                            max_iterations: 10,
                            body_start: "use_item".to_owned(),
                            body_end: "use_item".to_owned(),
                        },
                    },
                },
                request("use_item", "GET", "/api/items/{{it.id}}", vec![]),
            ],
            vec![
                edge("fetch", "extract"),
                edge("extract", "loop"),
                edge("loop", "use_item"),
                edge("use_item", "after"),
            ],
        );

        let result = run(wf, http).await;
        assert_eq!(result.status, RunStatus::Completed, "{:?}", result.error);
        assert_eq!(result.results["loop"].output["iterations"], 3);
    }

    #[tokio::test]
    async fn cancellation_stops_run() {
        let http = client();
        http.push(ok_json(200, "{}"));
        let cancel = CancellationToken::new();
        cancel.cancel();
        let wf = workflow(vec![request("login", "POST", "/api/login", vec![])], vec![]);
        let result = WorkflowRunner::new(wf, http, cancel, "run").run().await;
        assert_eq!(result.status, RunStatus::Cancelled);
    }

    #[tokio::test]
    async fn workflow_timeout() {
        let http = client();
        let wf = Arc::new(Workflow {
            name: "slow".to_owned(),
            base_url: "https://api.example.com".to_owned(),
            nodes: vec![Node {
                id: "sleep".to_owned(),
                kind: NodeKind::Delay {
                    config: crate::contract::DelayConfig { ms: 60_000 },
                },
            }],
            edges: vec![],
            timeout_secs: 1,
        });
        let result = run(wf, http).await;
        assert_eq!(result.status, RunStatus::TimedOut);
    }

    #[tokio::test]
    async fn node_events_are_emitted() {
        let http = client();
        http.push(ok_json(200, "{}"));
        let events = Arc::new(std::sync::Mutex::new(Vec::new()));
        let events_clone = events.clone();
        let wf = workflow(vec![request("login", "POST", "/api/login", vec![])], vec![]);
        let result = WorkflowRunner::new(wf, http, CancellationToken::new(), "run-events")
            .on_node(move |event| events_clone.lock().unwrap().push(event))
            .run()
            .await;
        assert_eq!(result.status, RunStatus::Completed);
        let events = events.lock().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].node_id, "login");
        assert!(events[0].ok);
    }
}
