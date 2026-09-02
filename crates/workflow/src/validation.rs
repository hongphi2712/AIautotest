//! Graph + dataflow validation for workflows. `errors` block the workflow;
//! `scope_warnings` only require explicit user confirmation before running.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};

use api_tester_domain::ScopeFilter;
use serde::Serialize;

use crate::contract::{Node, NodeKind, Workflow};

/// One request that falls outside the configured capture scope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ScopeWarning {
    pub node_id: String,
    pub url: String,
}

/// Result of validating a workflow.
#[derive(Debug, Clone, Default)]
pub struct Validation {
    /// Blocking problems (must be fixed — possibly via the AI repair loop).
    pub errors: Vec<String>,
    /// Non-blocking scope warnings (require confirm at run time).
    pub scope_warnings: Vec<ScopeWarning>,
}

impl Validation {
    pub fn is_valid(&self) -> bool {
        self.errors.is_empty()
    }
}

/// Validates structure, dataflow and scope. `scope` may be `None` when the
/// caller has no scope configured (scope checks are then skipped).
pub fn validate(workflow: &Workflow, scope: Option<&ScopeFilter>) -> Validation {
    let mut validation = Validation::default();

    // --- node ids ---
    let mut ids: HashSet<&str> = HashSet::new();
    for node in &workflow.nodes {
        if !ids.insert(node.id.as_str()) {
            validation
                .errors
                .push(format!("duplicate node id: {}", node.id));
        }
    }
    if workflow.nodes.is_empty() {
        validation.errors.push("workflow has no nodes".to_owned());
        return validation;
    }

    // --- edges ---
    let mut edge_keys: HashSet<(&str, &str)> = HashSet::new();
    for edge in &workflow.edges {
        if !ids.contains(edge.from.as_str()) {
            validation
                .errors
                .push(format!("edge from unknown node: {}", edge.from));
        }
        if !ids.contains(edge.to.as_str()) {
            validation
                .errors
                .push(format!("edge to unknown node: {}", edge.to));
        }
        if !edge_keys.insert((edge.from.as_str(), edge.to.as_str())) {
            validation
                .errors
                .push(format!("duplicate edge: {} -> {}", edge.from, edge.to));
        }
        if let Some(when) = &edge.when {
            if when != "true" && when != "false" {
                validation.errors.push(format!(
                    "edge {} -> {}: when must be \"true\" or \"false\"",
                    edge.from, edge.to
                ));
            }
        }
    }

    // --- when only from condition nodes ---
    for edge in &workflow.edges {
        if edge.when.is_some() {
            if let Some(node) = workflow.node(&edge.from) {
                if !node.kind.is_boolean() {
                    validation.errors.push(format!(
                        "edge {} -> {}: when is only allowed from condition/assert nodes",
                        edge.from, edge.to
                    ));
                }
            }
        }
    }

    // --- DAG check (topological sort over all edges) ---
    let topo = topological_order(workflow);
    let topo_order: HashMap<String, usize> = match &topo {
        Ok(order) => order
            .iter()
            .enumerate()
            .map(|(index, id)| (id.clone(), index))
            .collect(),
        Err(cycle_nodes) => {
            validation.errors.push(format!(
                "workflow graph contains a cycle involving: {}",
                cycle_nodes.join(", ")
            ));
            // Continue validating dataflow with a best-effort order (input
            // order) so the AI repair loop gets all problems at once.
            workflow
                .nodes
                .iter()
                .enumerate()
                .map(|(index, node)| (node.id.clone(), index))
                .collect()
        }
    };

    // --- per-node semantic checks ---
    let mut produced_vars: HashSet<String> = HashSet::new();
    for node in order_nodes(workflow, &topo_order) {
        match &node.kind {
            NodeKind::HttpRequest { config } => {
                if config.method.trim().is_empty() {
                    validation
                        .errors
                        .push(format!("node {}: http_request has no method", node.id));
                }
                if config.path.trim().is_empty() {
                    validation
                        .errors
                        .push(format!("node {}: http_request has no path", node.id));
                }
                check_scope(workflow, node, scope, &mut validation);
            }
            NodeKind::ExtractVariable { config } => {
                if config.name.trim().is_empty() {
                    validation
                        .errors
                        .push(format!("node {}: extract_variable has no name", node.id));
                }
                if produced_vars.contains(&config.name) {
                    validation.errors.push(format!(
                        "node {}: variable \"{}\" is already produced earlier",
                        node.id, config.name
                    ));
                }
                check_source(&config.source, &topo_order, workflow, node, &mut validation);
                produced_vars.insert(config.name.clone());
            }
            NodeKind::Assert { config } => {
                if !matches!(
                    config.operator.as_str(),
                    "eq" | "ne" | "gt" | "lt" | "contains"
                ) {
                    validation.errors.push(format!(
                        "node {}: unknown operator \"{}\"",
                        node.id, config.operator
                    ));
                }
                check_source(&config.source, &topo_order, workflow, node, &mut validation);
            }
            NodeKind::Condition { config } => {
                if !matches!(
                    config.operator.as_str(),
                    "eq" | "ne" | "gt" | "lt" | "contains"
                ) {
                    validation.errors.push(format!(
                        "node {}: unknown operator \"{}\"",
                        node.id, config.operator
                    ));
                }
                check_source(&config.source, &topo_order, workflow, node, &mut validation);
            }
            NodeKind::Delay { config } => {
                if config.ms > 300_000 {
                    validation.errors.push(format!(
                        "node {}: delay {}ms exceeds the 5 minute cap",
                        node.id, config.ms
                    ));
                }
            }
            NodeKind::Loop { config } => {
                if !ids.contains(config.body_start.as_str()) {
                    validation.errors.push(format!(
                        "node {}: loop body_start unknown: {}",
                        node.id, config.body_start
                    ));
                }
                if !ids.contains(config.body_end.as_str()) {
                    validation.errors.push(format!(
                        "node {}: loop body_end unknown: {}",
                        node.id, config.body_end
                    ));
                }
                if config.max_iterations == 0 {
                    validation.errors.push(format!(
                        "node {}: loop max_iterations must be >= 1",
                        node.id
                    ));
                }
                if config.item.trim().is_empty() {
                    validation
                        .errors
                        .push(format!("node {}: loop item name is empty", node.id));
                }
                if produced_vars.contains(&config.item) {
                    validation.errors.push(format!(
                        "node {}: loop item \"{}\" collides with an existing variable",
                        node.id, config.item
                    ));
                }
                check_source(&config.source, &topo_order, workflow, node, &mut validation);
                produced_vars.insert(config.item.clone());
                // The loop body must not contain another loop (no nesting).
                let start_exists = ids.contains(config.body_start.as_str());
                let end_exists = ids.contains(config.body_end.as_str());
                if start_exists && end_exists {
                    for body_node in
                        reachable_between(workflow, &config.body_start, &config.body_end)
                    {
                        if matches!(body_node.kind, NodeKind::Loop { .. }) {
                            validation.errors.push(format!(
                                "node {}: nested loops are not supported (loop {} inside body)",
                                node.id, body_node.id
                            ));
                        }
                    }
                }
            }
        }
    }

    // --- start/end sanity ---
    let start_count = start_nodes(workflow).len();
    if start_count == 0 {
        validation
            .errors
            .push("workflow has no start node (everything is reachable from a cycle)".to_owned());
    }

    validation
}

fn order_nodes<'a>(workflow: &'a Workflow, order: &HashMap<String, usize>) -> Vec<&'a Node> {
    let mut nodes = workflow.nodes.iter().collect::<Vec<_>>();
    nodes.sort_by_key(|node| order.get(&node.id).copied().unwrap_or(usize::MAX));
    nodes
}

fn start_nodes(workflow: &Workflow) -> Vec<String> {
    let mut in_degree: HashMap<&str, usize> = workflow
        .nodes
        .iter()
        .map(|node| (node.id.as_str(), 0))
        .collect();
    for edge in &workflow.edges {
        if let Some(degree) = in_degree.get_mut(edge.to.as_str()) {
            *degree += 1;
        }
    }
    workflow
        .nodes
        .iter()
        .filter(|node| in_degree[node.id.as_str()] == 0)
        .map(|node| node.id.clone())
        .collect()
}

/// Kahn's topological sort. Returns the sorted node ids or the nodes involved
/// in a cycle when the graph is not a DAG.
fn topological_order(workflow: &Workflow) -> Result<Vec<String>, Vec<String>> {
    let mut in_degree: BTreeMap<&str, usize> = workflow
        .nodes
        .iter()
        .map(|node| (node.id.as_str(), 0))
        .collect();
    let mut adj: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for edge in &workflow.edges {
        adj.entry(edge.from.as_str())
            .or_default()
            .push(edge.to.as_str());
        if let Some(degree) = in_degree.get_mut(edge.to.as_str()) {
            *degree += 1;
        }
    }
    let mut queue: VecDeque<&str> = in_degree
        .iter()
        .filter(|(_, degree)| **degree == 0)
        .map(|(id, _)| *id)
        .collect();
    queue.make_contiguous().sort_unstable();

    let mut order = Vec::new();
    let mut remaining = workflow.nodes.len();
    while let Some(id) = queue.pop_front() {
        order.push(id.to_owned());
        remaining -= 1;
        if let Some(targets) = adj.get(id) {
            let mut targets = targets.clone();
            targets.sort_unstable();
            for target in targets {
                if let Some(degree) = in_degree.get_mut(target) {
                    *degree -= 1;
                    if *degree == 0 {
                        queue.push_back(target);
                    }
                }
            }
        }
    }
    if remaining > 0 {
        let in_cycle = in_degree
            .iter()
            .filter(|(_, degree)| **degree > 0)
            .map(|(id, _)| (*id).to_owned())
            .collect();
        Err(in_cycle)
    } else {
        Ok(order)
    }
}

/// Validates that a `source` reference resolves to a node/var produced earlier
/// in the DAG (dataflow check).
fn check_source(
    source: &str,
    topo_order: &HashMap<String, usize>,
    workflow: &Workflow,
    node: &Node,
    validation: &mut Validation,
) {
    let trimmed = source.trim();
    if trimmed.is_empty() {
        validation
            .errors
            .push(format!("node {}: empty source", node.id));
        return;
    }

    let (first, rest): (&str, Vec<&str>) = if let Some(rest) = trimmed.strip_prefix("var.") {
        (rest, Vec::new())
    } else if let Some((head, tail)) = trimmed.split_once('.') {
        (head, tail.split('.').collect())
    } else {
        (trimmed, Vec::new())
    };

    // Node reference (e.g. login.response.body) — must be an ancestor.
    if let Some(referenced) = workflow.node(first) {
        let node_index = topo_order.get(&node.id).copied().unwrap_or(0);
        let ref_index = topo_order.get(first).copied().unwrap_or(usize::MAX);
        if ref_index == usize::MAX {
            validation.errors.push(format!(
                "node {}: source references unknown node \"{}\"",
                node.id, first
            ));
            return;
        }
        if ref_index >= node_index {
            validation.errors.push(format!(
                "node {}: source references node \"{}\" which does not run before it",
                node.id, first
            ));
            return;
        }
        // Validate the rest of the path against the referenced node kind.
        if !rest.is_empty() {
            match &referenced.kind {
                NodeKind::HttpRequest { .. } => {
                    if rest[0] != "response" && rest[0] != "output" {
                        validation.errors.push(format!(
                            "node {}: source path \"{}\" is invalid for http_request node",
                            node.id, trimmed
                        ));
                    }
                }
                NodeKind::ExtractVariable { .. }
                | NodeKind::Assert { .. }
                | NodeKind::Condition { .. }
                | NodeKind::Delay { .. }
                | NodeKind::Loop { .. } => {
                    if rest[0] != "output" {
                        validation.errors.push(format!(
                            "node {}: source path \"{}\" is invalid for {} node",
                            node.id,
                            trimmed,
                            referenced.kind.type_name()
                        ));
                    }
                }
            }
        }
        return;
    }

    // Variable reference — must be produced by an ancestor extract_variable
    // (or be a loop item in scope).
    let name = first;
    let produced: HashSet<String> = workflow
        .nodes
        .iter()
        .filter_map(|n| match &n.kind {
            NodeKind::ExtractVariable { config } => Some(config.name.clone()),
            NodeKind::Loop { config } => Some(config.item.clone()),
            _ => None,
        })
        .collect();
    if !produced.contains(name) {
        validation
            .errors
            .push(format!("node {}: unknown source \"{}\"", node.id, trimmed));
    }
}

fn check_scope(
    workflow: &Workflow,
    node: &Node,
    scope: Option<&ScopeFilter>,
    validation: &mut Validation,
) {
    let Some(scope) = scope else { return };
    let NodeKind::HttpRequest { config } = &node.kind else {
        return;
    };
    let url = join_url(&workflow.base_url, &config.path);
    let Ok(parsed) = url::Url::parse(&url) else {
        return;
    };
    let Some(host) = parsed.host_str() else {
        return;
    };
    let path = parsed.path();
    if !scope.should_capture(host, path) {
        validation.scope_warnings.push(ScopeWarning {
            node_id: node.id.clone(),
            url,
        });
    }
}

pub fn join_url(base_url: &str, path: &str) -> String {
    let base = base_url.trim_end_matches('/');
    if path.starts_with('/') {
        format!("{base}{path}")
    } else if path.is_empty() {
        base.to_owned()
    } else {
        format!("{base}/{path}")
    }
}

/// Nodes reachable from `from` following edges, up to and including `to`.
pub fn reachable_between<'a>(workflow: &'a Workflow, from: &str, to: &str) -> Vec<&'a Node> {
    let mut seen = HashSet::new();
    let mut queue = VecDeque::new();
    queue.push_back(from);
    while let Some(id) = queue.pop_front() {
        if !seen.insert(id.to_owned()) {
            continue;
        }
        if id == to {
            continue;
        }
        for edge in &workflow.edges {
            if edge.from == id {
                queue.push_back(edge.to.as_str());
            }
        }
    }
    seen.into_iter()
        .filter_map(|id| workflow.node(&id))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::validate;
    use crate::contract::{Edge, HttpRequestConfig, Node, NodeKind, Workflow};
    use serde_json::json;

    fn workflow_with(nodes: Vec<Node>, edges: Vec<Edge>) -> Workflow {
        Workflow {
            name: "test".to_owned(),
            base_url: "https://api.example.com".to_owned(),
            nodes,
            edges,
            timeout_secs: 60,
        }
    }

    fn request(id: &str, method: &str, path: &str) -> Node {
        Node {
            id: id.to_owned(),
            kind: NodeKind::HttpRequest {
                config: HttpRequestConfig {
                    method: method.to_owned(),
                    path: path.to_owned(),
                    ..HttpRequestConfig::default()
                },
            },
        }
    }

    fn extract(id: &str, source: &str, name: &str) -> Node {
        Node {
            id: id.to_owned(),
            kind: NodeKind::ExtractVariable {
                config: crate::contract::ExtractVariableConfig {
                    source: source.to_owned(),
                    path: "$.access_token".to_owned(),
                    name: name.to_owned(),
                },
            },
        }
    }

    #[test]
    fn valid_linear_workflow_passes() {
        let workflow = workflow_with(
            vec![
                request("login", "POST", "/api/login"),
                extract("extract", "login.response.body", "token"),
            ],
            vec![Edge {
                from: "login".to_owned(),
                to: "extract".to_owned(),
                when: None,
            }],
        );
        let result = validate(&workflow, None);
        assert!(result.is_valid(), "{:?}", result.errors);
    }

    #[test]
    fn duplicate_ids_and_unknown_edges_fail() {
        let workflow = workflow_with(
            vec![request("a", "GET", "/"), request("a", "GET", "/")],
            vec![Edge {
                from: "a".to_owned(),
                to: "ghost".to_owned(),
                when: None,
            }],
        );
        let result = validate(&workflow, None);
        assert!(!result.is_valid());
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.contains("duplicate node id"))
        );
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.contains("unknown node: ghost"))
        );
    }

    #[test]
    fn cycle_is_rejected() {
        let workflow = workflow_with(
            vec![request("a", "GET", "/"), request("b", "GET", "/")],
            vec![
                Edge {
                    from: "a".to_owned(),
                    to: "b".to_owned(),
                    when: None,
                },
                Edge {
                    from: "b".to_owned(),
                    to: "a".to_owned(),
                    when: None,
                },
            ],
        );
        let result = validate(&workflow, None);
        assert!(result.errors.iter().any(|e| e.contains("cycle")));
    }

    #[test]
    fn forward_reference_is_rejected() {
        let workflow = workflow_with(
            vec![
                extract("extract", "login.response.body", "token"),
                request("login", "POST", "/api/login"),
            ],
            vec![Edge {
                from: "extract".to_owned(),
                to: "login".to_owned(),
                when: None,
            }],
        );
        let result = validate(&workflow, None);
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.contains("does not run before"))
        );
    }

    #[test]
    fn unknown_source_is_rejected() {
        let workflow = workflow_with(
            vec![extract("extract", "ghost.response.body", "token")],
            vec![],
        );
        let result = validate(&workflow, None);
        assert!(result.errors.iter().any(|e| e.contains("unknown source")));
    }

    #[test]
    fn when_on_non_condition_is_rejected() {
        let workflow = workflow_with(
            vec![request("a", "GET", "/"), request("b", "GET", "/")],
            vec![Edge {
                from: "a".to_owned(),
                to: "b".to_owned(),
                when: Some("true".to_owned()),
            }],
        );
        let result = validate(&workflow, None);
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.contains("when is only allowed"))
        );
    }

    #[test]
    fn scope_warnings_are_reported_not_errors() {
        let workflow = workflow_with(
            vec![
                request("login", "POST", "/api/login"),
                request("assets", "GET", "/app.js"),
            ],
            vec![],
        );
        let scope =
            api_tester_domain::ScopeFilter::new(api_tester_domain::ScopeConfig::default()).unwrap();
        let result = validate(&workflow, Some(&scope));
        assert!(result.is_valid());
        assert!(
            result
                .scope_warnings
                .iter()
                .any(|w| w.node_id == "assets" && w.url.ends_with("/app.js"))
        );
        assert!(!result.scope_warnings.iter().any(|w| w.node_id == "login"));
    }

    #[test]
    fn loop_body_validation() {
        let workflow = workflow_with(
            vec![
                extract("extract", "login.response.body", "items"),
                crate::contract::Node {
                    id: "loop".to_owned(),
                    kind: NodeKind::Loop {
                        config: crate::contract::LoopConfig {
                            source: "var.items".to_owned(),
                            item: "it".to_owned(),
                            max_iterations: 3,
                            body_start: "extract".to_owned(),
                            body_end: "ghost".to_owned(),
                        },
                    },
                },
            ],
            vec![Edge {
                from: "extract".to_owned(),
                to: "loop".to_owned(),
                when: None,
            }],
        );
        let result = validate(&workflow, None);
        assert!(result.errors.iter().any(|e| e.contains("body_end unknown")));
    }

    #[test]
    fn operator_names_are_checked() {
        let workflow = workflow_with(
            vec![
                extract("e", "login.response.body", "token"),
                Node {
                    id: "a".to_owned(),
                    kind: NodeKind::Assert {
                        config: crate::contract::AssertConfig {
                            source: "e.output".to_owned(),
                            path: String::new(),
                            operator: "matches".to_owned(),
                            expected: json!(1),
                        },
                    },
                },
            ],
            vec![],
        );
        let result = validate(&workflow, None);
        assert!(result.errors.iter().any(|e| e.contains("unknown operator")));
    }
}
