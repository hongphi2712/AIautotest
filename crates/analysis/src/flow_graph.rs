use std::collections::BTreeSet;

use api_tester_domain::{ExtractedToken, HttpFlow};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::token_extractor::TokenExtractor;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TimelineNode {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub method: String,
    pub path: String,
    pub status: u16,
    pub duration_ms: u64,
    pub parent_ids: Vec<String>,
    pub children_ids: Vec<String>,
    pub token: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct TimelineGraph {
    pub nodes: Vec<TimelineNode>,
}

pub struct FlowGraphBuilder {
    extractor: TokenExtractor,
}

impl Default for FlowGraphBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl FlowGraphBuilder {
    pub fn new() -> Self {
        Self {
            extractor: TokenExtractor::new(),
        }
    }

    pub fn build_timeline_graph(&self, raw_flows: &[HttpFlow]) -> TimelineGraph {
        let mut flows = raw_flows.to_vec();
        flows.sort_by_key(|flow| flow.timestamp);

        let mut nodes: Vec<TimelineNode> = Vec::with_capacity(flows.len());
        let mut token_pool: Vec<(ExtractedToken, String)> = Vec::new();
        let mut prev_node_id: Option<String> = None;

        for flow in &flows {
            let mut produced = self.extractor.extract_from_flow(flow);
            for token in &mut produced {
                token.source_flow_id = flow.id.clone();
                token_pool.push((token.clone(), flow.id.clone()));
            }

            let mut parent_ids = Vec::new();
            let mut used_token_desc = None;

            for (name, value) in &flow.request_headers {
                for (token, src_id) in &token_pool {
                    if src_id != &flow.id && !token.value.is_empty() && value.contains(&token.value) {
                        if !parent_ids.contains(src_id) {
                            parent_ids.push(src_id.clone());
                        }
                        if used_token_desc.is_none() {
                            used_token_desc = Some(format!("{}: {}", token.token_type.as_str(), name));
                        }
                    }
                }
            }

            if let Some(body) = flow.request_body.as_deref() {
                for (token, src_id) in &token_pool {
                    if src_id != &flow.id && !token.value.is_empty() && body.contains(&token.value) {
                        if !parent_ids.contains(src_id) {
                            parent_ids.push(src_id.clone());
                        }
                        if used_token_desc.is_none() {
                            used_token_desc = Some(format!("{}: body", token.token_type.as_str()));
                        }
                    }
                }
            }

            if parent_ids.is_empty() {
                if let Some(ref prev_id) = prev_node_id {
                    parent_ids.push(prev_id.clone());
                }
            }

            let path_clean = flow.path.split('?').next().unwrap_or(&flow.path).to_string();

            nodes.push(TimelineNode {
                id: flow.id.clone(),
                timestamp: flow.timestamp,
                method: flow.method.as_str().to_string(),
                path: path_clean,
                status: flow.response_status,
                duration_ms: flow.duration_ms,
                parent_ids,
                children_ids: Vec::new(),
                token: used_token_desc,
            });

            prev_node_id = Some(flow.id.clone());
        }

        // Backfill children_ids in nodes
        let mut parent_to_children: std::collections::HashMap<String, BTreeSet<String>> =
            std::collections::HashMap::new();
        for node in &nodes {
            for parent_id in &node.parent_ids {
                parent_to_children
                    .entry(parent_id.clone())
                    .or_default()
                    .insert(node.id.clone());
            }
        }

        for node in &mut nodes {
            if let Some(children) = parent_to_children.get(&node.id) {
                node.children_ids = children.iter().cloned().collect();
            }
        }

        TimelineGraph { nodes }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use api_tester_domain::HttpMethod;

    #[test]
    fn test_empty_graph() {
        let builder = FlowGraphBuilder::new();
        let graph = builder.build_timeline_graph(&[]);
        assert!(graph.nodes.is_empty());
    }

    #[test]
    fn test_timeline_chain_and_children() {
        let mut f1 = HttpFlow::new(HttpMethod::Post, "example.com", "/login");
        f1.response_status = 200;
        f1.response_body = Some(r#"{"access_token":"token_123"}"#.to_owned());
        f1.content_type = "application/json".to_owned();

        let mut f2 = HttpFlow::new(HttpMethod::Get, "example.com", "/profile");
        f2.request_headers.insert("Authorization".to_owned(), "Bearer token_123".to_owned());
        f2.response_status = 200;

        let mut f3 = HttpFlow::new(HttpMethod::Get, "example.com", "/profile");
        f3.response_status = 403;

        let builder = FlowGraphBuilder::new();
        let graph = builder.build_timeline_graph(&[f1.clone(), f2.clone(), f3.clone()]);

        assert_eq!(graph.nodes.len(), 3);
        assert_eq!(graph.nodes[0].id, f1.id);
        assert_eq!(graph.nodes[1].id, f2.id);
        assert_eq!(graph.nodes[2].id, f3.id);

        assert_eq!(graph.nodes[1].parent_ids, vec![f1.id.clone()]);
        assert!(graph.nodes[0].children_ids.contains(&f2.id));
    }
}
