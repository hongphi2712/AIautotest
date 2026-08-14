use std::collections::BTreeMap;

use api_tester_domain::{ExtractedToken, FlowDependency, HttpFlow};

use crate::token_extractor::TokenExtractor;

/// Maps dependencies: flow A produces a token, flow B consumes it. Results
/// are sorted so output is deterministic.
pub struct DependencyMapper {
    extractor: TokenExtractor,
}

impl Default for DependencyMapper {
    fn default() -> Self {
        Self::new()
    }
}

impl DependencyMapper {
    pub fn new() -> Self {
        Self {
            extractor: TokenExtractor::new(),
        }
    }

    /// Builds a graph of `source_flow_id -> Vec<flow_id depending on it>`.
    pub fn build_graph(&self, flows: &[HttpFlow]) -> BTreeMap<String, Vec<String>> {
        let pool = self.build_token_pool(flows);
        let mut graph: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for flow in flows {
            for token in self.find_used_tokens(flow, &pool) {
                if token.source_flow_id == flow.fingerprint() {
                    continue;
                }
                graph
                    .entry(token.source_flow_id.clone())
                    .or_default()
                    .push(flow.fingerprint());
            }
        }
        for targets in graph.values_mut() {
            targets.sort();
            targets.dedup();
        }
        graph
    }

    /// Builds a detailed dependency list, sorted for determinism.
    pub fn build_dependencies(&self, flows: &[HttpFlow]) -> Vec<FlowDependency> {
        let pool = self.build_token_pool(flows);
        let mut dependencies = Vec::new();
        for flow in flows {
            for (token, location) in self.find_used_tokens_with_location(flow, &pool) {
                if token.source_flow_id == flow.fingerprint() {
                    continue;
                }
                dependencies.push(FlowDependency {
                    source_flow_id: token.source_flow_id.clone(),
                    target_flow_id: flow.fingerprint(),
                    token: token.clone(),
                    usage_location: location,
                });
            }
        }
        dependencies.sort_by(|left, right| {
            left.source_flow_id
                .cmp(&right.source_flow_id)
                .then(left.target_flow_id.cmp(&right.target_flow_id))
                .then(left.usage_location.cmp(&right.usage_location))
        });
        dependencies
    }

    fn build_token_pool(&self, flows: &[HttpFlow]) -> Vec<ExtractedToken> {
        let mut pool = Vec::new();
        for flow in flows {
            let mut tokens = self.extractor.extract_from_flow(flow);
            for token in &mut tokens {
                token.source_flow_id = flow.fingerprint();
            }
            pool.extend(tokens);
        }
        pool
    }

    fn find_used_tokens(&self, flow: &HttpFlow, pool: &[ExtractedToken]) -> Vec<ExtractedToken> {
        self.find_used_tokens_with_location(flow, pool)
            .into_iter()
            .map(|(token, _)| token)
            .collect()
    }

    fn find_used_tokens_with_location(
        &self,
        flow: &HttpFlow,
        pool: &[ExtractedToken],
    ) -> Vec<(ExtractedToken, String)> {
        let mut found = Vec::new();
        for (name, value) in &flow.request_headers {
            for token in pool {
                if !token.value.is_empty() && value.contains(&token.value) {
                    found.push((token.clone(), format!("header:{name}")));
                }
            }
        }
        if let Some(body) = flow.request_body.as_deref() {
            for token in pool {
                if !token.value.is_empty() && body.contains(&token.value) {
                    found.push((token.clone(), "body".to_owned()));
                }
            }
        }
        found
    }
}

#[cfg(test)]
mod tests {
    use super::DependencyMapper;
    use crate::flow_sequencer::FlowSequencer;
    use api_tester_domain::{HttpFlow, HttpMethod};
    use std::collections::BTreeMap;

    fn make_login_flow() -> HttpFlow {
        let mut flow = HttpFlow::new(HttpMethod::Post, "api.example.com", "/api/login");
        flow.full_url = "https://api.example.com/api/login".to_owned();
        flow.request_body = Some(r#"{"username":"admin","password":"pass"}"#.to_owned());
        flow.response_status = 200;
        flow.response_headers
            .insert("content-type".to_owned(), "application/json".to_owned());
        flow.response_body = Some(r#"{"access_token":"token_abc123"}"#.to_owned());
        flow.content_type = "application/json".to_owned();
        flow
    }

    fn make_profile_flow(token: &str) -> HttpFlow {
        let mut flow = HttpFlow::new(HttpMethod::Get, "api.example.com", "/api/profile");
        flow.full_url = "https://api.example.com/api/profile".to_owned();
        flow.request_headers
            .insert("Authorization".to_owned(), format!("Bearer {token}"));
        flow.response_status = 200;
        flow.response_headers
            .insert("content-type".to_owned(), "application/json".to_owned());
        flow.response_body = Some(r#"{"id":1,"name":"Test"}"#.to_owned());
        flow.content_type = "application/json".to_owned();
        flow
    }

    fn make_orders_flow(token: &str) -> HttpFlow {
        let mut flow = HttpFlow::new(HttpMethod::Get, "api.example.com", "/api/orders");
        flow.full_url = "https://api.example.com/api/orders".to_owned();
        flow.request_headers
            .insert("Authorization".to_owned(), format!("Bearer {token}"));
        flow.response_status = 200;
        flow
    }

    #[test]
    fn dependency_results_are_deterministic() {
        let flows = vec![
            make_login_flow(),
            make_profile_flow("token_abc123"),
            make_orders_flow("token_abc123"),
        ];
        let mapper = DependencyMapper::new();
        let first_graph = mapper.build_graph(&flows);
        let second_graph = mapper.build_graph(&flows);
        assert_eq!(first_graph, second_graph);

        let first_deps = mapper.build_dependencies(&flows);
        let second_deps = mapper.build_dependencies(&flows);
        assert_eq!(first_deps, second_deps);
        assert_eq!(first_deps.len(), 2);
    }

    #[test]
    fn simple_dependency() {
        let login = make_login_flow();
        let profile = make_profile_flow("token_abc123");
        let mapper = DependencyMapper::new();
        let graph = mapper.build_graph(&[login.clone(), profile.clone()]);

        assert!(graph.contains_key(&login.fingerprint()));
        assert!(graph[&login.fingerprint()].contains(&profile.fingerprint()));
    }

    #[test]
    fn no_dependency() {
        let login = make_login_flow();
        let profile = make_profile_flow("different_token");
        let mapper = DependencyMapper::new();
        let graph = mapper.build_graph(&[login, profile.clone()]);

        assert!(
            !graph
                .values()
                .flat_map(|targets| targets.iter())
                .any(|target| *target == profile.fingerprint())
        );
    }

    #[test]
    fn self_dependency_ignored() {
        let mut flow = make_login_flow();
        flow.request_headers
            .insert("Authorization".to_owned(), "Bearer token_abc123".to_owned());
        let mapper = DependencyMapper::new();
        let graph = mapper.build_graph(&[flow]);
        assert!(graph.is_empty());
    }

    #[test]
    fn build_dependencies() {
        let login = make_login_flow();
        let profile = make_profile_flow("token_abc123");
        let mapper = DependencyMapper::new();
        let deps = mapper.build_dependencies(&[login.clone(), profile.clone()]);

        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].source_flow_id, login.fingerprint());
        assert_eq!(deps[0].target_flow_id, profile.fingerprint());
    }

    #[test]
    fn topological_sort_simple() {
        let login = make_login_flow();
        let profile = make_profile_flow("token_abc123");
        let mapper = DependencyMapper::new();
        let graph = mapper.build_graph(&[profile.clone(), login.clone()]);

        let sequencer = FlowSequencer;
        let result = sequencer.topological_sort(&[profile.clone(), login.clone()], &graph);

        assert_eq!(result.flows[0].fingerprint(), login.fingerprint());
        assert_eq!(result.flows[1].fingerprint(), profile.fingerprint());
    }

    #[test]
    fn circular_dependency_handled() {
        let f1 = make_login_flow();
        let f2 = make_profile_flow("token_abc123");
        let graph: BTreeMap<String, Vec<String>> = BTreeMap::from([
            (f1.fingerprint(), vec![f2.fingerprint()]),
            (f2.fingerprint(), vec![f1.fingerprint()]),
        ]);
        let sequencer = FlowSequencer;
        let result = sequencer.topological_sort(&[f1, f2], &graph);
        assert_eq!(result.flows.len(), 2);
        assert_eq!(result.cycles_detected, 2);
    }
}
