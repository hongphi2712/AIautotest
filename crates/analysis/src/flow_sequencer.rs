use std::collections::{BTreeMap, HashSet, VecDeque};

use api_tester_domain::HttpFlow;

/// Result of a topological sort with the number of flows left unsorted by a
/// cycle (they are appended in input order so nothing is lost).
pub struct TopoResult {
    pub flows: Vec<HttpFlow>,
    pub cycles_detected: usize,
}

/// Sorts flows by dependency order (Kahn's algorithm). Cyclic flows are
/// appended in their original order instead of crashing, mirroring the
/// Python reference.
pub struct FlowSequencer;

impl FlowSequencer {
    pub fn topological_sort(
        &self,
        flows: &[HttpFlow],
        graph: &BTreeMap<String, Vec<String>>,
    ) -> TopoResult {
        let flow_by_id: BTreeMap<String, &HttpFlow> = flows
            .iter()
            .map(|flow| (flow.fingerprint(), flow))
            .collect();

        let mut in_degree: BTreeMap<String, usize> =
            flows.iter().map(|flow| (flow.fingerprint(), 0)).collect();
        let mut adj: BTreeMap<String, Vec<String>> = BTreeMap::new();

        for (source, targets) in graph {
            if !flow_by_id.contains_key(source) {
                continue;
            }
            for target in targets {
                if !flow_by_id.contains_key(target) {
                    continue;
                }
                if target == source {
                    continue;
                }
                adj.entry(source.clone()).or_default().push(target.clone());
                *in_degree.entry(target.clone()).or_default() += 1;
            }
        }

        let mut queue: VecDeque<String> = in_degree
            .iter()
            .filter(|(_, degree)| **degree == 0)
            .map(|(id, _)| id.clone())
            .collect();
        queue.make_contiguous().sort();

        let mut result = Vec::new();
        let mut visited = 0;
        while let Some(id) = queue.pop_front() {
            if let Some(flow) = flow_by_id.get(&id) {
                result.push((*flow).clone());
            }
            visited += 1;
            if let Some(neighbors) = adj.get(&id) {
                let mut neighbors = neighbors.clone();
                neighbors.sort();
                for neighbor in neighbors {
                    if let Some(degree) = in_degree.get_mut(&neighbor) {
                        *degree = degree.saturating_sub(1);
                        if *degree == 0 {
                            queue.push_back(neighbor);
                        }
                    }
                }
                queue.make_contiguous().sort();
            }
        }

        let cycles_detected = flows.len().saturating_sub(visited);
        if cycles_detected > 0 {
            let included: HashSet<String> = result.iter().map(|flow| flow.fingerprint()).collect();
            for flow in flows {
                if !included.contains(&flow.fingerprint()) {
                    result.push(flow.clone());
                }
            }
        }

        TopoResult {
            flows: result,
            cycles_detected,
        }
    }
}
