use std::collections::BTreeMap;

use api_tester_analysis::FlowSequencer;
use api_tester_domain::HttpFlow;

/// Generates a Mermaid sequence diagram describing an API flow, mirroring
/// the Python reference generator.
pub struct MermaidGenerator {
    sequencer: FlowSequencer,
}

impl Default for MermaidGenerator {
    fn default() -> Self {
        Self::new()
    }
}

impl MermaidGenerator {
    pub fn new() -> Self {
        Self {
            sequencer: FlowSequencer,
        }
    }

    pub fn generate(&self, flows: &[HttpFlow], graph: &BTreeMap<String, Vec<String>>) -> String {
        let sorted = self.sequencer.topological_sort(flows, graph).flows;
        let mut lines = vec![
            "sequenceDiagram".to_owned(),
            "    participant Client".to_owned(),
            "    participant API".to_owned(),
            String::new(),
        ];

        for flow in &sorted {
            let body_summary = summarize_body(flow.request_body.as_deref());
            let display_path = flow.path.split('?').next().unwrap_or(&flow.path);
            lines.push(format!(
                "    Client->>API: {} {} {}",
                flow.method.as_str(),
                display_path,
                body_summary
            ));
            lines.push(format!("    API-->>Client: {}", flow.response_status));
            lines.push(String::new());
        }

        lines.join("\n")
    }
}

fn summarize_body(body: Option<&str>) -> String {
    let Some(body) = body else {
        return String::new();
    };
    if body.chars().count() > 40 {
        let prefix: String = body.chars().take(37).collect();
        return format!("{prefix}...");
    }
    body.replace('\n', " ")
}

#[cfg(test)]
mod tests {
    use super::MermaidGenerator;
    use api_tester_domain::{HttpFlow, HttpMethod};
    use std::collections::BTreeMap;

    fn make_flow(method: HttpMethod, path: &str) -> HttpFlow {
        let mut flow = HttpFlow::new(method, "api.example.com", path);
        flow.full_url = format!("https://api.example.com{path}");
        flow.response_status = 200;
        flow
    }

    #[test]
    fn sequence_diagram() {
        let generator = MermaidGenerator::new();
        let flows = vec![
            make_flow(HttpMethod::Post, "/api/login"),
            make_flow(HttpMethod::Get, "/api/profile"),
        ];
        let diagram = generator.generate(&flows, &BTreeMap::new());

        assert!(diagram.starts_with("sequenceDiagram"));
        assert!(diagram.contains("participant Client"));
        assert!(diagram.contains("participant API"));
        assert!(diagram.contains("Client->>API"));
        assert!(diagram.contains("API-->>Client"));
    }
}
