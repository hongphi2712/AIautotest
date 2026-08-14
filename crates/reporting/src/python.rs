use std::collections::BTreeMap;

use api_tester_analysis::FlowSequencer;
use api_tester_domain::HttpFlow;
use serde_json::Value;
use url::Url;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayMode {
    Recording,
    Parameterized,
}

/// Generates replayable Python code from captured flows, mirroring the
/// Python reference generator (recording and parameterized modes).
pub struct PythonReplayGenerator {
    sequencer: FlowSequencer,
    mode: ReplayMode,
}

impl PythonReplayGenerator {
    pub fn new(mode: ReplayMode) -> Self {
        Self {
            sequencer: FlowSequencer,
            mode,
        }
    }

    pub fn generate(&self, flows: &[HttpFlow], graph: &BTreeMap<String, Vec<String>>) -> String {
        let sorted = self.sequencer.topological_sort(flows, graph).flows;
        let mut lines = vec![
            "\"\"\"Auto-generated flow code from API-AutoTester.\"\"\"".to_owned(),
            String::new(),
            "import requests".to_owned(),
            String::new(),
            format!("BASE_URL = \"{}\"", extract_base_url(flows)),
            "session = requests.Session()".to_owned(),
            String::new(),
        ];

        for (index, flow) in sorted.iter().enumerate() {
            lines.extend(flow_to_code(flow, index + 1, self.mode));
        }

        lines.join("\n")
    }
}

fn extract_base_url(flows: &[HttpFlow]) -> String {
    let Some(first) = flows.first() else {
        return String::new();
    };
    let Ok(url) = Url::parse(&first.full_url) else {
        return String::new();
    };
    let Some(host) = url.host_str() else {
        return String::new();
    };
    let authority = match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_owned(),
    };
    format!("{}://{authority}", url.scheme())
}

fn flow_to_code(flow: &HttpFlow, step: usize, mode: ReplayMode) -> Vec<String> {
    match mode {
        ReplayMode::Recording => flow_to_code_recording(flow, step),
        ReplayMode::Parameterized => flow_to_code_parameterized(flow, step),
    }
}

fn flow_to_code_recording(flow: &HttpFlow, step: usize) -> Vec<String> {
    let mut lines = vec![format!(
        "# Step {step}: {} {}",
        flow.method.as_str(),
        flow.path
    )];
    let method = flow.method.as_str().to_ascii_lowercase();
    let path = path_without_base(flow);
    let url = format!("f\"{{BASE_URL}}{path}\"");

    let mut args = Vec::new();
    if !flow.request_headers.is_empty() {
        let headers_repr = serde_json::to_string(&flow.request_headers).unwrap_or_default();
        args.push(format!("headers={headers_repr}"));
    }
    if let Some(body) = flow.request_body.as_deref() {
        if flow.has_json_body() {
            let parsed = serde_json::from_str::<Value>(body).unwrap_or(Value::Null);
            args.push(format!(
                "json={}",
                serde_json::to_string(&parsed).unwrap_or_default()
            ));
        } else {
            args.push(format!("data={body:?}"));
        }
    }

    let mut call = format!("resp{step} = session.{method}({url}");
    if !args.is_empty() {
        call.push_str(", ");
        call.push_str(&args.join(", "));
    }
    call.push(')');
    lines.push(call);
    lines.push(String::new());
    lines
}

fn flow_to_code_parameterized(flow: &HttpFlow, step: usize) -> Vec<String> {
    let mut lines = vec![format!(
        "# Step {step}: {} {}",
        flow.method.as_str(),
        flow.path
    )];
    let method = flow.method.as_str().to_ascii_lowercase();
    let func_name = format!("step_{step}_{method}");

    let mut call_args = Vec::new();
    if !flow.request_headers.is_empty() {
        let headers_repr = serde_json::to_string(&flow.request_headers).unwrap_or_default();
        call_args.push(format!("headers={headers_repr}"));
    }
    if let Some(body) = flow.request_body.as_deref() {
        if flow.has_json_body() {
            let parsed = serde_json::from_str::<Value>(body).unwrap_or(Value::Null);
            call_args.push(format!(
                "json={}",
                serde_json::to_string(&parsed).unwrap_or_default()
            ));
        }
    }

    let path = path_without_base(flow);
    lines.push(format!("def {func_name}():"));
    lines.push(format!(
        "    return session.{method}(f\"{{BASE_URL}}{path}\""
    ));
    if !call_args.is_empty() {
        lines.push(format!("        {}", call_args.join(",\n        ")));
    }
    lines.push("    )".to_owned());
    lines.push(String::new());
    lines
}

fn path_without_base(flow: &HttpFlow) -> String {
    let Ok(url) = Url::parse(&flow.full_url) else {
        return flow.path.clone();
    };
    let mut path = url.path().to_owned();
    if path.is_empty() {
        path = "/".to_owned();
    }
    if let Some(query) = url.query() {
        path.push('?');
        path.push_str(query);
    }
    path
}

#[cfg(test)]
mod tests {
    use super::{PythonReplayGenerator, ReplayMode};
    use api_tester_domain::{HttpFlow, HttpMethod};
    use std::collections::BTreeMap;

    fn make_login_flow() -> HttpFlow {
        let mut flow = HttpFlow::new(HttpMethod::Post, "api.example.com", "/api/login");
        flow.full_url = "https://api.example.com/api/login".to_owned();
        flow.request_headers
            .insert("Content-Type".to_owned(), "application/json".to_owned());
        flow.request_body = Some(r#"{"username":"admin","password":"pass"}"#.to_owned());
        flow.response_status = 200;
        flow
    }

    fn make_profile_flow() -> HttpFlow {
        let mut flow = HttpFlow::new(HttpMethod::Get, "api.example.com", "/api/profile");
        flow.full_url = "https://api.example.com/api/profile".to_owned();
        flow.request_headers
            .insert("Authorization".to_owned(), "Bearer token_abc123".to_owned());
        flow.response_status = 200;
        flow
    }

    #[test]
    fn recording_mode() {
        let generator = PythonReplayGenerator::new(ReplayMode::Recording);
        let code = generator.generate(&[make_login_flow(), make_profile_flow()], &BTreeMap::new());
        assert!(code.contains("import requests"));
        assert!(code.contains("BASE_URL"));
        assert!(code.contains("session.post"));
        assert!(code.contains("session.get"));
    }

    #[test]
    fn parameterized_mode() {
        let generator = PythonReplayGenerator::new(ReplayMode::Parameterized);
        let code = generator.generate(&[make_login_flow()], &BTreeMap::new());
        assert!(code.contains("def step_"));
        assert!(code.contains("return session."));
    }

    #[test]
    fn empty_flows() {
        let generator = PythonReplayGenerator::new(ReplayMode::Recording);
        let code = generator.generate(&[], &BTreeMap::new());
        assert!(code.contains("import requests"));
        assert!(code.contains("BASE_URL = \"\""));
    }
}
