use std::collections::BTreeMap;
use std::sync::Arc;

use api_tester_analysis::{DependencyMapper, FlowSequencer};
use api_tester_auth::AuthManager;
use api_tester_domain::HttpFlow;
use api_tester_ports::HttpRequest;

use crate::error::ScanError;
use crate::request_executor::RequestExecutor;

/// Outcome of replaying one flow.
#[derive(Debug, Clone)]
pub struct ReplayOutcome {
    pub flow_id: String,
    pub path: String,
    pub status: u16,
    pub ok: bool,
}

/// Replays captured flows in dependency order (topological sort), optionally
/// injecting fresh tokens from the auth manager.
pub struct Replayer {
    executor: Arc<RequestExecutor>,
    auth: Option<Arc<AuthManager>>,
}

impl Replayer {
    pub fn new(executor: Arc<RequestExecutor>, auth: Option<Arc<AuthManager>>) -> Self {
        Self { executor, auth }
    }

    pub async fn replay(&self, flows: Vec<HttpFlow>) -> Result<Vec<ReplayOutcome>, ScanError> {
        let graph = DependencyMapper::new().build_graph(&flows);
        let ordered = FlowSequencer.topological_sort(&flows, &graph).flows;

        let tokens = if let Some(auth) = &self.auth {
            auth.ensure_auth()
                .await
                .map_err(|error| ScanError::Auth(error.to_string()))?
        } else {
            BTreeMap::new()
        };

        let mut outcomes = Vec::new();
        for flow in &ordered {
            let request = flow_request(flow, &tokens);
            match self.executor.execute(request).await {
                Ok(response) => outcomes.push(ReplayOutcome {
                    flow_id: flow.id.clone(),
                    path: flow.path.clone(),
                    status: response.status,
                    ok: true,
                }),
                Err(_) => outcomes.push(ReplayOutcome {
                    flow_id: flow.id.clone(),
                    path: flow.path.clone(),
                    status: 0,
                    ok: false,
                }),
            }
        }
        Ok(outcomes)
    }
}

fn flow_request(flow: &HttpFlow, tokens: &BTreeMap<String, String>) -> HttpRequest {
    let mut request = HttpRequest {
        method: flow.method.as_str().to_owned(),
        url: flow.full_url.clone(),
        headers: flow
            .request_headers
            .iter()
            .map(|(name, value)| (name.clone(), value.clone()))
            .collect(),
        body: flow
            .request_body
            .as_deref()
            .map(|body| body.as_bytes().to_vec()),
    };
    let token = tokens
        .get("access_token")
        .or_else(|| tokens.values().next());
    if let Some(token) = token {
        if request
            .headers
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case("authorization"))
        {
            request
                .headers
                .retain(|(name, _)| !name.eq_ignore_ascii_case("authorization"));
            request
                .headers
                .push(("Authorization".to_owned(), format!("Bearer {token}")));
        }
    }
    request
}
