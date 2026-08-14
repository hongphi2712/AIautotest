use std::collections::BTreeMap;

use api_tester_domain::HttpFlow;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Deserialize)]
pub struct FlowFilters {
    pub method: Option<String>,
    pub host: Option<String>,
    pub q: Option<String>,
}

/// Compact view of a flow for the HTTP history table.
#[derive(Debug, Clone, Serialize)]
pub struct FlowSummary {
    pub id: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub method: String,
    pub host: String,
    pub ip: String,
    pub cookies: Vec<String>,
    pub path: String,
    pub full_url: String,
    pub status: u16,
    pub content_type: String,
    pub length: usize,
    pub has_params: bool,
}

impl From<&HttpFlow> for FlowSummary {
    fn from(flow: &HttpFlow) -> Self {
        let mut cookies: Vec<String> = flow
            .request_cookies
            .iter()
            .chain(flow.response_cookies.iter())
            .cloned()
            .collect();
        cookies.sort();
        cookies.dedup();
        Self {
            id: flow.id.clone(),
            timestamp: flow.timestamp,
            method: flow.method.as_str().to_owned(),
            host: flow.host.clone(),
            ip: flow.ip.clone(),
            cookies,
            path: flow.path.clone(),
            full_url: flow.full_url.clone(),
            status: flow.response_status,
            content_type: flow.content_type.clone(),
            length: flow.response_body.as_deref().map(str::len).unwrap_or(0),
            has_params: flow.path.contains('?') || flow.request_body.is_some(),
        }
    }
}

/// Full flow including bodies and headers, for the inspector.
#[derive(Debug, Clone, Serialize)]
pub struct FlowDetail {
    #[serde(flatten)]
    pub summary: FlowSummary,
    pub request_headers: BTreeMap<String, String>,
    pub request_body: Option<String>,
    pub response_headers: BTreeMap<String, String>,
    pub response_body: Option<String>,
    pub request_cookies: Vec<String>,
    pub response_cookies: Vec<String>,
    pub request_cookie_values: BTreeMap<String, String>,
    pub response_cookie_values: BTreeMap<String, String>,
}

impl From<&HttpFlow> for FlowDetail {
    fn from(flow: &HttpFlow) -> Self {
        Self {
            summary: FlowSummary::from(flow),
            request_headers: flow.request_headers.clone(),
            request_body: flow.request_body.clone(),
            response_headers: flow.response_headers.clone(),
            response_body: flow.response_body.clone(),
            request_cookies: flow.request_cookies.clone(),
            response_cookies: flow.response_cookies.clone(),
            request_cookie_values: flow.request_cookie_values.clone(),
            response_cookie_values: flow.response_cookie_values.clone(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct RepeaterRequest {
    pub method: String,
    pub url: String,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    #[serde(default)]
    pub body: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct RepeaterResponse {
    pub status: u16,
    pub length: usize,
    pub body: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProxyStatus {
    pub running: bool,
    pub host: String,
    pub port: u16,
    pub address: String,
    pub error: Option<String>,
}

/// State of the MITM CA certificate.
#[derive(Debug, Clone, Serialize)]
pub struct CertInfo {
    pub path: String,
    pub exists: bool,
    pub installed: bool,
}

/// A capture session for the dashboard sidebar / history grouping.
#[derive(Debug, Clone, Serialize)]
pub struct SessionSummary {
    pub id: String,
    pub name: String,
    pub target_host: String,
    pub start_time: chrono::DateTime<chrono::Utc>,
    pub end_time: Option<chrono::DateTime<chrono::Utc>>,
    pub flow_count: u64,
}

pub fn filter_flows(flows: Vec<HttpFlow>, filters: &FlowFilters) -> Vec<HttpFlow> {
    flows
        .into_iter()
        .filter(|flow| {
            let method_ok = filters
                .method
                .as_deref()
                .filter(|value| !value.is_empty())
                .map(|method| flow.method.as_str().eq_ignore_ascii_case(method))
                .unwrap_or(true);
            let host_ok = filters
                .host
                .as_deref()
                .filter(|value| !value.is_empty())
                .map(|host| {
                    flow.host
                        .to_ascii_lowercase()
                        .contains(&host.to_ascii_lowercase())
                })
                .unwrap_or(true);
            let query_ok = filters
                .q
                .as_deref()
                .filter(|value| !value.is_empty())
                .map(|query| {
                    let query = query.to_ascii_lowercase();
                    flow.host.to_ascii_lowercase().contains(&query)
                        || flow.full_url.to_ascii_lowercase().contains(&query)
                })
                .unwrap_or(true);
            method_ok && host_ok && query_ok
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{FlowDetail, FlowFilters, FlowSummary, filter_flows};
    use api_tester_domain::{HttpFlow, HttpMethod};

    fn make_flow(method: HttpMethod, host: &str, path: &str) -> HttpFlow {
        let mut flow = HttpFlow::new(method, host, path);
        flow.full_url = format!("https://{host}{path}");
        flow.response_status = 200;
        flow
    }

    #[test]
    fn summary_has_dashboard_fields() {
        let mut flow = make_flow(HttpMethod::Post, "api.example.com", "/api/login?x=1");
        flow.request_body = Some("body".to_owned());
        flow.response_body = Some("hello".to_owned());
        flow.request_cookies = vec!["session".to_owned()];
        flow.response_cookies = vec!["csrf".to_owned()];

        let summary = FlowSummary::from(&flow);
        assert_eq!(summary.method, "POST");
        assert!(summary.has_params);
        assert_eq!(summary.length, 5);
        assert_eq!(summary.cookies, vec!["csrf", "session"]);
    }

    #[test]
    fn detail_contains_bodies_and_headers() {
        let mut flow = make_flow(HttpMethod::Get, "api.example.com", "/api/x");
        flow.request_headers
            .insert("authorization".to_owned(), "Bearer tok".to_owned());
        flow.response_body = Some("{\"ok\":true}".to_owned());

        let detail = FlowDetail::from(&flow);
        assert_eq!(
            detail
                .request_headers
                .get("authorization")
                .map(String::as_str),
            Some("Bearer tok")
        );
        assert_eq!(detail.response_body.as_deref(), Some("{\"ok\":true}"));
        assert_eq!(detail.summary.host, "api.example.com");
    }

    #[test]
    fn filter_by_method_host_and_query() {
        let flows = vec![
            make_flow(HttpMethod::Get, "api.example.com", "/api/a"),
            make_flow(HttpMethod::Post, "api.example.com", "/api/b"),
            make_flow(HttpMethod::Get, "other.com", "/api/c"),
        ];

        let by_method = filter_flows(
            flows.clone(),
            &FlowFilters {
                method: Some("GET".into()),
                host: None,
                q: None,
            },
        );
        assert_eq!(by_method.len(), 2);

        let by_host = filter_flows(
            flows.clone(),
            &FlowFilters {
                method: None,
                host: Some("example".into()),
                q: None,
            },
        );
        assert_eq!(by_host.len(), 2);

        let by_query = filter_flows(
            flows.clone(),
            &FlowFilters {
                method: None,
                host: None,
                q: Some("api/c".into()),
            },
        );
        assert_eq!(by_query.len(), 1);
        assert_eq!(by_query[0].host, "other.com");
    }

    #[test]
    fn empty_filters_return_all() {
        let flows = vec![
            make_flow(HttpMethod::Get, "api.example.com", "/api/a"),
            make_flow(HttpMethod::Post, "other.com", "/api/b"),
        ];
        let result = filter_flows(
            flows.clone(),
            &FlowFilters {
                method: Some(String::new()),
                host: Some(String::new()),
                q: Some(String::new()),
            },
        );
        assert_eq!(
            result.len(),
            2,
            "empty filter values must not filter anything"
        );
    }
}
