use std::collections::BTreeMap;
use std::collections::BTreeSet;

use api_tester_domain::{FlowDependency, HttpFlow};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Deserialize)]
pub struct FlowFilters {
    pub method: Option<String>,
    pub host: Option<String>,
    pub q: Option<String>,
    pub session_id: Option<String>,
}

/// Compact view of a flow for the HTTP history table.
#[derive(Debug, Clone, Serialize)]
pub struct FlowSummary {
    pub id: String,
    pub session_id: String,
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
    pub security_signals: Vec<String>,
    pub is_suspicious: bool,
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

        let mut security_signals = Vec::new();
        let mut is_suspicious = false;
        if let Some(body) = &flow.response_body {
            let overfetching = api_tester_analysis::OverfetchingAnalyzer::analyze(body);
            let sec = api_tester_analysis::SecretScanner::analyze(body);

            security_signals.extend(overfetching.detected_signals);
            security_signals.extend(sec.summary_signals);
            security_signals.sort();
            security_signals.dedup();
            is_suspicious = !security_signals.is_empty();
        }

        Self {
            id: flow.id.clone(),
            session_id: flow.session_id.clone(),
            timestamp: flow.timestamp,
            method: flow.method.as_str().to_owned(),
            host: flow.host.clone(),
            ip: flow.ip.clone(),
            cookies,
            path: flow.path.clone(),
            full_url: flow.full_url.clone(),
            status: flow.response_status,
            content_type: flow.content_type.clone(),
            length: flow
                .response_body_len
                .max(flow.response_body.as_deref().map_or(0, str::len)),
            has_params: flow.path.contains('?') || flow.request_body.is_some(),
            security_signals,
            is_suspicious,
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
    pub headers: Vec<(String, String)>,
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

/// Request for the flow-code generator (`POST /api/analyze/flow`).
#[derive(Debug, Clone, Deserialize)]
pub struct FlowReportRequest {
    /// `mermaid` (default) or `python`.
    #[serde(default)]
    pub format: String,
    /// Python replay mode: `recording` (default) or `parameterized`.
    #[serde(default)]
    pub mode: Option<String>,
}

/// One dependency-ordered step of the flow (topological order).
#[derive(Debug, Clone, Serialize)]
pub struct FlowStep {
    pub fingerprint: String,
    pub method: String,
    pub path: String,
    pub status: u16,
    /// How many identical requests (same method + path without query) were
    /// collapsed into this step.
    pub count: usize,
}

/// Node in the Timeline Branch Graph.
#[derive(Debug, Clone, Serialize)]
pub struct FlowGraphNode {
    pub id: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub method: String,
    pub path: String,
    pub status: u16,
    pub duration_ms: u64,
    pub parent_ids: Vec<String>,
    pub children_ids: Vec<String>,
    pub token: Option<String>,
}

impl From<&api_tester_analysis::TimelineNode> for FlowGraphNode {
    fn from(node: &api_tester_analysis::TimelineNode) -> Self {
        Self {
            id: node.id.clone(),
            timestamp: node.timestamp,
            method: node.method.clone(),
            path: node.path.clone(),
            status: node.status,
            duration_ms: node.duration_ms,
            parent_ids: node.parent_ids.clone(),
            children_ids: node.children_ids.clone(),
            token: node.token.clone(),
        }
    }
}

/// The generated flow report returned to the Analyzer UI.
#[derive(Debug, Clone, Serialize)]
pub struct FlowReport {
    pub flow_count: usize,
    pub cycles: usize,
    pub format: String,
    pub output: String,
    pub steps: Vec<FlowStep>,
    pub graph_nodes: Vec<FlowGraphNode>,
    pub dependencies: Vec<FlowDependency>,
}

/// Annotation view merged into sitemap endpoint nodes. Stored keyed by
/// `{scheme}://{host}{path}` (query stripped); `None` fields mean "unset".
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SitemapAnnotationDto {
    #[serde(default)]
    pub comment: Option<String>,
    #[serde(default)]
    pub color: Option<String>,
}

/// A node of the Burp-style site map tree: either a path directory or an
/// endpoint leaf aggregating every captured flow sharing that path.
#[derive(Debug, Clone, Serialize)]
pub struct SitemapNode {
    /// Path segment name for directories, last segment for endpoints
    /// (or `"/"` for the site root).
    pub name: String,
    /// `"dir"` or `"endpoint"`.
    pub kind: String,
    /// Full path from the site root (`/api/v1`), used for scope rules and
    /// annotation keys.
    pub path: String,
    pub children: Vec<SitemapNode>,
    /// Endpoint-only aggregates below.
    pub methods: Vec<String>,
    pub statuses: Vec<u16>,
    pub count: usize,
    pub content_types: Vec<String>,
    pub last_seen: Option<chrono::DateTime<chrono::Utc>>,
    /// Newest flow id for this path — the UI fetches it on node click.
    pub sample_flow_id: Option<String>,
    pub has_params: bool,
    pub annotation: Option<SitemapAnnotationDto>,
}

/// One site (`scheme://host`) in the tree.
#[derive(Debug, Clone, Serialize)]
pub struct SitemapSite {
    pub scheme: String,
    pub host: String,
    pub children: Vec<SitemapNode>,
}

/// Response of `GET /api/sitemap`.
#[derive(Debug, Clone, Serialize)]
pub struct SitemapTree {
    pub sites: Vec<SitemapSite>,
}

/// Flat per-host endpoint lines derived from the tree, used for AI context.
#[derive(Debug, Clone, Serialize)]
pub struct SitemapFlatHost {
    pub host: String,
    pub endpoints: Vec<String>,
}

/// Accumulator for one endpoint leaf while building the tree.
#[derive(Default)]
struct EndpointAcc {
    methods: BTreeSet<String>,
    statuses: BTreeSet<u16>,
    content_types: BTreeSet<String>,
    count: usize,
    last_seen: Option<chrono::DateTime<chrono::Utc>>,
    sample_flow_id: Option<String>,
    has_params: bool,
}

/// Accumulator for one directory level: sub-directories plus endpoint leaves,
/// both keyed by segment name in a `BTreeMap` to keep children sorted.
#[derive(Default)]
struct DirAcc {
    dirs: BTreeMap<String, DirAcc>,
    endpoints: BTreeMap<String, EndpointAcc>,
}

/// Derives the URL scheme from a flow: prefix of `full_url` before `://`,
/// defaulting to `https`.
fn flow_scheme(flow: &HttpFlow) -> String {
    flow.full_url
        .split_once("://")
        .map(|(scheme, _)| scheme.to_owned())
        .unwrap_or_else(|| "https".to_owned())
}

/// Short content type (parameters like `; charset=utf-8` stripped, lowercased).
fn short_content_type(content_type: &str) -> String {
    content_type
        .split(';')
        .next()
        .unwrap_or(content_type)
        .trim()
        .to_ascii_lowercase()
}

/// Annotation key for an endpoint: `{scheme}://{host}{path}` without query.
pub fn sitemap_annotation_key(scheme: &str, host: &str, path: &str) -> String {
    format!("{scheme}://{host}{path}")
}

/// Builds the Burp-style hierarchical site map: site → path directories →
/// endpoint leaves. Flows with the same path (query string stripped) collapse
/// into one endpoint node aggregating methods, statuses, content types, count
/// and the newest flow id.
pub fn build_sitemap_tree(
    flows: &[HttpFlow],
    annotations: &std::collections::HashMap<String, SitemapAnnotationDto>,
) -> SitemapTree {
    let mut sites: BTreeMap<(String, String), DirAcc> = BTreeMap::new();
    for flow in flows {
        let scheme = flow_scheme(flow);
        let host = flow.host.clone();
        let path = flow.path.split('?').next().unwrap_or(&flow.path).to_owned();
        let segments: Vec<&str> = path
            .split('/')
            .filter(|segment| !segment.is_empty())
            .collect();
        let root = sites.entry((scheme, host)).or_default();
        let acc = match segments.split_last() {
            Some((leaf_name, dir_segments)) => {
                let mut dir = root;
                for segment in dir_segments {
                    dir = dir.dirs.entry((*segment).to_owned()).or_default();
                }
                dir.endpoints.entry((*leaf_name).to_owned()).or_default()
            }
            None => root.endpoints.entry("/".to_owned()).or_default(),
        };
        acc.count += 1;
        acc.methods.insert(flow.method.as_str().to_owned());
        acc.statuses.insert(flow.response_status);
        let content_type = short_content_type(&flow.content_type);
        if !content_type.is_empty() {
            acc.content_types.insert(content_type);
        }
        if acc.last_seen.is_none_or(|seen| flow.timestamp > seen) {
            acc.last_seen = Some(flow.timestamp);
            acc.sample_flow_id = Some(flow.id.clone());
        }
        if flow.path.contains('?') {
            acc.has_params = true;
        }
    }

    let sites = sites
        .into_iter()
        .map(|((scheme, host), root)| SitemapSite {
            scheme: scheme.clone(),
            host: host.clone(),
            children: build_dir_children(&root, String::new(), &scheme, &host, annotations),
        })
        .collect();
    SitemapTree { sites }
}

fn build_dir_children(
    dir: &DirAcc,
    prefix: String,
    scheme: &str,
    host: &str,
    annotations: &std::collections::HashMap<String, SitemapAnnotationDto>,
) -> Vec<SitemapNode> {
    let mut children: Vec<SitemapNode> = Vec::new();
    for (name, sub) in &dir.dirs {
        let path = format!("{prefix}/{name}");
        children.push(SitemapNode {
            name: name.clone(),
            kind: "dir".to_owned(),
            path,
            children: build_dir_children(
                sub,
                format!("{prefix}/{name}"),
                scheme,
                host,
                annotations,
            ),
            methods: Vec::new(),
            statuses: Vec::new(),
            count: 0,
            content_types: Vec::new(),
            last_seen: None,
            sample_flow_id: None,
            has_params: false,
            annotation: None,
        });
    }
    for (name, acc) in &dir.endpoints {
        let path = if name == "/" {
            "/".to_owned()
        } else {
            format!("{prefix}/{name}")
        };
        let key = sitemap_annotation_key(scheme, host, &path);
        children.push(SitemapNode {
            name: name.clone(),
            kind: "endpoint".to_owned(),
            path,
            children: Vec::new(),
            methods: acc.methods.iter().cloned().collect(),
            statuses: acc.statuses.iter().copied().collect(),
            count: acc.count,
            content_types: acc.content_types.iter().cloned().collect(),
            last_seen: acc.last_seen,
            sample_flow_id: acc.sample_flow_id.clone(),
            has_params: acc.has_params,
            annotation: annotations.get(&key).cloned(),
        });
    }
    children
}

/// Flattens the tree into per-host endpoint lines (`{path} ({count}, GET/POST)`)
/// for compact AI prompt context.
pub fn flatten_sitemap_tree(tree: &SitemapTree) -> Vec<SitemapFlatHost> {
    let mut hosts: BTreeMap<String, Vec<String>> = BTreeMap::new();
    fn walk(nodes: &[SitemapNode], lines: &mut Vec<String>) {
        for node in nodes {
            if node.kind == "endpoint" {
                let methods = node.methods.join("/");
                lines.push(format!("{} ({}, {})", node.path, node.count, methods));
            }
            walk(&node.children, lines);
        }
    }
    for site in &tree.sites {
        let lines = hosts.entry(site.host.clone()).or_default();
        walk(&site.children, lines);
    }
    hosts
        .into_iter()
        .map(|(host, endpoints)| SitemapFlatHost { host, endpoints })
        .collect()
}

pub fn filter_flows(flows: Vec<HttpFlow>, filters: &FlowFilters) -> Vec<HttpFlow> {
    let flows = if let Some(ref sid) = filters.session_id {
        flows
            .into_iter()
            .filter(|f| f.session_id == *sid)
            .collect::<Vec<_>>()
    } else {
        flows
    };
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
                session_id: None,
            },
        );
        assert_eq!(by_method.len(), 2);

        let by_host = filter_flows(
            flows.clone(),
            &FlowFilters {
                method: None,
                host: Some("example".into()),
                q: None,
                session_id: None,
            },
        );
        assert_eq!(by_host.len(), 2);

        let by_query = filter_flows(
            flows.clone(),
            &FlowFilters {
                method: None,
                host: None,
                q: Some("api/c".into()),
                session_id: None,
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
                session_id: None,
            },
        );
        assert_eq!(
            result.len(),
            2,
            "empty filter values must not filter anything"
        );
    }

    use super::{
        SitemapAnnotationDto, build_sitemap_tree, flatten_sitemap_tree, sitemap_annotation_key,
    };
    use std::collections::HashMap;

    #[test]
    fn tree_groups_by_host_and_strips_query_strings() {
        let mut login = make_flow(HttpMethod::Post, "api.example.com", "/api/login");
        login.full_url = "https://api.example.com/api/login?x=1".to_owned();
        let mut users1 = make_flow(HttpMethod::Get, "api.example.com", "/api/users?id=1");
        users1.full_url = "https://api.example.com/api/users?id=1".to_owned();
        let mut users2 = make_flow(HttpMethod::Delete, "api.example.com", "/api/users?id=2");
        users2.full_url = "https://api.example.com/api/users?id=2".to_owned();
        let mut other = make_flow(HttpMethod::Get, "static.example.com", "/index.html");
        other.full_url = "https://static.example.com/index.html".to_owned();

        let tree = build_sitemap_tree(&[login, users1, users2, other], &HashMap::new());
        assert_eq!(tree.sites.len(), 2);

        let api = tree
            .sites
            .iter()
            .find(|s| s.host == "api.example.com")
            .unwrap();
        let api_dir = api.children.iter().find(|n| n.name == "api").unwrap();
        assert_eq!(api_dir.children.len(), 2);

        let users = api_dir.children.iter().find(|n| n.name == "users").unwrap();
        assert_eq!(users.kind, "endpoint");
        assert_eq!(users.count, 2);
        assert_eq!(users.methods, vec!["DELETE", "GET"]);
        assert!(users.has_params);

        let login_node = api_dir.children.iter().find(|n| n.name == "login").unwrap();
        assert_eq!(login_node.methods, vec!["POST"]);
        assert!(!login_node.has_params);
    }

    fn tree_flow(
        id: &str,
        method: HttpMethod,
        host: &str,
        path: &str,
        status: u16,
        content_type: &str,
    ) -> HttpFlow {
        let mut flow = HttpFlow::new(method, host, path);
        flow.id = id.to_owned();
        flow.full_url = format!("https://{host}{}", flow.path.split('?').next().unwrap());
        flow.response_status = status;
        flow.content_type = content_type.to_owned();
        flow
    }

    fn find_child<'a>(nodes: &'a [super::SitemapNode], name: &str) -> &'a super::SitemapNode {
        nodes.iter().find(|n| n.name == name).unwrap()
    }

    #[test]
    fn tree_nests_directories_and_aggregates_endpoints() {
        let flows = vec![
            tree_flow(
                "1",
                HttpMethod::Get,
                "api.example.com",
                "/api/v1/users",
                200,
                "application/json; charset=utf-8",
            ),
            tree_flow(
                "2",
                HttpMethod::Post,
                "api.example.com",
                "/api/v1/users",
                201,
                "application/json",
            ),
            tree_flow(
                "3",
                HttpMethod::Get,
                "api.example.com",
                "/api/v1/orders/42",
                200,
                "application/json",
            ),
            tree_flow(
                "4",
                HttpMethod::Get,
                "api.example.com",
                "/",
                200,
                "text/html",
            ),
        ];

        let tree = build_sitemap_tree(&flows, &HashMap::new());
        assert_eq!(tree.sites.len(), 1);
        let site = &tree.sites[0];
        assert_eq!(site.host, "api.example.com");
        assert_eq!(site.scheme, "https");

        let api_dir = find_child(&site.children, "api");
        assert_eq!(api_dir.kind, "dir");
        assert_eq!(api_dir.path, "/api");
        let v1_dir = find_child(&api_dir.children, "v1");
        assert_eq!(v1_dir.path, "/api/v1");

        let users = find_child(&v1_dir.children, "users");
        assert_eq!(users.kind, "endpoint");
        assert_eq!(users.path, "/api/v1/users");
        assert_eq!(users.methods, vec!["GET", "POST"]);
        assert_eq!(users.statuses, vec![200, 201]);
        assert_eq!(users.count, 2);
        assert_eq!(users.content_types, vec!["application/json"]);
        // sample = newest flow, both share the default timestamp so the last
        // writer wins deterministically per insertion order.
        assert!(users.sample_flow_id.is_some());

        let orders_dir = find_child(&v1_dir.children, "orders");
        let order = find_child(&orders_dir.children, "42");
        assert_eq!(order.kind, "endpoint");
        assert_eq!(order.path, "/api/v1/orders/42");

        let root = find_child(&site.children, "/");
        assert_eq!(root.kind, "endpoint");
        assert_eq!(root.path, "/");
    }

    #[test]
    fn tree_merges_annotations_and_marks_params() {
        let mut a = tree_flow(
            "1",
            HttpMethod::Get,
            "api.example.com",
            "/api/users?id=1",
            200,
            "application/json",
        );
        a.timestamp = chrono::Utc::now();
        let mut b = tree_flow(
            "2",
            HttpMethod::Get,
            "api.example.com",
            "/api/users",
            200,
            "application/json",
        );
        b.timestamp = a.timestamp + chrono::Duration::seconds(5);

        let mut annotations = HashMap::new();
        annotations.insert(
            sitemap_annotation_key("https", "api.example.com", "/api/users"),
            SitemapAnnotationDto {
                comment: Some("vulnerable".to_owned()),
                color: Some("red".to_owned()),
            },
        );

        let tree = build_sitemap_tree(&[a, b], &annotations);
        let api_dir = find_child(&tree.sites[0].children, "api");
        let users = find_child(&api_dir.children, "users");
        assert!(users.has_params);
        assert_eq!(users.sample_flow_id.as_deref(), Some("2"));
        let annotation = users.annotation.as_ref().unwrap();
        assert_eq!(annotation.comment.as_deref(), Some("vulnerable"));
        assert_eq!(annotation.color.as_deref(), Some("red"));
    }

    #[test]
    fn tree_separates_scheme_and_flatten_roundtrips() {
        let https = tree_flow(
            "1",
            HttpMethod::Get,
            "api.example.com",
            "/a",
            200,
            "text/html",
        );
        let mut http = tree_flow(
            "2",
            HttpMethod::Get,
            "api.example.com",
            "/b",
            200,
            "text/html",
        );
        http.full_url = "http://api.example.com/b".to_owned();

        let tree = build_sitemap_tree(&[https, http], &HashMap::new());
        assert_eq!(tree.sites.len(), 2);

        let flat = flatten_sitemap_tree(&tree);
        assert_eq!(flat.len(), 1);
        assert_eq!(flat[0].host, "api.example.com");
        assert!(flat[0].endpoints.contains(&"/a (1, GET)".to_owned()));
        assert!(flat[0].endpoints.contains(&"/b (1, GET)".to_owned()));
    }
}
