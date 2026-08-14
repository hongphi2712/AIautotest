use api_tester_domain::{AnalyzedParam, HttpFlow, InjectionLocation, ParamType};
use regex::Regex;
use serde_json::Value;
use url::Url;

const INTERESTING_HEADERS: &[&str] = &["authorization", "x-api-key", "x-auth-token", "cookie"];

/// Parses an absolute URL, falling back to a synthetic base for relative
/// targets (mirrors Python's lenient `urlparse`).
fn parse_flow_url(full_url: &str) -> Option<Url> {
    Url::parse(full_url).ok().or_else(|| {
        let base = Url::parse("http://invalid.local").ok()?;
        Url::options().base_url(Some(&base)).parse(full_url).ok()
    })
}

/// Classifies and extracts parameters from query, JSON body, headers and
/// path, mirroring the Python reference analyzer.
pub struct ParamAnalyzer {
    uuid: Regex,
    email: Regex,
    jwt: Regex,
    dates: Vec<Regex>,
}

impl Default for ParamAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl ParamAnalyzer {
    pub fn new() -> Self {
        Self {
            uuid: Regex::new(r"(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
                .expect("uuid pattern must be valid"),
            email: Regex::new(r"^[^@]+@[^@]+\.[^@]+$").expect("email pattern must be valid"),
            jwt: Regex::new(r"^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$")
                .expect("jwt pattern must be valid"),
            dates: vec![
                Regex::new(r"^\d{4}-\d{2}-\d{2}$").expect("date pattern must be valid"),
                Regex::new(r"^\d{4}/\d{2}/\d{2}$").expect("date pattern must be valid"),
                Regex::new(r"^\d{2}-\d{2}-\d{4}$").expect("date pattern must be valid"),
            ],
        }
    }

    pub fn analyze_flow(&self, flow: &HttpFlow) -> Vec<AnalyzedParam> {
        let mut params = Vec::new();
        params.extend(self.analyze_query_params(flow));
        params.extend(self.analyze_json_body(flow));
        params.extend(self.analyze_headers(flow));
        params.extend(self.analyze_path_params(flow));
        params
    }

    pub fn classify(&self, value: &Value) -> ParamType {
        match value {
            Value::Null => ParamType::Unknown,
            Value::Bool(_) => ParamType::Boolean,
            Value::Number(number) => {
                if let Some(int) = number.as_i64() {
                    if int > 1_000_000 {
                        ParamType::Id
                    } else {
                        ParamType::Int
                    }
                } else if let Some(int) = number.as_u64() {
                    if int > 1_000_000 {
                        ParamType::Id
                    } else {
                        ParamType::Int
                    }
                } else {
                    ParamType::Float
                }
            }
            Value::String(text) => self.classify_string(text),
            _ => ParamType::Unknown,
        }
    }

    fn analyze_query_params(&self, flow: &HttpFlow) -> Vec<AnalyzedParam> {
        let Some(url) = parse_flow_url(&flow.full_url) else {
            return Vec::new();
        };
        let mut params = Vec::new();
        for (key, value) in url.query_pairs() {
            let value = value.into_owned();
            params.push(AnalyzedParam {
                name: key.into_owned(),
                param_type: self.classify(&Value::String(value.clone())),
                location: InjectionLocation::Query,
                sample_value: Some(Value::String(value)),
                enum_values: Vec::new(),
            });
        }
        params
    }

    fn analyze_json_body(&self, flow: &HttpFlow) -> Vec<AnalyzedParam> {
        let Some(body) = flow.json_body() else {
            return Vec::new();
        };
        if !body.is_object() {
            return Vec::new();
        }
        let mut params = Vec::new();
        self.walk_json(&body, InjectionLocation::BodyJson, "", &mut params);
        params
    }

    fn analyze_headers(&self, flow: &HttpFlow) -> Vec<AnalyzedParam> {
        let mut params = Vec::new();
        for (name, value) in &flow.request_headers {
            let lower = name.to_ascii_lowercase();
            if INTERESTING_HEADERS.contains(&lower.as_str()) {
                params.push(AnalyzedParam {
                    name: name.clone(),
                    param_type: self.classify(&Value::String(value.clone())),
                    location: InjectionLocation::Header,
                    sample_value: Some(Value::String(value.clone())),
                    enum_values: Vec::new(),
                });
            }
        }
        params
    }

    fn analyze_path_params(&self, flow: &HttpFlow) -> Vec<AnalyzedParam> {
        let Some(url) = parse_flow_url(&flow.full_url) else {
            return Vec::new();
        };
        let mut params = Vec::new();
        for segment in url.path().split('/') {
            if segment.is_empty() {
                continue;
            }
            if segment.chars().all(|ch| ch.is_ascii_digit()) {
                params.push(AnalyzedParam {
                    name: "path_param".to_owned(),
                    param_type: self.classify(&Value::String(segment.to_owned())),
                    location: InjectionLocation::Path,
                    sample_value: Some(Value::String(segment.to_owned())),
                    enum_values: Vec::new(),
                });
            }
        }
        params
    }

    fn walk_json(
        &self,
        obj: &Value,
        location: InjectionLocation,
        prefix: &str,
        out: &mut Vec<AnalyzedParam>,
    ) {
        match obj {
            Value::Object(map) => {
                for (key, value) in map {
                    let path = if prefix.is_empty() {
                        key.clone()
                    } else {
                        format!("{prefix}.{key}")
                    };
                    if value.is_object() || value.is_array() {
                        self.walk_json(value, location.clone(), &path, out);
                    } else {
                        out.push(AnalyzedParam {
                            name: path,
                            param_type: self.classify(value),
                            location: location.clone(),
                            sample_value: Some(value.clone()),
                            enum_values: Vec::new(),
                        });
                    }
                }
            }
            Value::Array(items) => {
                for (index, item) in items.iter().enumerate() {
                    self.walk_json(item, location.clone(), &format!("{prefix}[{index}]"), out);
                }
            }
            _ => {}
        }
    }

    fn classify_string(&self, value: &str) -> ParamType {
        if self.uuid.is_match(value) {
            return ParamType::Uuid;
        }
        if self.jwt.is_match(value) {
            return ParamType::Token;
        }
        if self.email.is_match(value) {
            return ParamType::Email;
        }
        if !value.is_empty() && value.chars().all(|ch| ch.is_ascii_digit()) && value.len() <= 10 {
            return ParamType::Id;
        }
        if self.dates.iter().any(|re| re.is_match(value)) {
            return ParamType::Date;
        }
        ParamType::String
    }
}

#[cfg(test)]
mod tests {
    use super::ParamAnalyzer;
    use api_tester_domain::{HttpFlow, HttpMethod, InjectionLocation, ParamType};
    use serde_json::Value;

    fn make_flow(
        method: HttpMethod,
        path: &str,
        full_url: &str,
        request_headers: Vec<(&str, &str)>,
        request_body: Option<&str>,
    ) -> HttpFlow {
        let mut flow = HttpFlow::new(method, "api.example.com", path);
        flow.full_url = full_url.to_owned();
        flow.request_headers = request_headers
            .into_iter()
            .map(|(name, value)| (name.to_owned(), value.to_owned()))
            .collect();
        flow.request_body = request_body.map(str::to_owned);
        flow
    }

    #[test]
    fn classify_string() {
        let analyzer = ParamAnalyzer::new();
        assert_eq!(
            analyzer.classify(&Value::String("hello".to_owned())),
            ParamType::String
        );
    }

    #[test]
    fn classify_int() {
        let analyzer = ParamAnalyzer::new();
        assert_eq!(analyzer.classify(&Value::from(42)), ParamType::Int);
    }

    #[test]
    fn classify_large_int_as_id() {
        let analyzer = ParamAnalyzer::new();
        assert_eq!(analyzer.classify(&Value::from(1_234_567)), ParamType::Id);
    }

    #[test]
    fn classify_uuid() {
        let analyzer = ParamAnalyzer::new();
        assert_eq!(
            analyzer.classify(&Value::String(
                "550e8400-e29b-41d4-a716-446655440000".to_owned()
            )),
            ParamType::Uuid
        );
    }

    #[test]
    fn classify_email() {
        let analyzer = ParamAnalyzer::new();
        assert_eq!(
            analyzer.classify(&Value::String("test@example.com".to_owned())),
            ParamType::Email
        );
    }

    #[test]
    fn classify_jwt() {
        let analyzer = ParamAnalyzer::new();
        assert_eq!(
            analyzer.classify(&Value::String(
                "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123".to_owned()
            )),
            ParamType::Token
        );
    }

    #[test]
    fn classify_date() {
        let analyzer = ParamAnalyzer::new();
        assert_eq!(
            analyzer.classify(&Value::String("2024-01-15".to_owned())),
            ParamType::Date
        );
    }

    #[test]
    fn analyze_query_params() {
        let flow = make_flow(
            HttpMethod::Get,
            "/api/search",
            "https://api.example.com/api/search?q=test&limit=10&active=true",
            vec![],
            None,
        );
        let params = ParamAnalyzer::new().analyze_flow(&flow);
        let query_params: Vec<_> = params
            .iter()
            .filter(|p| p.location == InjectionLocation::Query)
            .collect();
        assert_eq!(query_params.len(), 3);

        let q = query_params.iter().find(|p| p.name == "q").unwrap();
        assert_eq!(q.param_type, ParamType::String);

        let limit = query_params.iter().find(|p| p.name == "limit").unwrap();
        assert_eq!(limit.param_type, ParamType::Id);
    }

    #[test]
    fn analyze_json_body() {
        let flow = make_flow(
            HttpMethod::Post,
            "/api/login",
            "https://api.example.com/api/login",
            vec![("Content-Type", "application/json")],
            Some(r#"{"username":"admin","age":25,"email":"admin@example.com"}"#),
        );
        let params = ParamAnalyzer::new().analyze_flow(&flow);
        let body_params: Vec<_> = params
            .iter()
            .filter(|p| p.location == InjectionLocation::BodyJson)
            .collect();
        assert_eq!(body_params.len(), 3);

        let email = body_params.iter().find(|p| p.name == "email").unwrap();
        assert_eq!(email.param_type, ParamType::Email);
    }

    #[test]
    fn analyze_nested_json() {
        let flow = make_flow(
            HttpMethod::Post,
            "/api/login",
            "https://api.example.com/api/login",
            vec![("Content-Type", "application/json")],
            Some(r#"{"user":{"id":42,"name":"test"}}"#),
        );
        let params = ParamAnalyzer::new().analyze_flow(&flow);
        let body_params: Vec<_> = params
            .iter()
            .filter(|p| p.location == InjectionLocation::BodyJson)
            .collect();
        assert_eq!(body_params.len(), 2);
    }

    #[test]
    fn analyze_path_params() {
        let flow = make_flow(
            HttpMethod::Get,
            "/users/123",
            "https://api.example.com/users/123",
            vec![],
            None,
        );
        let params = ParamAnalyzer::new().analyze_flow(&flow);
        let path_params: Vec<_> = params
            .iter()
            .filter(|p| p.location == InjectionLocation::Path)
            .collect();
        assert_eq!(path_params.len(), 1);
        assert_eq!(path_params[0].param_type, ParamType::Id);
    }

    #[test]
    fn analyze_relative_url() {
        let flow = make_flow(
            HttpMethod::Get,
            "/users/123",
            "/users/123?q=test",
            vec![],
            None,
        );
        let params = ParamAnalyzer::new().analyze_flow(&flow);
        assert!(params.iter().any(|p| p.location == InjectionLocation::Path));
        assert!(
            params
                .iter()
                .any(|p| p.location == InjectionLocation::Query)
        );
    }
}
