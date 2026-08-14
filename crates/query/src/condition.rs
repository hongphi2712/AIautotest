use std::cmp::Ordering;

use api_tester_domain::HttpFlow;
use regex::Regex;

/// Fields of `HttpFlow` exposed to the query DSL and parser.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FieldName {
    Method,
    Host,
    Path,
    FullUrl,
    ContentType,
    ResponseStatus,
    RequestBody,
    ResponseBody,
}

/// A value an `Equals`-style condition is compared against. Mirrors the
/// Python DSL where comparisons accept strings, numbers and booleans.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QueryValue {
    Text(String),
    Number(i64),
    Bool(bool),
}

impl From<&str> for QueryValue {
    fn from(value: &str) -> Self {
        Self::Text(value.to_owned())
    }
}

impl From<String> for QueryValue {
    fn from(value: String) -> Self {
        Self::Text(value)
    }
}

impl From<i64> for QueryValue {
    fn from(value: i64) -> Self {
        Self::Number(value)
    }
}

impl From<i32> for QueryValue {
    fn from(value: i32) -> Self {
        Self::Number(value as i64)
    }
}

impl From<u16> for QueryValue {
    fn from(value: u16) -> Self {
        Self::Number(value as i64)
    }
}

impl From<bool> for QueryValue {
    fn from(value: bool) -> Self {
        Self::Bool(value)
    }
}

/// A compiled filter condition over one `HttpFlow`. The `Regex` variant
/// holds a compiled pattern; invalid patterns compile to `NoMatch` so the
/// DSL never panics on user input.
#[derive(Debug, Clone)]
pub enum Condition {
    And(Vec<Condition>),
    Or(Vec<Condition>),
    Not(Box<Condition>),
    Equals(FieldName, QueryValue),
    NotEquals(FieldName, QueryValue),
    Contains(FieldName, String),
    Regex(FieldName, Regex),
    Gt(FieldName, QueryValue),
    Ge(FieldName, QueryValue),
    Lt(FieldName, QueryValue),
    Le(FieldName, QueryValue),
    NoMatch,
}

#[derive(Debug, Clone)]
enum FieldValue {
    Text(String),
    Number(i64),
    Null,
}

fn extract(field: &FieldName, flow: &HttpFlow) -> FieldValue {
    match field {
        FieldName::Method => FieldValue::Text(flow.method.as_str().to_owned()),
        FieldName::Host => FieldValue::Text(flow.host.clone()),
        FieldName::Path => FieldValue::Text(flow.path.clone()),
        FieldName::FullUrl => FieldValue::Text(flow.full_url.clone()),
        FieldName::ContentType => FieldValue::Text(flow.content_type.clone()),
        FieldName::ResponseStatus => FieldValue::Number(flow.response_status as i64),
        FieldName::RequestBody => flow
            .request_body
            .clone()
            .map(FieldValue::Text)
            .unwrap_or(FieldValue::Null),
        FieldName::ResponseBody => flow
            .response_body
            .clone()
            .map(FieldValue::Text)
            .unwrap_or(FieldValue::Null),
    }
}

fn compare_eq(field: &FieldValue, expected: &QueryValue) -> bool {
    match (field, expected) {
        (FieldValue::Text(actual), QueryValue::Text(expected)) => actual == expected,
        (FieldValue::Number(actual), QueryValue::Number(expected)) => actual == expected,
        _ => false,
    }
}

fn compare_ordered(field: &FieldValue, expected: &QueryValue, order: Ordering) -> bool {
    match (field, expected) {
        (FieldValue::Number(actual), QueryValue::Number(expected)) => actual.cmp(expected) == order,
        _ => false,
    }
}

impl Condition {
    pub fn matches(&self, flow: &HttpFlow) -> bool {
        match self {
            Self::And(conditions) => conditions.iter().all(|condition| condition.matches(flow)),
            Self::Or(conditions) => conditions.iter().any(|condition| condition.matches(flow)),
            Self::Not(condition) => !condition.matches(flow),
            Self::Equals(field, value) => compare_eq(&extract(field, flow), value),
            Self::NotEquals(field, value) => !compare_eq(&extract(field, flow), value),
            Self::Contains(field, needle) => match extract(field, flow) {
                FieldValue::Text(text) => text.contains(needle.as_str()),
                _ => false,
            },
            Self::Regex(field, pattern) => match extract(field, flow) {
                FieldValue::Text(text) => pattern.is_match(&text),
                FieldValue::Null => pattern.is_match(""),
                FieldValue::Number(_) => false,
            },
            Self::Gt(field, value) => {
                compare_ordered(&extract(field, flow), value, Ordering::Greater)
            }
            Self::Ge(field, value) => {
                compare_ordered(&extract(field, flow), value, Ordering::Greater)
                    || compare_eq(&extract(field, flow), value)
            }
            Self::Lt(field, value) => compare_ordered(&extract(field, flow), value, Ordering::Less),
            Self::Le(field, value) => {
                compare_ordered(&extract(field, flow), value, Ordering::Less)
                    || compare_eq(&extract(field, flow), value)
            }
            Self::NoMatch => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Condition, FieldName, QueryValue};
    use api_tester_domain::{HttpFlow, HttpMethod};

    fn make_flow(method: HttpMethod, path: &str, status: u16) -> HttpFlow {
        let mut flow = HttpFlow::new(method, "api.example.com", path);
        flow.full_url = format!("https://api.example.com{path}");
        flow.response_status = status;
        flow
    }

    fn equals(field: FieldName, value: &str) -> Condition {
        Condition::Equals(field, QueryValue::Text(value.to_owned()))
    }

    #[test]
    fn equals_matches() {
        let condition = equals(FieldName::Method, "GET");
        assert!(condition.matches(&make_flow(HttpMethod::Get, "/api/test", 200)));
        assert!(!condition.matches(&make_flow(HttpMethod::Post, "/api/test", 200)));
    }

    #[test]
    fn contains_matches() {
        let condition = Condition::Contains(FieldName::Path, "/api/".to_owned());
        assert!(condition.matches(&make_flow(HttpMethod::Get, "/api/users", 200)));
        assert!(!condition.matches(&make_flow(HttpMethod::Get, "/other", 200)));
    }

    #[test]
    fn greater_than_matches() {
        let condition = Condition::Ge(FieldName::ResponseStatus, QueryValue::Number(400));
        assert!(condition.matches(&make_flow(HttpMethod::Get, "/api/x", 500)));
        assert!(!condition.matches(&make_flow(HttpMethod::Get, "/api/x", 200)));
    }

    #[test]
    fn and_combines() {
        let condition = Condition::And(vec![
            equals(FieldName::Method, "GET"),
            Condition::Equals(FieldName::ResponseStatus, QueryValue::Number(200)),
        ]);
        assert!(condition.matches(&make_flow(HttpMethod::Get, "/api/x", 200)));
        assert!(!condition.matches(&make_flow(HttpMethod::Get, "/api/x", 404)));
    }

    #[test]
    fn or_matches_any() {
        let condition = Condition::Or(vec![
            equals(FieldName::Method, "GET"),
            equals(FieldName::Method, "POST"),
        ]);
        assert!(condition.matches(&make_flow(HttpMethod::Post, "/api/x", 200)));
        assert!(!condition.matches(&make_flow(HttpMethod::Delete, "/api/x", 200)));
    }

    #[test]
    fn not_inverts() {
        let condition = Condition::Not(Box::new(equals(FieldName::Method, "GET")));
        assert!(condition.matches(&make_flow(HttpMethod::Post, "/api/x", 200)));
    }

    #[test]
    fn null_body_never_equals_text() {
        let condition = equals(FieldName::RequestBody, "x");
        let flow = make_flow(HttpMethod::Post, "/api/x", 200);
        assert!(!condition.matches(&flow));
    }
}
