use regex::Regex;

use crate::condition::{Condition, FieldName, QueryValue};

/// A typed query field with builder methods. Python overloads `==`, `>=` etc;
/// Rust cannot, so conditions are built with explicit methods.
#[derive(Debug, Clone, Copy)]
pub struct Field {
    pub(crate) name: FieldName,
}

impl Field {
    pub fn eq(self, value: impl Into<QueryValue>) -> Condition {
        Condition::Equals(self.name, value.into())
    }

    pub fn ne(self, value: impl Into<QueryValue>) -> Condition {
        Condition::NotEquals(self.name, value.into())
    }

    pub fn gt(self, value: impl Into<QueryValue>) -> Condition {
        Condition::Gt(self.name, value.into())
    }

    pub fn ge(self, value: impl Into<QueryValue>) -> Condition {
        Condition::Ge(self.name, value.into())
    }

    pub fn lt(self, value: impl Into<QueryValue>) -> Condition {
        Condition::Lt(self.name, value.into())
    }

    pub fn le(self, value: impl Into<QueryValue>) -> Condition {
        Condition::Le(self.name, value.into())
    }

    pub fn contains(self, value: impl Into<String>) -> Condition {
        Condition::Contains(self.name, value.into())
    }

    /// An invalid pattern compiles to `Condition::NoMatch` instead of
    /// panicking.
    pub fn regex(self, pattern: &str) -> Condition {
        match Regex::new(pattern) {
            Ok(re) => Condition::Regex(self.name, re),
            Err(_) => Condition::NoMatch,
        }
    }
}

/// Namespace of queryable `HttpFlow` fields.
pub struct Q;

impl Q {
    pub const fn method() -> Field {
        Field {
            name: FieldName::Method,
        }
    }

    pub const fn host() -> Field {
        Field {
            name: FieldName::Host,
        }
    }

    pub const fn path() -> Field {
        Field {
            name: FieldName::Path,
        }
    }

    pub const fn full_url() -> Field {
        Field {
            name: FieldName::FullUrl,
        }
    }

    pub const fn content_type() -> Field {
        Field {
            name: FieldName::ContentType,
        }
    }

    pub const fn response_status() -> Field {
        Field {
            name: FieldName::ResponseStatus,
        }
    }

    pub const fn request_body() -> Field {
        Field {
            name: FieldName::RequestBody,
        }
    }

    pub const fn response_body() -> Field {
        Field {
            name: FieldName::ResponseBody,
        }
    }
}

pub fn and_(conditions: Vec<Condition>) -> Condition {
    Condition::And(conditions)
}

pub fn or_(conditions: Vec<Condition>) -> Condition {
    Condition::Or(conditions)
}

pub fn not_(condition: Condition) -> Condition {
    Condition::Not(Box::new(condition))
}

#[cfg(test)]
mod tests {
    use super::{Q, and_, not_, or_};
    use api_tester_domain::{HttpFlow, HttpMethod};

    fn make_flow(method: HttpMethod, path: &str, status: u16) -> HttpFlow {
        let mut flow = HttpFlow::new(method, "api.example.com", path);
        flow.full_url = format!("https://api.example.com{path}");
        flow.response_status = status;
        flow
    }

    #[test]
    fn equals() {
        let condition = Q::method().eq("GET");
        assert!(condition.matches(&make_flow(HttpMethod::Get, "/api/test", 200)));
        assert!(!condition.matches(&make_flow(HttpMethod::Post, "/api/test", 200)));
    }

    #[test]
    fn contains() {
        let condition = Q::path().contains("/api/");
        assert!(condition.matches(&make_flow(HttpMethod::Get, "/api/users", 200)));
        assert!(!condition.matches(&make_flow(HttpMethod::Get, "/other", 200)));
    }

    #[test]
    fn greater_than() {
        let condition = Q::response_status().ge(400);
        assert!(condition.matches(&make_flow(HttpMethod::Get, "/api/x", 500)));
        assert!(!condition.matches(&make_flow(HttpMethod::Get, "/api/x", 200)));
    }

    #[test]
    fn and_function() {
        let condition = and_(vec![Q::method().eq("GET"), Q::path().contains("/api/")]);
        assert!(condition.matches(&make_flow(HttpMethod::Get, "/api/x", 200)));
        assert!(!condition.matches(&make_flow(HttpMethod::Post, "/api/x", 200)));
    }

    #[test]
    fn or_function() {
        let condition = or_(vec![Q::method().eq("GET"), Q::method().eq("POST")]);
        assert!(condition.matches(&make_flow(HttpMethod::Post, "/api/x", 200)));
    }

    #[test]
    fn not_function() {
        let condition = not_(Q::method().eq("GET"));
        assert!(condition.matches(&make_flow(HttpMethod::Post, "/api/x", 200)));
    }

    #[test]
    fn regex_invalid_is_no_match() {
        let condition = Q::path().regex("(");
        assert!(!condition.matches(&make_flow(HttpMethod::Get, "/api/x", 200)));
    }
}
