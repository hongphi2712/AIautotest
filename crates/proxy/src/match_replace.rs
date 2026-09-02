use http::header::{HeaderMap, HeaderName, HeaderValue};

use api_tester_domain::{MatchConditionType, MatchRule, ReplaceActionType, RuleDirection};
use regex::Regex;

/// Applies match & replace rules to requests and responses, mirroring the
/// Python reference engine. All rule regexes are compiled once at engine
/// construction so hot-path matching never recompiles a pattern. The engine
/// operates on `http::HeaderMap` so duplicate header values survive rule
/// application and forwarding.
pub struct MatchReplaceEngine {
    rules: Vec<MatchRule>,
    compiled: Vec<CompiledRule>,
}

struct CompiledRule {
    direction: RuleDirection,
    condition: CompiledCondition,
    action: CompiledAction,
}

enum CompiledCondition {
    Always,
    Header {
        header: Option<HeaderName>,
        pattern: Option<Regex>,
    },
    PathPattern(Option<Regex>),
    BodyRegex(Option<Regex>),
}

enum CompiledAction {
    SetHeader {
        header: Option<HeaderName>,
        value: Option<HeaderValue>,
    },
    RemoveHeader {
        header: Option<HeaderName>,
    },
    ReplaceBody {
        pattern: Option<Regex>,
        replacement: String,
    },
    ReplaceUrl {
        pattern: Option<Regex>,
        replacement: String,
    },
}

impl CompiledCondition {
    fn matches(&self, headers: &HeaderMap, path: &str, body: Option<&str>) -> bool {
        match self {
            Self::Always => true,
            Self::Header {
                header: Some(name),
                pattern: Some(re),
            } => headers
                .get(name)
                .is_some_and(|value| re.is_match(value.to_str().unwrap_or_default())),
            Self::Header { .. } => false,
            Self::PathPattern(pattern) => pattern.as_ref().is_some_and(|re| re.is_match(path)),
            Self::BodyRegex(pattern) => pattern
                .as_ref()
                .is_some_and(|re| body.is_some_and(|b| re.is_match(b))),
        }
    }
}

impl CompiledAction {
    fn apply_headers(&self, headers: &mut HeaderMap) {
        match self {
            Self::SetHeader {
                header: Some(name),
                value: Some(value),
            } => {
                headers.insert(name.clone(), value.clone());
            }
            Self::RemoveHeader { header: Some(name) } => {
                headers.remove(name);
            }
            _ => {}
        }
    }

    fn apply_body(&self, body: &mut String) {
        if let Self::ReplaceBody {
            pattern: Some(re),
            replacement,
        } = self
        {
            *body = re.replace_all(body, replacement.as_str()).into_owned();
        }
    }
}

impl MatchReplaceEngine {
    pub fn new(rules: Vec<MatchRule>) -> Self {
        let compiled = rules.iter().map(compile_rule).collect();
        Self { rules, compiled }
    }

    pub fn rules(&self) -> &[MatchRule] {
        &self.rules
    }

    pub fn add_rule(&mut self, rule: MatchRule) {
        self.compiled.push(compile_rule(&rule));
        self.rules.push(rule);
    }

    pub fn remove_rule(&mut self, name: &str) {
        self.rules.retain(|rule| rule.name != name);
        self.compiled = self.rules.iter().map(compile_rule).collect();
    }

    pub fn apply_to_request_headers(
        &self,
        headers: &HeaderMap,
        path: &str,
        body: Option<&str>,
    ) -> HeaderMap {
        let mut result = headers.clone();
        for rule in &self.compiled {
            if rule.direction != RuleDirection::Request {
                continue;
            }
            if rule.condition.matches(&result, path, body) {
                rule.action.apply_headers(&mut result);
            }
        }
        result
    }

    pub fn apply_to_response_headers(&self, headers: &HeaderMap, path: &str) -> HeaderMap {
        let mut result = headers.clone();
        for rule in &self.compiled {
            if rule.direction != RuleDirection::Response {
                continue;
            }
            if rule.condition.matches(&result, path, None) {
                rule.action.apply_headers(&mut result);
            }
        }
        result
    }

    pub fn apply_to_body(
        &self,
        body: &str,
        direction: RuleDirection,
        headers: &HeaderMap,
        path: &str,
    ) -> String {
        let mut result = body.to_owned();
        for rule in &self.compiled {
            if rule.direction != direction {
                continue;
            }
            if !rule.condition.matches(headers, path, Some(&result)) {
                continue;
            }
            rule.action.apply_body(&mut result);
        }
        result
    }

    /// Rewrites a request URL (`scheme://host/path`) by applying matching
    /// request-direction `replace_url` rules. Rules with a response direction
    /// are ignored (a response has no URL to rewrite). The pattern is matched
    /// against the full absolute URL, so a rule can change the scheme, host,
    /// port, path, or query string.
    pub fn apply_to_url(
        &self,
        url: &str,
        headers: &HeaderMap,
        path: &str,
        body: Option<&str>,
    ) -> String {
        let mut result = url.to_owned();
        for rule in &self.compiled {
            if rule.direction != RuleDirection::Request {
                continue;
            }
            if !rule.condition.matches(headers, path, body) {
                continue;
            }
            if let CompiledAction::ReplaceUrl {
                pattern: Some(re),
                replacement,
            } = &rule.action
            {
                result = re.replace_all(&result, replacement.as_str()).into_owned();
            }
        }
        result
    }
}

fn compile_rule(rule: &MatchRule) -> CompiledRule {
    let condition = match rule.r#match.kind {
        MatchConditionType::Always => CompiledCondition::Always,
        MatchConditionType::Header => CompiledCondition::Header {
            header: rule
                .r#match
                .header
                .as_deref()
                .and_then(|name| HeaderName::try_from(name).ok()),
            pattern: compile_optional(&rule.r#match.pattern),
        },
        MatchConditionType::PathPattern => {
            CompiledCondition::PathPattern(compile_optional(&rule.r#match.pattern))
        }
        MatchConditionType::BodyRegex => {
            CompiledCondition::BodyRegex(compile_optional(&rule.r#match.pattern))
        }
    };
    let action = match rule.action.kind {
        ReplaceActionType::SetHeader => CompiledAction::SetHeader {
            header: rule
                .action
                .header
                .as_deref()
                .and_then(|name| HeaderName::try_from(name).ok()),
            value: rule
                .action
                .value
                .as_deref()
                .and_then(|value| HeaderValue::from_str(value).ok()),
        },
        ReplaceActionType::RemoveHeader => CompiledAction::RemoveHeader {
            header: rule
                .action
                .header
                .as_deref()
                .and_then(|name| HeaderName::try_from(name).ok()),
        },
        ReplaceActionType::ReplaceBody => CompiledAction::ReplaceBody {
            pattern: compile_optional(&rule.action.pattern),
            replacement: rule.action.replacement.clone().unwrap_or_default(),
        },
        ReplaceActionType::ReplaceUrl => CompiledAction::ReplaceUrl {
            pattern: compile_optional(&rule.action.pattern),
            replacement: rule.action.replacement.clone().unwrap_or_default(),
        },
    };
    CompiledRule {
        direction: rule.direction.clone(),
        condition,
        action,
    }
}

fn compile_optional(pattern: &Option<String>) -> Option<Regex> {
    pattern.as_deref().and_then(|p| Regex::new(p).ok())
}

#[cfg(test)]
mod tests {
    use super::MatchReplaceEngine;
    use api_tester_domain::{
        MatchCondition, MatchConditionType, MatchRule, ReplaceAction, ReplaceActionType,
        RuleDirection,
    };
    use http::header::{HeaderMap, HeaderName, HeaderValue};

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.insert(
                HeaderName::from_bytes(name.as_bytes()).unwrap(),
                HeaderValue::from_str(value).unwrap(),
            );
        }
        map
    }

    fn value<'a>(map: &'a HeaderMap, name: &str) -> Option<&'a str> {
        map.get(name).and_then(|value| value.to_str().ok())
    }

    fn always_rule(action: ReplaceAction) -> MatchRule {
        MatchRule {
            name: "test".to_owned(),
            direction: RuleDirection::Request,
            r#match: MatchCondition {
                kind: MatchConditionType::Always,
                header: None,
                pattern: None,
            },
            action,
        }
    }

    #[test]
    fn request_set_header_is_applied() {
        let action = ReplaceAction {
            kind: ReplaceActionType::SetHeader,
            header: Some("X-Test".to_owned()),
            value: Some("1".to_owned()),
            pattern: None,
            replacement: None,
        };
        let engine = MatchReplaceEngine::new(vec![always_rule(action)]);
        let request_headers = headers(&[("Host", "example.com")]);

        let out = engine.apply_to_request_headers(&request_headers, "/api", None);

        assert_eq!(value(&out, "X-Test"), Some("1"));
        assert_eq!(value(&out, "Host"), Some("example.com"));
    }

    #[test]
    fn response_remove_header_is_applied() {
        let action = ReplaceAction {
            kind: ReplaceActionType::RemoveHeader,
            header: Some("Server".to_owned()),
            value: None,
            pattern: None,
            replacement: None,
        };
        let rule = MatchRule {
            name: "r".to_owned(),
            direction: RuleDirection::Response,
            r#match: MatchCondition::default(),
            action,
        };
        let engine = MatchReplaceEngine::new(vec![rule]);
        let response_headers = headers(&[("Server", "nginx")]);

        let out = engine.apply_to_response_headers(&response_headers, "/");

        assert!(!out.contains_key("Server"));
    }

    #[test]
    fn duplicate_header_values_survive() {
        let engine = MatchReplaceEngine::new(vec![]);
        let mut response_headers = HeaderMap::new();
        response_headers.append(
            HeaderName::from_bytes(b"set-cookie").unwrap(),
            HeaderValue::from_str("a=1").unwrap(),
        );
        response_headers.append(
            HeaderName::from_bytes(b"set-cookie").unwrap(),
            HeaderValue::from_str("b=2").unwrap(),
        );

        let out = engine.apply_to_response_headers(&response_headers, "/");

        let values: Vec<&str> = out
            .get_all("set-cookie")
            .iter()
            .filter_map(|value| value.to_str().ok())
            .collect();
        assert_eq!(values, vec!["a=1", "b=2"]);
    }

    #[test]
    fn body_regex_is_replaced() {
        let action = ReplaceAction {
            kind: ReplaceActionType::ReplaceBody,
            header: None,
            value: None,
            pattern: Some(r"secret-\d+".to_owned()),
            replacement: Some("REDACTED".to_owned()),
        };
        let engine = MatchReplaceEngine::new(vec![always_rule(action)]);

        let out = engine.apply_to_body(
            "token=secret-42",
            RuleDirection::Request,
            &HeaderMap::new(),
            "/",
        );

        assert_eq!(out, "token=REDACTED");
    }

    #[test]
    fn header_condition_matches() {
        let rule = MatchRule {
            name: "modify_json".to_owned(),
            direction: RuleDirection::Response,
            r#match: MatchCondition {
                kind: MatchConditionType::Header,
                header: Some("Content-Type".to_owned()),
                pattern: Some(r"application/json".to_owned()),
            },
            action: ReplaceAction {
                kind: ReplaceActionType::SetHeader,
                header: Some("X-JSON".to_owned()),
                value: Some("true".to_owned()),
                pattern: None,
                replacement: None,
            },
        };
        let engine = MatchReplaceEngine::new(vec![rule]);

        let matched = engine
            .apply_to_response_headers(&headers(&[("Content-Type", "application/json")]), "/");
        assert_eq!(value(&matched, "X-JSON"), Some("true"));

        let unmatched =
            engine.apply_to_response_headers(&headers(&[("Content-Type", "text/html")]), "/");
        assert!(!unmatched.contains_key("X-JSON"));
    }

    #[test]
    fn path_pattern_condition_matches() {
        let rule = MatchRule {
            name: "flag_admin".to_owned(),
            direction: RuleDirection::Request,
            r#match: MatchCondition {
                kind: MatchConditionType::PathPattern,
                header: None,
                pattern: Some(r"/admin/.*".to_owned()),
            },
            action: ReplaceAction {
                kind: ReplaceActionType::SetHeader,
                header: Some("X-Admin".to_owned()),
                value: Some("true".to_owned()),
                pattern: None,
                replacement: None,
            },
        };
        let engine = MatchReplaceEngine::new(vec![rule]);

        let admin = engine.apply_to_request_headers(&HeaderMap::new(), "/admin/users", None);
        assert_eq!(value(&admin, "X-Admin"), Some("true"));

        let public = engine.apply_to_request_headers(&HeaderMap::new(), "/public", None);
        assert!(!public.contains_key("X-Admin"));
    }

    #[test]
    fn password_body_is_masked() {
        let rule = MatchRule {
            name: "mask_sensitive".to_owned(),
            direction: RuleDirection::Response,
            r#match: MatchCondition {
                kind: MatchConditionType::BodyRegex,
                header: None,
                pattern: Some(r#""password"\s*:\s*"[^"]*""#.to_owned()),
            },
            action: ReplaceAction {
                kind: ReplaceActionType::ReplaceBody,
                header: None,
                value: None,
                pattern: Some(r#""password"\s*:\s*"[^"]*""#.to_owned()),
                replacement: Some(r#""password":"***""#.to_owned()),
            },
        };
        let engine = MatchReplaceEngine::new(vec![rule]);
        let body = r#"{"user":"admin","password":"secret123","role":"admin"}"#;

        let out = engine.apply_to_body(body, RuleDirection::Response, &HeaderMap::new(), "/");

        assert!(out.contains(r#""password":"***""#));
        assert!(!out.contains("secret123"));
    }

    #[test]
    fn header_condition_is_case_insensitive() {
        let rule = MatchRule {
            name: "lowercase_keys".to_owned(),
            direction: RuleDirection::Request,
            r#match: MatchCondition {
                kind: MatchConditionType::Header,
                header: Some("Content-Type".to_owned()),
                pattern: Some(r"application/json".to_owned()),
            },
            action: ReplaceAction {
                kind: ReplaceActionType::SetHeader,
                header: Some("X-JSON".to_owned()),
                value: Some("true".to_owned()),
                pattern: None,
                replacement: None,
            },
        };
        let engine = MatchReplaceEngine::new(vec![rule]);

        let matched = engine.apply_to_request_headers(
            &headers(&[("content-type", "application/json")]),
            "/",
            None,
        );
        assert_eq!(value(&matched, "X-JSON"), Some("true"));
    }

    #[test]
    fn path_condition_applies_to_body_rules() {
        let rule = MatchRule {
            name: "body_on_admin_path".to_owned(),
            direction: RuleDirection::Request,
            r#match: MatchCondition {
                kind: MatchConditionType::PathPattern,
                header: None,
                pattern: Some(r"/admin/.*".to_owned()),
            },
            action: ReplaceAction {
                kind: ReplaceActionType::ReplaceBody,
                header: None,
                value: None,
                pattern: Some("secret".to_owned()),
                replacement: Some("REDACTED".to_owned()),
            },
        };
        let engine = MatchReplaceEngine::new(vec![rule]);

        let rewritten = engine.apply_to_body(
            "secret=1",
            RuleDirection::Request,
            &HeaderMap::new(),
            "/admin/x",
        );
        assert_eq!(rewritten, "REDACTED=1");

        let untouched = engine.apply_to_body(
            "secret=1",
            RuleDirection::Request,
            &HeaderMap::new(),
            "/public",
        );
        assert_eq!(untouched, "secret=1");
    }

    #[test]
    fn remove_rule_removes_by_name() {
        let action = ReplaceAction {
            kind: ReplaceActionType::SetHeader,
            header: Some("X-Test".to_owned()),
            value: Some("1".to_owned()),
            pattern: None,
            replacement: None,
        };
        let mut engine = MatchReplaceEngine::new(vec![always_rule(action)]);
        engine.remove_rule("test");

        let out = engine.apply_to_request_headers(&HeaderMap::new(), "/", None);
        assert!(!out.contains_key("X-Test"));
    }

    #[test]
    fn wrong_direction_skipped() {
        let rule = MatchRule {
            name: "response_only".to_owned(),
            direction: RuleDirection::Response,
            r#match: MatchCondition::default(),
            action: ReplaceAction {
                kind: ReplaceActionType::SetHeader,
                header: Some("X-Resp".to_owned()),
                value: Some("1".to_owned()),
                pattern: None,
                replacement: None,
            },
        };
        let engine = MatchReplaceEngine::new(vec![rule]);

        let out = engine.apply_to_request_headers(&HeaderMap::new(), "/", None);
        assert!(!out.contains_key("X-Resp"));
    }

    fn url_rule(
        name: &str,
        direction: RuleDirection,
        condition: MatchCondition,
        pattern: Option<&str>,
        replacement: &str,
    ) -> MatchRule {
        MatchRule {
            name: name.to_owned(),
            direction,
            r#match: condition,
            action: ReplaceAction {
                kind: ReplaceActionType::ReplaceUrl,
                header: None,
                value: None,
                pattern: pattern.map(str::to_owned),
                replacement: Some(replacement.to_owned()),
            },
        }
    }

    #[test]
    fn replace_url_rewrites_full_url() {
        let rule = url_rule(
            "move",
            RuleDirection::Request,
            MatchCondition::default(),
            Some(r"http://old\.example\.com:8080/"),
            "https://new.example.com/",
        );
        let engine = MatchReplaceEngine::new(vec![rule]);

        let out = engine.apply_to_url(
            "http://old.example.com:8080/api/orders?q=1",
            &HeaderMap::new(),
            "/api/orders",
            None,
        );

        assert_eq!(out, "https://new.example.com/api/orders?q=1");
    }

    #[test]
    fn replace_url_path_pattern_condition_gates_rewrite() {
        let rule = url_rule(
            "admin_only",
            RuleDirection::Request,
            MatchCondition {
                kind: MatchConditionType::PathPattern,
                header: None,
                pattern: Some(r"/admin/.*".to_owned()),
            },
            Some(r"/admin/"),
            "/api/v2/admin/",
        );
        let engine = MatchReplaceEngine::new(vec![rule]);

        let matched = engine.apply_to_url(
            "http://example.com/admin/users",
            &HeaderMap::new(),
            "/admin/users",
            None,
        );
        assert_eq!(matched, "http://example.com/api/v2/admin/users");

        let untouched = engine.apply_to_url(
            "http://example.com/public",
            &HeaderMap::new(),
            "/public",
            None,
        );
        assert_eq!(untouched, "http://example.com/public");
    }

    #[test]
    fn replace_url_ignores_response_direction() {
        let rule = url_rule(
            "response_only",
            RuleDirection::Response,
            MatchCondition::default(),
            Some(r"example\.com"),
            "elsewhere.com",
        );
        let engine = MatchReplaceEngine::new(vec![rule]);

        let out = engine.apply_to_url("http://example.com/", &HeaderMap::new(), "/", None);

        assert_eq!(out, "http://example.com/");
    }

    #[test]
    fn replace_url_supports_capture_groups() {
        let rule = url_rule(
            "rewrite_path",
            RuleDirection::Request,
            MatchCondition::default(),
            Some(r"http://example\.com/([^?]+)"),
            "http://mirror.example.com/api/$1",
        );
        let engine = MatchReplaceEngine::new(vec![rule]);

        let out = engine.apply_to_url(
            "http://example.com/v1/resource?id=7",
            &HeaderMap::new(),
            "/v1/resource",
            None,
        );

        assert_eq!(out, "http://mirror.example.com/api/v1/resource?id=7");
    }

    #[test]
    fn replace_url_no_op_when_pattern_absent_or_invalid() {
        let missing = url_rule(
            "missing_pattern",
            RuleDirection::Request,
            MatchCondition::default(),
            None,
            "http://other.example.com/",
        );
        let invalid = url_rule(
            "invalid_pattern",
            RuleDirection::Request,
            MatchCondition::default(),
            Some("("),
            "http://other.example.com/",
        );
        let engine = MatchReplaceEngine::new(vec![missing, invalid]);

        let out = engine.apply_to_url("http://example.com/", &HeaderMap::new(), "/", None);

        assert_eq!(out, "http://example.com/");
    }

    #[test]
    fn replace_url_multiple_rules_apply_in_order() {
        let engine = MatchReplaceEngine::new(vec![
            url_rule(
                "switch_host",
                RuleDirection::Request,
                MatchCondition::default(),
                Some(r"^http://example\.com"),
                "http://mirror.example.com",
            ),
            url_rule(
                "prefix_path",
                RuleDirection::Request,
                MatchCondition::default(),
                Some(r"http://mirror\.example\.com/"),
                "http://mirror.example.com/api/",
            ),
        ]);

        let out = engine.apply_to_url(
            "http://example.com/orders",
            &HeaderMap::new(),
            "/orders",
            None,
        );

        assert_eq!(out, "http://mirror.example.com/api/orders");
    }
}
