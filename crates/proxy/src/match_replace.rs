use std::collections::BTreeMap;

use api_tester_domain::{
    MatchCondition, MatchConditionType, MatchRule, ReplaceAction, ReplaceActionType, RuleDirection,
};
use regex::Regex;

pub type HeaderMap = BTreeMap<String, String>;

/// Applies match & replace rules to requests and responses, mirroring the
/// Python reference engine.
pub struct MatchReplaceEngine {
    rules: Vec<MatchRule>,
}

impl MatchReplaceEngine {
    pub fn new(rules: Vec<MatchRule>) -> Self {
        Self { rules }
    }

    pub fn rules(&self) -> &[MatchRule] {
        &self.rules
    }

    pub fn add_rule(&mut self, rule: MatchRule) {
        self.rules.push(rule);
    }

    pub fn remove_rule(&mut self, name: &str) {
        self.rules.retain(|rule| rule.name != name);
    }

    pub fn apply_to_request_headers(
        &self,
        headers: &HeaderMap,
        path: &str,
        body: Option<&str>,
    ) -> HeaderMap {
        let mut result = headers.clone();
        for rule in &self.rules {
            if rule.direction != RuleDirection::Request {
                continue;
            }
            if self.matches(&rule.r#match, &result, path, body) {
                apply_header_action(&rule.action, &mut result);
            }
        }
        result
    }

    pub fn apply_to_response_headers(&self, headers: &HeaderMap, path: &str) -> HeaderMap {
        let mut result = headers.clone();
        for rule in &self.rules {
            if rule.direction != RuleDirection::Response {
                continue;
            }
            if self.matches(&rule.r#match, &result, path, None) {
                apply_header_action(&rule.action, &mut result);
            }
        }
        result
    }

    pub fn apply_to_body(
        &self,
        body: &str,
        direction: RuleDirection,
        headers: &HeaderMap,
    ) -> String {
        let mut result = body.to_owned();
        for rule in &self.rules {
            if rule.direction != direction {
                continue;
            }
            if !self.matches(&rule.r#match, headers, "", Some(&result)) {
                continue;
            }
            if rule.action.kind == ReplaceActionType::ReplaceBody {
                if let (Some(pattern), Some(replacement)) =
                    (&rule.action.pattern, &rule.action.replacement)
                {
                    if let Ok(re) = Regex::new(pattern) {
                        result = re.replace_all(&result, replacement.as_str()).into_owned();
                    }
                }
            }
        }
        result
    }

    fn matches(
        &self,
        condition: &MatchCondition,
        headers: &HeaderMap,
        path: &str,
        body: Option<&str>,
    ) -> bool {
        match condition.kind {
            MatchConditionType::Always => true,
            MatchConditionType::Header => {
                let Some(header) = condition.header.as_deref() else {
                    return false;
                };
                let Some(pattern) = condition.pattern.as_deref() else {
                    return false;
                };
                headers
                    .get(header)
                    .is_some_and(|value| Regex::new(pattern).is_ok_and(|re| re.is_match(value)))
            }
            MatchConditionType::PathPattern => condition
                .pattern
                .as_deref()
                .is_some_and(|pattern| Regex::new(pattern).is_ok_and(|re| re.is_match(path))),
            MatchConditionType::BodyRegex => {
                let Some(pattern) = condition.pattern.as_deref() else {
                    return false;
                };
                let Some(body) = body else {
                    return false;
                };
                Regex::new(pattern).is_ok_and(|re| re.is_match(body))
            }
        }
    }
}

fn apply_header_action(action: &ReplaceAction, headers: &mut HeaderMap) {
    match action.kind {
        ReplaceActionType::SetHeader => {
            if let (Some(name), Some(value)) = (&action.header, &action.value) {
                headers.insert(name.clone(), value.clone());
            }
        }
        ReplaceActionType::RemoveHeader => {
            if let Some(name) = &action.header {
                headers.remove(name);
            }
        }
        ReplaceActionType::ReplaceBody | ReplaceActionType::ReplaceUrl => {}
    }
}

#[cfg(test)]
mod tests {
    use super::MatchReplaceEngine;
    use api_tester_domain::{
        MatchCondition, MatchConditionType, MatchRule, ReplaceAction, ReplaceActionType,
        RuleDirection,
    };
    use std::collections::BTreeMap;

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
        let headers = BTreeMap::from([("Host".to_owned(), "example.com".to_owned())]);

        let out = engine.apply_to_request_headers(&headers, "/api", None);

        assert_eq!(out.get("X-Test").map(String::as_str), Some("1"));
        assert_eq!(out.get("Host").map(String::as_str), Some("example.com"));
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
        let headers = BTreeMap::from([("Server".to_owned(), "nginx".to_owned())]);

        let out = engine.apply_to_response_headers(&headers, "/");

        assert!(!out.contains_key("Server"));
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

        let out = engine.apply_to_body("token=secret-42", RuleDirection::Request, &BTreeMap::new());

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

        let matched = engine.apply_to_response_headers(
            &BTreeMap::from([("Content-Type".to_owned(), "application/json".to_owned())]),
            "/",
        );
        assert_eq!(matched.get("X-JSON").map(String::as_str), Some("true"));

        let unmatched = engine.apply_to_response_headers(
            &BTreeMap::from([("Content-Type".to_owned(), "text/html".to_owned())]),
            "/",
        );
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

        let admin = engine.apply_to_request_headers(&BTreeMap::new(), "/admin/users", None);
        assert_eq!(admin.get("X-Admin").map(String::as_str), Some("true"));

        let public = engine.apply_to_request_headers(&BTreeMap::new(), "/public", None);
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

        let out = engine.apply_to_body(body, RuleDirection::Response, &BTreeMap::new());

        assert!(out.contains(r#""password":"***""#));
        assert!(!out.contains("secret123"));
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

        let out = engine.apply_to_request_headers(&BTreeMap::new(), "/", None);
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

        let out = engine.apply_to_request_headers(&BTreeMap::new(), "/", None);
        assert!(!out.contains_key("X-Resp"));
    }
}
