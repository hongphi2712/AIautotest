use regex::Regex;
use thiserror::Error;

use crate::condition::{Condition, FieldName};
use crate::dsl::Field;

const WILDCARD_PATTERN: &str = r"[*?]";

#[derive(Debug, Error, PartialEq, Eq)]
pub enum QueryError {
    #[error("invalid HTTPQL line: {0}")]
    InvalidLine(String),
    #[error("unknown field: {0}")]
    UnknownField(String),
    #[error("unknown operator: {0}")]
    UnknownOperator(String),
    #[error("unbalanced parentheses: {0}")]
    Unbalanced(String),
}

/// Parses HTTPQL-style query strings into a `Condition`.
///
/// Base syntax (Python parity), each line is AND-ed together:
/// ```text
/// method:POST
/// path:/api/*
/// host:*.example.com
/// resp.status:>=400
/// req.body:error
/// resp.body:token
/// ```
///
/// Extension: within a line `|` ORs alternatives, `&` ANDs them, and
/// parentheses group, e.g. `(method:GET | method:POST) & resp.status:>=400`.
pub struct HTTPQLParser;

fn field(name: &str) -> Option<Field> {
    match name {
        "method" => Some(crate::dsl::Q::method()),
        "path" => Some(crate::dsl::Q::path()),
        "host" => Some(crate::dsl::Q::host()),
        "resp.status" => Some(crate::dsl::Q::response_status()),
        "req.body" => Some(crate::dsl::Q::request_body()),
        "resp.body" => Some(crate::dsl::Q::response_body()),
        "content-type" => Some(crate::dsl::Q::content_type()),
        _ => None,
    }
}

/// Splits on `sep` only at parenthesis depth zero.
fn split_top_level(input: &str, sep: char) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut depth = 0i32;
    let mut start = 0;
    for (index, ch) in input.char_indices() {
        match ch {
            '(' => depth += 1,
            ')' => depth -= 1,
            current if current == sep && depth == 0 => {
                parts.push(&input[start..index]);
                start = index + ch.len_utf8();
            }
            _ => {}
        }
    }
    parts.push(&input[start..]);
    parts
}

impl HTTPQLParser {
    pub fn parse(&self, query_string: &str) -> Result<Condition, QueryError> {
        let mut conditions = Vec::new();
        for raw_line in query_string.split('\n') {
            let line = raw_line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            conditions.push(self.parse_line(line)?);
        }
        Ok(Condition::And(conditions))
    }

    fn parse_line(&self, line: &str) -> Result<Condition, QueryError> {
        let or_parts = split_top_level(line, '|');
        if or_parts.len() > 1 {
            let mut conditions = Vec::new();
            let mut all_valid = true;
            for part in &or_parts {
                match self.parse_and(part) {
                    Ok(condition) => conditions.push(condition),
                    Err(_) => {
                        all_valid = false;
                        break;
                    }
                }
            }
            if all_valid {
                return Ok(Condition::Or(conditions));
            }
        }
        // A single literal may itself contain '|' (e.g. req.body:a|b), so
        // fall back to parsing the whole line as one field when the OR
        // interpretation fails.
        self.parse_and(line)
    }

    fn parse_and(&self, line: &str) -> Result<Condition, QueryError> {
        let and_parts = split_top_level(line, '&');
        if and_parts.len() > 1 {
            let mut conditions = Vec::new();
            let mut all_valid = true;
            for part in &and_parts {
                match self.parse_atom(part) {
                    Ok(condition) => conditions.push(condition),
                    Err(_) => {
                        all_valid = false;
                        break;
                    }
                }
            }
            if all_valid {
                return Ok(Condition::And(conditions));
            }
        }
        self.parse_atom(line)
    }

    fn parse_atom(&self, atom: &str) -> Result<Condition, QueryError> {
        let atom = atom.trim();
        if atom.is_empty() {
            return Err(QueryError::InvalidLine(atom.to_owned()));
        }
        if atom.starts_with('(') {
            return match atom
                .strip_prefix('(')
                .and_then(|inner| inner.strip_suffix(')'))
            {
                Some(inner) => self.parse_line(inner.trim()),
                None => Err(QueryError::Unbalanced(atom.to_owned())),
            };
        }
        self.parse_field_line(atom)
    }

    fn parse_field_line(&self, line: &str) -> Result<Condition, QueryError> {
        let Some((field_name, rest)) = line.split_once(':') else {
            return Err(QueryError::InvalidLine(line.to_owned()));
        };
        let field_name = field_name.trim();
        let rest = rest.trim();

        let field =
            field(field_name).ok_or_else(|| QueryError::UnknownField(field_name.to_owned()))?;

        let operator = Regex::new(r"^(>=|<=|!=|>|<|=)(.*)$").expect("operator pattern is valid");
        if let Some(captures) = operator.captures(rest) {
            let op = captures.get(1).map(|m| m.as_str()).unwrap_or_default();
            let value = captures
                .get(2)
                .map(|m| m.as_str().trim())
                .unwrap_or_default();
            return self.apply_operator(field, op, value);
        }

        Ok(self.build_condition(field, rest))
    }

    fn build_condition(&self, field: Field, value: &str) -> Condition {
        let wildcard = Regex::new(WILDCARD_PATTERN).expect("wildcard pattern is valid");
        if wildcard.is_match(value) {
            let pattern = wildcard_to_regex(value);
            return field.regex(&pattern);
        }
        if matches!(
            field,
            Field {
                name: FieldName::Path
            }
        ) {
            return field.contains(value.to_owned());
        }
        if is_all_digits(value) {
            if let Ok(number) = value.parse::<i64>() {
                return field.eq(number);
            }
        }
        field.eq(value.to_owned())
    }

    fn apply_operator(&self, field: Field, op: &str, value: &str) -> Result<Condition, QueryError> {
        let number = if is_all_digits(value) {
            Some(
                value
                    .parse::<i64>()
                    .map_err(|_| QueryError::InvalidLine(value.to_owned()))?,
            )
        } else {
            None
        };

        let comparable = || number.ok_or_else(|| QueryError::InvalidLine(value.to_owned()));

        match op {
            "=" => Ok(match number {
                Some(number) => field.eq(number),
                None => field.eq(value.to_owned()),
            }),
            "!=" => Ok(match number {
                Some(number) => field.ne(number),
                None => field.ne(value.to_owned()),
            }),
            ">" => Ok(field.gt(comparable()?)),
            ">=" => Ok(field.ge(comparable()?)),
            "<" => Ok(field.lt(comparable()?)),
            "<=" => Ok(field.le(comparable()?)),
            _ => Err(QueryError::UnknownOperator(op.to_owned())),
        }
    }
}

fn is_all_digits(value: &str) -> bool {
    !value.is_empty() && value.chars().all(|ch| ch.is_ascii_digit())
}

fn wildcard_to_regex(value: &str) -> String {
    let mut out = String::from("^");
    for ch in value.chars() {
        match ch {
            '.' => out.push_str(r"\."),
            '*' => out.push_str(".*"),
            '?' => out.push('.'),
            other => out.push(other),
        }
    }
    out.push('$');
    out
}

#[cfg(test)]
mod tests {
    use super::HTTPQLParser;
    use api_tester_domain::{HttpFlow, HttpMethod};

    fn make_flow(method: HttpMethod, path: &str, status: u16) -> HttpFlow {
        let mut flow = HttpFlow::new(method, "api.example.com", path);
        flow.full_url = format!("https://api.example.com{path}");
        flow.response_status = status;
        flow
    }

    #[test]
    fn parse_method() {
        let condition = HTTPQLParser.parse("method:POST").unwrap();
        assert!(condition.matches(&make_flow(HttpMethod::Post, "/api/x", 200)));
        assert!(!condition.matches(&make_flow(HttpMethod::Get, "/api/x", 200)));
    }

    #[test]
    fn parse_path() {
        let condition = HTTPQLParser.parse("path:/api/").unwrap();
        assert!(condition.matches(&make_flow(HttpMethod::Get, "/api/users", 200)));
    }

    #[test]
    fn parse_status() {
        let condition = HTTPQLParser.parse("resp.status:>=400").unwrap();
        assert!(condition.matches(&make_flow(HttpMethod::Get, "/api/x", 500)));
        assert!(!condition.matches(&make_flow(HttpMethod::Get, "/api/x", 200)));
    }

    #[test]
    fn parse_multiple_lines() {
        let query = "method:GET\nresp.status:200";
        let condition = HTTPQLParser.parse(query).unwrap();
        assert!(condition.matches(&make_flow(HttpMethod::Get, "/api/x", 200)));
        assert!(!condition.matches(&make_flow(HttpMethod::Get, "/api/x", 404)));
    }

    #[test]
    fn parse_comment_skipped() {
        let query = "# comment\nmethod:GET";
        let condition = HTTPQLParser.parse(query).unwrap();
        assert!(condition.matches(&make_flow(HttpMethod::Get, "/api/x", 200)));
    }

    #[test]
    fn parse_or_within_line() {
        let condition = HTTPQLParser.parse("method:GET | method:POST").unwrap();
        assert!(condition.matches(&make_flow(HttpMethod::Post, "/api/x", 200)));
        assert!(!condition.matches(&make_flow(HttpMethod::Delete, "/api/x", 200)));
    }

    #[test]
    fn parse_grouped_expression() {
        let query = "(method:GET | method:POST) & resp.status:>=400";
        let condition = HTTPQLParser.parse(query).unwrap();
        assert!(condition.matches(&make_flow(HttpMethod::Post, "/api/x", 500)));
        assert!(!condition.matches(&make_flow(HttpMethod::Get, "/api/x", 200)));
        assert!(!condition.matches(&make_flow(HttpMethod::Delete, "/api/x", 500)));
    }

    #[test]
    fn parse_wildcard_path() {
        let condition = HTTPQLParser.parse("path:/api/*").unwrap();
        assert!(condition.matches(&make_flow(HttpMethod::Get, "/api/users", 200)));
        assert!(!condition.matches(&make_flow(HttpMethod::Get, "/other", 200)));
    }

    #[test]
    fn parse_literal_pipe_in_value() {
        let condition = HTTPQLParser.parse("path:/api/a|b").unwrap();
        let flow = make_flow(HttpMethod::Get, "/api/a|b", 200);
        assert!(condition.matches(&flow));
    }

    #[test]
    fn parse_literal_ampersand_in_value() {
        let condition = HTTPQLParser.parse("req.body:a&b").unwrap();
        let mut flow = make_flow(HttpMethod::Post, "/api/x", 200);
        flow.request_body = Some("a&b".to_owned());
        assert!(condition.matches(&flow));
    }

    #[test]
    fn parse_pipe_and_grouping_still_work() {
        let condition = HTTPQLParser.parse("method:GET | method:POST").unwrap();
        assert!(condition.matches(&make_flow(HttpMethod::Post, "/api/x", 200)));

        let grouped = HTTPQLParser
            .parse("(method:GET | method:POST) & resp.status:>=400")
            .unwrap();
        assert!(grouped.matches(&make_flow(HttpMethod::Post, "/api/x", 500)));
    }

    #[test]
    fn unknown_field_is_error() {
        assert!(HTTPQLParser.parse("bogus:value").is_err());
    }

    #[test]
    fn missing_colon_is_error() {
        assert!(HTTPQLParser.parse("method").is_err());
    }

    #[test]
    fn unbalanced_parentheses_is_error() {
        assert!(HTTPQLParser.parse("(method:GET").is_err());
        assert!(HTTPQLParser.parse("(method:GET | method:POST").is_err());
    }

    #[test]
    fn non_numeric_ordered_comparison_is_error() {
        assert!(HTTPQLParser.parse("resp.status:>=abc").is_err());
    }
}
