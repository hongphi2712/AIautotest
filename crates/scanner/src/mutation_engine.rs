use std::sync::Arc;

use api_tester_domain::{AnalyzedParam, HttpFlow, InjectionLocation, Payload};
use api_tester_ports::HttpRequest;
use serde_json::Value;
use url::Url;

use crate::payload_source::{PayloadSource, PayloadTemplate};

/// A single mutated request plus the parameter and payload that produced it.
#[derive(Debug, Clone)]
pub struct Mutation {
    pub request: HttpRequest,
    pub param: AnalyzedParam,
    pub payload: Payload,
}

/// Builds mutated requests by injecting payloads into parameter locations
/// (query, JSON body, header, path).
pub struct MutationEngine {
    source: Arc<dyn PayloadSource>,
    limit_per_param: usize,
}

impl MutationEngine {
    pub fn new(source: Arc<dyn PayloadSource>, limit_per_param: usize) -> Self {
        Self {
            source,
            limit_per_param: limit_per_param.max(1),
        }
    }

    pub fn mutations_for(
        &self,
        flow: &HttpFlow,
        params: &[AnalyzedParam],
        skills: &[String],
    ) -> Vec<Mutation> {
        let mut out = Vec::new();
        for param in params {
            for skill in skills {
                for template in self.source.payloads_for(skill) {
                    if out.len() >= self.limit_per_param * params.len() {
                        return out;
                    }
                    out.push(self.mutate(flow, param, skill, &template));
                }
            }
        }
        out
    }

    fn mutate(
        &self,
        flow: &HttpFlow,
        param: &AnalyzedParam,
        skill: &str,
        template: &PayloadTemplate,
    ) -> Mutation {
        let payload = Payload {
            value: template.value.clone(),
            location: param.location.clone(),
            param_name: param.name.clone(),
            skill_name: skill.to_owned(),
            description: template.description.clone(),
        };
        let request = match param.location {
            InjectionLocation::Query => self.mutate_query(flow, &param.name, &template.value),
            InjectionLocation::BodyJson => {
                self.mutate_json_body(flow, &param.name, &template.value)
            }
            InjectionLocation::Header => self.mutate_header(flow, &param.name, &template.value),
            InjectionLocation::Path => self.mutate_path(flow, &param.sample_value, &template.value),
            InjectionLocation::BodyForm | InjectionLocation::Cookie => {
                self.mutate_header(flow, &param.name, &template.value)
            }
        };
        Mutation {
            request,
            param: param.clone(),
            payload,
        }
    }

    fn base_request(flow: &HttpFlow) -> HttpRequest {
        HttpRequest {
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
        }
    }

    fn mutate_query(&self, flow: &HttpFlow, name: &str, value: &str) -> HttpRequest {
        let mut request = Self::base_request(flow);
        let Some(mut url) = parse_url(&request.url) else {
            return request;
        };
        let mut pairs: Vec<(String, String)> = url
            .query_pairs()
            .map(|(key, val)| (key.into_owned(), val.into_owned()))
            .collect();
        if let Some(pair) = pairs.iter_mut().find(|(key, _)| key == name) {
            pair.1 = value.to_owned();
        } else {
            pairs.push((name.to_owned(), value.to_owned()));
        }
        url.set_query(None);
        let mut serializer = url::form_urlencoded::Serializer::new(String::new());
        for (key, val) in &pairs {
            serializer.append_pair(key, val);
        }
        url.set_query(Some(&serializer.finish()));
        request.url = url.to_string();
        request
    }

    fn mutate_json_body(&self, flow: &HttpFlow, name: &str, value: &str) -> HttpRequest {
        let mut request = Self::base_request(flow);
        if let Some(body) = request.body.take() {
            match serde_json::from_slice::<Value>(&body) {
                Ok(mut json) => {
                    set_json_path(&mut json, name, Value::String(value.to_owned()));
                    request.body = Some(serde_json::to_vec(&json).unwrap_or(body));
                }
                Err(_) => request.body = Some(body),
            }
        }
        if !request
            .headers
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case("content-type"))
        {
            request
                .headers
                .push(("Content-Type".to_owned(), "application/json".to_owned()));
        }
        request
    }

    fn mutate_header(&self, flow: &HttpFlow, name: &str, value: &str) -> HttpRequest {
        let mut request = Self::base_request(flow);
        request
            .headers
            .retain(|(key, _)| !key.eq_ignore_ascii_case(name));
        request.headers.push((name.to_owned(), value.to_owned()));
        request
    }

    fn mutate_path(
        &self,
        flow: &HttpFlow,
        sample_value: &Option<Value>,
        value: &str,
    ) -> HttpRequest {
        let mut request = Self::base_request(flow);
        if let Some(Value::String(sample)) = sample_value {
            if !sample.is_empty() {
                if let Some(mut url) = parse_url(&request.url) {
                    let new_path = url.path().replace(sample, value);
                    url.set_path(&new_path);
                    request.url = url.to_string();
                }
            }
        }
        request
    }
}

fn parse_url(full_url: &str) -> Option<Url> {
    Url::parse(full_url).ok().or_else(|| {
        let base = Url::parse("http://invalid.local").ok()?;
        Url::options().base_url(Some(&base)).parse(full_url).ok()
    })
}

enum PathSegment {
    Key(String),
    Index(usize),
}

fn parse_path(path: &str) -> Vec<PathSegment> {
    let mut segments = Vec::new();
    let mut chars = path.chars().peekable();
    let mut buffer = String::new();
    while let Some(ch) = chars.next() {
        match ch {
            '.' => {
                if !buffer.is_empty() {
                    segments.push(PathSegment::Key(std::mem::take(&mut buffer)));
                }
            }
            '[' => {
                if !buffer.is_empty() {
                    segments.push(PathSegment::Key(std::mem::take(&mut buffer)));
                }
                let mut index = String::new();
                while let Some(&next) = chars.peek() {
                    if next == ']' {
                        chars.next();
                        break;
                    }
                    index.push(next);
                    chars.next();
                }
                if let Ok(parsed) = index.parse::<usize>() {
                    segments.push(PathSegment::Index(parsed));
                }
            }
            other => buffer.push(other),
        }
    }
    if !buffer.is_empty() {
        segments.push(PathSegment::Key(buffer));
    }
    segments
}

/// Sets `root[key.path] = value`, supporting dotted keys and `[n]` indices.
pub(crate) fn set_json_path(root: &mut Value, path: &str, value: Value) {
    let segments = parse_path(path);
    let mut current = root;
    for (index, segment) in segments.iter().enumerate() {
        let last = index == segments.len() - 1;
        if last {
            apply_leaf(current, segment, &value);
            return;
        }
        match descend(current, segment) {
            Some(next) => current = next,
            None => return,
        }
    }
}

fn apply_leaf(current: &mut Value, segment: &PathSegment, value: &Value) {
    match segment {
        PathSegment::Key(key) => {
            if let Some(object) = current.as_object_mut() {
                object.insert(key.clone(), value.clone());
            }
        }
        PathSegment::Index(index) => {
            if let Some(array) = current.as_array_mut() {
                if let Some(slot) = array.get_mut(*index) {
                    *slot = value.clone();
                }
            }
        }
    }
}

fn descend<'a>(current: &'a mut Value, segment: &PathSegment) -> Option<&'a mut Value> {
    match segment {
        PathSegment::Key(key) => {
            let object = current.as_object_mut()?;
            if !object.contains_key(key) {
                object.insert(key.clone(), Value::Object(Default::default()));
            }
            object.get_mut(key)
        }
        PathSegment::Index(index) => {
            let array = current.as_array_mut()?;
            if array.len() <= *index {
                array.resize(*index + 1, Value::Null);
            }
            Some(&mut array[*index])
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{MutationEngine, set_json_path};
    use crate::payload_source::BuiltinPayloadSource;
    use api_tester_domain::{AnalyzedParam, HttpFlow, HttpMethod, InjectionLocation, ParamType};
    use serde_json::json;
    use std::sync::Arc;

    fn query_param_flow() -> HttpFlow {
        let mut flow = HttpFlow::new(HttpMethod::Get, "127.0.0.1", "/api/x");
        flow.full_url = "http://127.0.0.1/api/x?q=value&id=7".to_owned();
        flow
    }

    fn param(name: &str, location: InjectionLocation) -> AnalyzedParam {
        AnalyzedParam {
            name: name.to_owned(),
            param_type: ParamType::String,
            location,
            sample_value: Some(json!("value")),
            enum_values: vec![],
        }
    }

    #[test]
    fn query_param_is_percent_encoded() {
        let source = Arc::new(BuiltinPayloadSource);
        let engine = MutationEngine::new(source, 20);
        let mutations = engine.mutations_for(
            &query_param_flow(),
            &[param("q", InjectionLocation::Query)],
            &["sqli".to_owned()],
        );
        assert_eq!(mutations.len(), 6);
        let first = &mutations[0];
        assert_eq!(first.payload.param_name, "q");
        assert!(
            first.request.url.contains("%27"),
            "payload must be encoded, got {}",
            first.request.url
        );
    }

    #[test]
    fn json_body_param_is_replaced() {
        let mut flow = HttpFlow::new(HttpMethod::Post, "127.0.0.1", "/api/x");
        flow.full_url = "http://127.0.0.1/api/x".to_owned();
        flow.request_body = Some(r#"{"user":{"id":1}}"#.to_owned());
        flow.request_headers
            .insert("content-type".to_owned(), "application/json".to_owned());
        let source = Arc::new(BuiltinPayloadSource);
        let engine = MutationEngine::new(source, 20);
        let mutations = engine.mutations_for(
            &flow,
            &[param("user.id", InjectionLocation::BodyJson)],
            &["xss".to_owned()],
        );
        let first = &mutations[0];
        let body = String::from_utf8_lossy(first.request.body.as_deref().unwrap_or_default());
        assert!(
            body.contains("user") && body.contains("id"),
            "body should keep the JSON shape, got {body}"
        );
    }

    #[test]
    fn header_param_is_replaced() {
        let mut flow = query_param_flow();
        flow.request_headers
            .insert("Authorization".to_owned(), "Bearer old".to_owned());
        let source = Arc::new(BuiltinPayloadSource);
        let engine = MutationEngine::new(source, 20);
        let mutations = engine.mutations_for(
            &flow,
            &[param("authorization", InjectionLocation::Header)],
            &["auth_bypass".to_owned()],
        );
        let first = &mutations[0];
        let header = first
            .request
            .headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("authorization"))
            .map(|(_, value)| value.as_str());
        assert_eq!(header, Some("admin"));
    }

    #[test]
    fn path_param_replaced_without_touching_host() {
        let mut flow = HttpFlow::new(HttpMethod::Get, "127.0.0.1", "/api/users/123");
        flow.full_url = "http://127.0.0.1/api/users/123".to_owned();
        let source = Arc::new(BuiltinPayloadSource);
        let engine = MutationEngine::new(source, 20);
        let params = vec![AnalyzedParam {
            name: "path_param".to_owned(),
            param_type: ParamType::Id,
            location: InjectionLocation::Path,
            sample_value: Some(json!("123")),
            enum_values: vec![],
        }];
        let mutations = engine.mutations_for(&flow, &params, &["sqli".to_owned()]);
        let first = &mutations[0];
        assert!(
            first.request.url.starts_with("http://127.0.0.1"),
            "host must be preserved, got {}",
            first.request.url
        );
        assert!(
            first.request.url.contains("/api/users/"),
            "path must keep structure, got {}",
            first.request.url
        );
    }

    #[test]
    fn sets_dotted_path() {
        let mut value = json!({"user": {"id": 1}});
        set_json_path(&mut value, "user.id", json!("payload"));
        assert_eq!(value, json!({"user": {"id": "payload"}}));
    }

    #[test]
    fn creates_missing_object() {
        let mut value = json!({});
        set_json_path(&mut value, "a.b.c", json!(1));
        assert_eq!(value, json!({"a": {"b": {"c": 1}}}));
    }

    #[test]
    fn sets_array_index_path() {
        let mut value = json!({"items": [{"name": "a"}]});
        set_json_path(&mut value, "items[0].name", json!("payload"));
        assert_eq!(value, json!({"items": [{"name": "payload"}]}));
    }
}
