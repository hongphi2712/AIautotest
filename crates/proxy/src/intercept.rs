use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use serde::{Deserialize, Serialize};
use tokio::sync::oneshot;

/// A single header name/value pair used to exchange intercepted request and
/// response data with the UI. Preserves duplicates (e.g. multiple
/// `Set-Cookie` headers) and ordering.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InterceptHeader {
    pub name: String,
    pub value: String,
}

/// A request or response currently held for inspection/editing in the UI.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InterceptEntry {
    pub id: String,
    /// `"request"` or `"response"`.
    pub kind: String,
    pub method: String,
    pub url: String,
    pub status: Option<u16>,
    pub reason: Option<String>,
    pub headers: Vec<InterceptHeader>,
    pub body: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

/// User-edited fields applied when an intercepted request/response is
/// forwarded.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InterceptEdit {
    pub method: String,
    pub url: String,
    pub status: Option<u16>,
    pub reason: Option<String>,
    pub headers: Vec<InterceptHeader>,
    pub body: String,
}

/// What the proxy does with an intercepted item once the UI has acted.
pub enum InterceptDecision {
    /// Forward (possibly edited). `None` forwards the item unchanged.
    Forward(Option<InterceptEdit>),
    /// Abandon the item and close the client connection.
    Drop,
}

struct Pending {
    tx: Option<oneshot::Sender<InterceptDecision>>,
}

/// Holds intercepted requests/responses until the UI forwards or drops them.
///
/// The proxy task that hit an intercept point awaits its own `oneshot`
/// receiver (there is intentionally no timeout). `clear_all` is invoked on
/// proxy shutdown so paused tasks are released instead of hanging.
pub struct InterceptController {
    enabled: AtomicBool,
    intercept_requests: AtomicBool,
    intercept_responses: AtomicBool,
    pending: Mutex<HashMap<String, Pending>>,
    queue: Mutex<Vec<InterceptEntry>>,
}

impl Default for InterceptController {
    fn default() -> Self {
        Self {
            enabled: AtomicBool::new(false),
            // Both scopes default ON (Burp-style): flipping `enabled` alone
            // pauses requests and responses.
            intercept_requests: AtomicBool::new(true),
            intercept_responses: AtomicBool::new(true),
            pending: Mutex::new(HashMap::new()),
            queue: Mutex::new(Vec::new()),
        }
    }
}

impl InterceptController {
    pub fn set_enabled(&self, enabled: bool) {
        self.enabled.store(enabled, Ordering::SeqCst);
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::SeqCst)
    }

    pub fn set_intercept_requests(&self, enabled: bool) {
        self.intercept_requests.store(enabled, Ordering::SeqCst);
    }

    pub fn intercept_requests_enabled(&self) -> bool {
        self.intercept_requests.load(Ordering::SeqCst)
    }

    pub fn set_intercept_responses(&self, enabled: bool) {
        self.intercept_responses.store(enabled, Ordering::SeqCst);
    }

    pub fn intercept_responses_enabled(&self) -> bool {
        self.intercept_responses.load(Ordering::SeqCst)
    }

    pub fn should_intercept_request(&self) -> bool {
        self.is_enabled() && self.intercept_requests_enabled()
    }

    pub fn should_intercept_response(&self) -> bool {
        self.is_enabled() && self.intercept_responses_enabled()
    }

    /// Registers an intercepted item and returns the receiver the proxy task
    /// awaits until `forward`/`drop`/`clear_all` fires.
    pub fn enqueue(&self, entry: InterceptEntry) -> oneshot::Receiver<InterceptDecision> {
        let (tx, rx) = oneshot::channel();
        let id = entry.id.clone();
        self.pending
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .insert(id, Pending { tx: Some(tx) });
        self.queue
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .push(entry);
        rx
    }

    /// Blocks (no timeout) until the UI forwards or drops the item. A dropped
    /// controller falls back to forwarding the item unchanged.
    pub async fn wait_for_decision(rx: oneshot::Receiver<InterceptDecision>) -> InterceptDecision {
        rx.await.unwrap_or(InterceptDecision::Forward(None))
    }

    /// Items currently held, in arrival order.
    pub fn list(&self) -> Vec<InterceptEntry> {
        self.queue
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .clone()
    }

    pub fn len(&self) -> usize {
        self.pending
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn forward(&self, id: &str, edit: Option<InterceptEdit>) -> bool {
        let mut pending = self
            .pending
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        if let Some(p) = pending.remove(id) {
            if let Some(tx) = p.tx {
                let _ = tx.send(InterceptDecision::Forward(edit));
            }
            self.queue
                .lock()
                .unwrap_or_else(|poison| poison.into_inner())
                .retain(|entry| entry.id != id);
            true
        } else {
            false
        }
    }

    pub fn drop_item(&self, id: &str) -> bool {
        let mut pending = self
            .pending
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        if let Some(p) = pending.remove(id) {
            if let Some(tx) = p.tx {
                let _ = tx.send(InterceptDecision::Drop);
            }
            self.queue
                .lock()
                .unwrap_or_else(|poison| poison.into_inner())
                .retain(|entry| entry.id != id);
            true
        } else {
            false
        }
    }

    /// Releases every held item with a Drop. Used when the proxy stops.
    pub fn clear_all(&self) {
        let senders = self
            .pending
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .drain()
            .map(|(_, p)| p.tx)
            .collect::<Vec<_>>();
        for tx in senders.into_iter().flatten() {
            let _ = tx.send(InterceptDecision::Drop);
        }
        self.queue
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .clear();
    }
}

/// Converts a `HeaderMap` into ordered `(name, value)` pairs preserving
/// duplicates.
pub fn headers_to_intercept(headers: &http::HeaderMap) -> Vec<InterceptHeader> {
    let mut out = Vec::new();
    for name in headers.keys() {
        for value in headers.get_all(name) {
            out.push(InterceptHeader {
                name: name.as_str().to_owned(),
                value: String::from_utf8_lossy(value.as_bytes()).into_owned(),
            });
        }
    }
    out
}

/// Rebuilds a `HeaderMap` from an ordered list of `(name, value)` pairs,
/// skipping empty names.
pub fn headers_from_intercept(headers: &[InterceptHeader]) -> http::HeaderMap {
    let mut map = http::HeaderMap::new();
    for header in headers {
        let name = header.name.trim();
        if name.is_empty() {
            continue;
        }
        let Ok(name) = http::header::HeaderName::from_bytes(name.as_bytes()) else {
            continue;
        };
        if let Ok(value) = http::HeaderValue::from_str(&header.value) {
            map.append(name, value);
        }
    }
    map
}

/// Parses an edited URL into `(scheme, host, path)` where `host` may include
/// a port. Returns `None` when the URL cannot be parsed.
pub fn parse_edited_url(url: &str) -> Option<(String, String, String)> {
    let uri = url.parse::<http::Uri>().ok()?;
    let scheme = uri.scheme_str()?.to_owned();
    let host = uri.authority()?.as_str().to_owned();
    let path = uri
        .path_and_query()
        .map(|query| query.as_str().to_owned())
        .unwrap_or_else(|| "/".to_owned());
    Some((scheme, host, path))
}

#[cfg(test)]
mod tests {
    use super::{
        InterceptController, InterceptHeader, headers_from_intercept, headers_to_intercept,
        parse_edited_url,
    };

    #[test]
    fn defaults_intercept_both_scopes_when_disabled() {
        let controller = InterceptController::default();
        assert!(!controller.is_enabled());
        assert!(controller.intercept_requests_enabled());
        assert!(controller.intercept_responses_enabled());
        assert!(!controller.should_intercept_request());
        assert!(!controller.should_intercept_response());
        controller.set_enabled(true);
        assert!(controller.should_intercept_request());
        assert!(controller.should_intercept_response());
    }

    #[test]
    fn round_trips_headers_preserving_duplicates() {
        let mut map = http::HeaderMap::new();
        map.append("set-cookie", http::HeaderValue::from_static("a=1"));
        map.append("set-cookie", http::HeaderValue::from_static("b=2"));
        map.insert("content-type", http::HeaderValue::from_static("text/html"));

        let list = headers_to_intercept(&map);
        assert_eq!(list.len(), 3);
        let mut sorted = list.clone();
        sorted.sort_by(|left, right| (&left.name, &left.value).cmp(&(&right.name, &right.value)));
        assert_eq!(
            sorted,
            vec![
                InterceptHeader {
                    name: "content-type".into(),
                    value: "text/html".into()
                },
                InterceptHeader {
                    name: "set-cookie".into(),
                    value: "a=1".into()
                },
                InterceptHeader {
                    name: "set-cookie".into(),
                    value: "b=2".into()
                },
            ]
        );

        let rebuilt = headers_from_intercept(&list);
        let cookies = rebuilt
            .get_all("set-cookie")
            .iter()
            .map(|value| value.to_str().unwrap_or_default())
            .collect::<Vec<_>>();
        assert_eq!(cookies, vec!["a=1", "b=2"]);
    }

    #[test]
    fn parses_urls_with_and_without_port() {
        assert_eq!(
            parse_edited_url("https://example.com:8443/api/orders?q=1"),
            Some((
                "https".into(),
                "example.com:8443".into(),
                "/api/orders?q=1".into()
            ))
        );
        assert_eq!(
            parse_edited_url("http://example.com/"),
            Some(("http".into(), "example.com".into(), "/".into()))
        );
        assert_eq!(parse_edited_url("not a url"), None);
    }
}
