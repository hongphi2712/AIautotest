use std::collections::HashSet;
use std::sync::Mutex;

use api_tester_ports::HttpRequest;
use md5::compute;

const DEFAULT_DEDUP_LIMIT: usize = 100_000;

/// Bounds the number of distinct requests sent during a scan by dropping
/// requests that duplicate one already dispatched. The fingerprint set is
/// cleared when it grows too large, mirroring the capture dedup behaviour.
pub struct RequestDedup {
    seen: Mutex<HashSet<String>>,
    enabled: bool,
    limit: usize,
}

impl RequestDedup {
    pub fn new(enabled: bool) -> Self {
        Self::with_limit(enabled, DEFAULT_DEDUP_LIMIT)
    }

    pub fn with_limit(enabled: bool, limit: usize) -> Self {
        Self {
            seen: Mutex::new(HashSet::new()),
            enabled,
            limit: limit.max(1),
        }
    }

    /// Returns true when the request has not been seen before.
    pub fn first_seen(&self, request: &HttpRequest) -> bool {
        if !self.enabled {
            return true;
        }
        let fingerprint = fingerprint(request);
        let mut seen = self
            .seen
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        if seen.contains(&fingerprint) {
            return false;
        }
        if seen.len() >= self.limit {
            seen.clear();
        }
        seen.insert(fingerprint);
        true
    }
}

fn fingerprint(request: &HttpRequest) -> String {
    let body_hash = compute(request.body.as_deref().unwrap_or_default());
    format!("{}:{}:{body_hash:x}", request.method, request.url)
}

#[cfg(test)]
mod tests {
    use super::RequestDedup;
    use api_tester_ports::HttpRequest;

    fn request(url: &str) -> HttpRequest {
        HttpRequest {
            method: "GET".to_owned(),
            url: url.to_owned(),
            headers: vec![],
            body: None,
        }
    }

    #[test]
    fn duplicate_requests_are_dropped() {
        let dedup = RequestDedup::new(true);
        let request = request("http://a/b?x=1");
        assert!(dedup.first_seen(&request));
        assert!(!dedup.first_seen(&request));
    }

    #[test]
    fn disabled_dedup_never_drops() {
        let dedup = RequestDedup::new(false);
        let request = request("http://a/b");
        assert!(dedup.first_seen(&request));
        assert!(dedup.first_seen(&request));
    }

    #[test]
    fn different_body_is_distinct() {
        let dedup = RequestDedup::new(true);
        let mut first = request("http://a/b");
        first.body = Some(b"1".to_vec());
        let second = request("http://a/b");
        assert!(dedup.first_seen(&first));
        assert!(dedup.first_seen(&second));
    }
}
