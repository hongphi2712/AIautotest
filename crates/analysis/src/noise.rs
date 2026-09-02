//! Noise filtering for flow analysis: removes tracking/ads beacons and static
//! assets, strips query strings for display, and deduplicates repeated
//! identical requests so the generated diagram/flow code stays focused on the
//! actual application.

use std::collections::HashMap;

use api_tester_domain::HttpFlow;
use regex::Regex;
use std::sync::OnceLock;

/// Hosts that are always considered noise for flow generation (ads,
/// trackers, analytics, safe-browsing relays). Each pattern is matched as a
/// substring against the lower-cased host (so `e.dtscout.com` matches
/// `dtscout\.com`). Kept separate from `ScopeConfig` defaults so analysis stays
/// clean even when the proxy has captured those beacons.
const ANALYSIS_NOISE_HOST_PATTERNS: &[&str] = &[
    r"dtscout\.com",
    r"dtscdn\.com",
    r"adsrvr\.org",
    r"histats\.com",
    r"zeotap\.com",
    r"newshinyd\.com",
    r"safebrowsing",
    r"ohttp",
    // generic ad/tracking keyword fallback for hosts not explicitly listed
    r"doubleclick\.net",
    r"googletagmanager\.com",
    r"google-analytics\.com",
    r"facebook\.com",
    r"fbcdn\.net",
];

/// Path patterns that are noise for flow generation (static assets, Next.js
/// chunks, CRL, favicon). Mirrors the proxy `DEFAULT_NOISE_PATHS` but is
/// applied at analysis time so already-captured noise never pollutes the
/// generated flow.
const ANALYSIS_NOISE_PATH_PATTERNS: &[&str] = &[
    r".*\.(png|jpg|jpeg|gif|webp|svg|ico|jfif|css|js|woff2?|ttf|eot|map)(\?.*)?$",
    r"/_next/static/",
    r"/cdn-cgi/",
    r"favicon",
    r"beacon\.min\.js",
    r"/assets/generated/",
];

fn noise_host_regexes() -> &'static Vec<Regex> {
    static CELL: OnceLock<Vec<Regex>> = OnceLock::new();
    CELL.get_or_init(|| {
        ANALYSIS_NOISE_HOST_PATTERNS
            .iter()
            .map(|p| Regex::new(p).unwrap())
            .collect()
    })
}

fn noise_path_regexes() -> &'static Vec<Regex> {
    static CELL: OnceLock<Vec<Regex>> = OnceLock::new();
    CELL.get_or_init(|| {
        ANALYSIS_NOISE_PATH_PATTERNS
            .iter()
            .map(|p| Regex::new(p).unwrap())
            .collect()
    })
}

pub fn is_noise_host(host: &str) -> bool {
    let host = host.to_ascii_lowercase();
    noise_host_regexes().iter().any(|re| re.is_match(&host))
}

pub fn is_noise_path(path: &str) -> bool {
    let path_no_query = path.split('?').next().unwrap_or(path);
    noise_path_regexes()
        .iter()
        .any(|re| re.is_match(path_no_query))
}

pub fn is_noise(host: &str, path: &str) -> bool {
    is_noise_host(host) || is_noise_path(path)
}

pub fn filter_noise(flows: &[HttpFlow]) -> Vec<HttpFlow> {
    flows
        .iter()
        .filter(|flow| !is_noise(&flow.host, &flow.path))
        .cloned()
        .collect()
}

fn path_without_query(path: &str) -> &str {
    path.split('?').next().unwrap_or(path)
}

/// Filters flows for analysis: removes noise hosts/paths, strips query strings
/// is handled at display (the flow's `path` is left as-is so Python replay
/// keeps the original URL), and deduplicates repeated identical
/// `(method, path_without_query)` requests keeping the first occurrence.
pub fn filter_for_analysis(flows: &[HttpFlow]) -> Vec<HttpFlow> {
    let mut seen: HashMap<String, usize> = HashMap::new();
    let mut out = Vec::new();
    for flow in flows {
        if is_noise(&flow.host, &flow.path) {
            continue;
        }
        let key = format!(
            "{}:{}",
            flow.method.as_str(),
            path_without_query(&flow.path)
        );
        if seen.contains_key(&key) {
            continue;
        }
        seen.insert(key, out.len());
        out.push(flow.clone());
    }
    out
}

/// Like `filter_for_analysis` but also returns the occurrence count for each
/// deduped flow so the UI can show `×N`. Counts include the noise-filtered
/// duplicates that were collapsed.
pub fn filter_for_analysis_with_counts(flows: &[HttpFlow]) -> Vec<(HttpFlow, usize)> {
    let mut counts: HashMap<String, usize> = HashMap::new();
    let mut first: HashMap<String, HttpFlow> = HashMap::new();
    let mut order: Vec<String> = Vec::new();
    for flow in flows {
        if is_noise(&flow.host, &flow.path) {
            continue;
        }
        let key = format!(
            "{}:{}",
            flow.method.as_str(),
            path_without_query(&flow.path)
        );
        *counts.entry(key.clone()).or_insert(0) += 1;
        if !first.contains_key(&key) {
            first.insert(key.clone(), flow.clone());
            order.push(key);
        }
    }
    order
        .into_iter()
        .map(|key| {
            let count = counts[&key];
            let flow = first.remove(&key).unwrap();
            (flow, count)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{filter_for_analysis, filter_for_analysis_with_counts, is_noise};
    use api_tester_domain::{HttpFlow, HttpMethod};

    fn flow(host: &str, path: &str) -> HttpFlow {
        let mut f = HttpFlow::new(HttpMethod::Get, host, path);
        f.full_url = format!("https://{host}{path}");
        f.response_status = 200;
        f
    }

    #[test]
    fn noise_hosts_are_dropped() {
        assert!(is_noise("e.dtscout.com", "/"));
        assert!(is_noise("match.adsrvr.org", "/"));
        assert!(is_noise("s4.histats.com", "/"));
        assert!(is_noise("t.dtscdn.com", "/"));
        assert!(is_noise("spl.zeotap.com", "/"));
        assert!(!is_noise("fit.neu.edu.vn", "/codelab/api/auth/session"));
        assert!(!is_noise("api.example.com", "/api/login"));
    }

    #[test]
    fn static_paths_are_noise() {
        assert!(is_noise("fit.neu.edu.vn", "/_next/static/chunks/app.js"));
        assert!(is_noise("fit.neu.edu.vn", "/app.css?v=1"));
        assert!(is_noise("fit.neu.edu.vn", "/img/logo.png"));
        assert!(!is_noise("fit.neu.edu.vn", "/codelab/api/auth/session"));
    }

    #[test]
    fn filter_removes_noise_and_dedupes() {
        let flows = vec![
            flow("fit.neu.edu.vn", "/codelab/api/auth/session"),
            flow("fit.neu.edu.vn", "/codelab/api/auth/session"),
            flow("fit.neu.edu.vn", "/codelab/api/auth/session"),
            flow("e.dtscout.com", "/"),
            flow("fit.neu.edu.vn", "/?zdid=1332&zcluid=abc"),
            flow("fit.neu.edu.vn", "/?zdid=999&zcluid=xyz"),
            flow("fit.neu.edu.vn", "/_next/static/chunk.js"),
        ];
        let filtered = filter_for_analysis(&flows);
        // Only /codelab/api/auth/session and / (deduped) remain
        assert_eq!(filtered.len(), 2);
        assert!(
            filtered
                .iter()
                .any(|f| f.path == "/codelab/api/auth/session")
        );
        assert!(filtered.iter().any(|f| f.path == "/?zdid=1332&zcluid=abc"));
    }

    #[test]
    fn query_dedup_keeps_first_and_counts() {
        let flows = vec![
            flow(
                "fit.neu.edu.vn",
                "/codelab/api-backend/tags?limit=100&page=1",
            ),
            flow(
                "fit.neu.edu.vn",
                "/codelab/api-backend/tags?limit=100&page=2",
            ),
            flow(
                "fit.neu.edu.vn",
                "/codelab/api-backend/tags?limit=100&page=1",
            ),
        ];
        let with_counts = filter_for_analysis_with_counts(&flows);
        assert_eq!(with_counts.len(), 1);
        assert_eq!(with_counts[0].1, 3);
    }
}
