use api_tester_domain::ScopeConfig;
use regex::Regex;

use crate::error::ProxyError;

/// Target scope filtering, matching the Python reference semantics.
///
/// Semantics:
/// - `exclude_*` patterns win over `include_*` patterns.
/// - When `include_*` is non-empty, at least one pattern must match.
/// - Path patterns match against the path with the query string stripped.
pub struct ScopeFilter {
    include_hosts: Vec<Regex>,
    exclude_hosts: Vec<Regex>,
    include_paths: Vec<Regex>,
    exclude_paths: Vec<Regex>,
}

impl ScopeFilter {
    pub fn new(config: ScopeConfig) -> Result<Self, ProxyError> {
        Ok(Self {
            include_hosts: compile(&config.include_hosts)?,
            exclude_hosts: compile(&config.exclude_hosts)?,
            include_paths: compile(&config.include_paths)?,
            exclude_paths: compile(&config.exclude_paths)?,
        })
    }

    pub fn should_capture(&self, host: &str, path: &str) -> bool {
        self.host_matches(host) && self.path_matches(path)
    }

    fn host_matches(&self, host: &str) -> bool {
        if !self.exclude_hosts.is_empty() && self.exclude_hosts.iter().any(|re| re.is_match(host)) {
            return false;
        }
        if !self.include_hosts.is_empty() {
            return self.include_hosts.iter().any(|re| re.is_match(host));
        }
        true
    }

    fn path_matches(&self, path: &str) -> bool {
        let path_no_query = path.split('?').next().unwrap_or(path);
        if !self.exclude_paths.is_empty()
            && self
                .exclude_paths
                .iter()
                .any(|re| re.is_match(path_no_query))
        {
            return false;
        }
        if !self.include_paths.is_empty() {
            return self
                .include_paths
                .iter()
                .any(|re| re.is_match(path_no_query));
        }
        true
    }
}

fn compile(patterns: &[String]) -> Result<Vec<Regex>, ProxyError> {
    patterns
        .iter()
        .map(|pattern| Regex::new(pattern).map_err(|error| ProxyError::Regex(error.to_string())))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::ScopeFilter;
    use api_tester_domain::ScopeConfig;

    #[test]
    fn include_hosts_are_required_when_set() {
        let filter = ScopeFilter::new(ScopeConfig {
            include_hosts: vec!["example\\.com".to_owned()],
            ..ScopeConfig::default()
        })
        .unwrap();
        assert!(filter.should_capture("example.com", "/api"));
        assert!(!filter.should_capture("other.com", "/api"));
    }

    #[test]
    fn exclude_hosts_win_over_include() {
        let filter = ScopeFilter::new(ScopeConfig {
            include_hosts: vec!["example\\.com".to_owned()],
            exclude_hosts: vec!["ads\\.example\\.com".to_owned()],
            ..ScopeConfig::default()
        })
        .unwrap();
        assert!(filter.should_capture("example.com", "/"));
        assert!(!filter.should_capture("ads.example.com", "/"));
    }

    #[test]
    fn path_query_is_stripped_before_matching() {
        let filter = ScopeFilter::new(ScopeConfig {
            include_paths: vec![r".*\.json$".to_owned()],
            ..ScopeConfig::default()
        })
        .unwrap();
        assert!(filter.should_capture("example.com", "/data.json?v=1"));
        assert!(!filter.should_capture("example.com", "/data.txt"));
    }

    #[test]
    fn default_noise_paths_exclude_assets() {
        let filter = ScopeFilter::new(ScopeConfig::default()).unwrap();
        assert!(!filter.should_capture("example.com", "/app.js"));
        assert!(!filter.should_capture("example.com", "/img/logo.png"));
        assert!(filter.should_capture("example.com", "/api/login"));
    }

    #[test]
    fn default_allows_normal_traffic() {
        let filter = ScopeFilter::new(ScopeConfig::default()).unwrap();
        assert!(filter.should_capture("example.com", "/api/test"));
    }

    #[test]
    fn default_excludes_noise_hosts() {
        let filter = ScopeFilter::new(ScopeConfig::default()).unwrap();
        assert!(!filter.should_capture("google.com", "/"));
        assert!(!filter.should_capture("www.google-analytics.com", "/collect"));
    }

    #[test]
    fn excludes_static_with_query_string() {
        let filter = ScopeFilter::new(ScopeConfig::default()).unwrap();
        assert!(!filter.should_capture("example.com", "/app.js?v=123"));
        assert!(!filter.should_capture("example.com", "/style.css?ver=1.0"));
        assert!(!filter.should_capture("example.com", "/img/logo.png?size=100"));
        assert!(filter.should_capture("example.com", "/api/data?v=1"));
    }

    #[test]
    fn custom_exclude_path_pattern() {
        let filter = ScopeFilter::new(ScopeConfig {
            exclude_paths: vec![r".*\.(png|jpg|css)$".to_owned()],
            ..ScopeConfig::default()
        })
        .unwrap();
        assert!(filter.should_capture("example.com", "/api/data"));
        assert!(!filter.should_capture("example.com", "/style.css"));
        assert!(!filter.should_capture("example.com", "/img/logo.png"));
    }

    #[test]
    fn include_and_exclude_hosts() {
        let include = ScopeFilter::new(ScopeConfig {
            include_hosts: vec![r".*\.example\.com$".to_owned()],
            ..ScopeConfig::default()
        })
        .unwrap();
        assert!(include.should_capture("api.example.com", "/test"));
        assert!(!include.should_capture("google.com", "/test"));

        let exclude = ScopeFilter::new(ScopeConfig {
            exclude_hosts: vec![r".*\.google\.com$".to_owned()],
            ..ScopeConfig::default()
        })
        .unwrap();
        assert!(exclude.should_capture("example.com", "/test"));
        assert!(!exclude.should_capture("www.google.com", "/test"));
    }

    #[test]
    fn include_paths_and_combined_rules() {
        let filter = ScopeFilter::new(ScopeConfig {
            include_paths: vec![r"/api/.*".to_owned()],
            ..ScopeConfig::default()
        })
        .unwrap();
        assert!(filter.should_capture("example.com", "/api/users"));
        assert!(!filter.should_capture("example.com", "/static/page"));

        let combined = ScopeFilter::new(ScopeConfig {
            include_hosts: vec![r".*\.target\.com$".to_owned()],
            exclude_paths: vec![r".*\.js$".to_owned()],
            ..ScopeConfig::default()
        })
        .unwrap();
        assert!(combined.should_capture("api.target.com", "/data"));
        assert!(!combined.should_capture("api.target.com", "/bundle.js"));
        assert!(!combined.should_capture("other.com", "/data"));
    }
}
