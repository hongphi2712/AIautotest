use api_tester_domain::ScopeFilter;

use crate::error::ScanError;

/// Enforces the security guardrail: mutations are only sent inside the
/// authorized scope. The scanner refuses to run without an explicit target
/// allowlist (`include_hosts`).
pub struct ScopeGuard {
    filter: ScopeFilter,
}

impl ScopeGuard {
    pub fn new(filter: ScopeFilter) -> Self {
        Self { filter }
    }

    pub fn check(&self, host: &str, path: &str) -> bool {
        self.filter.should_capture(host, path)
    }
}

/// Validates that an explicit allowlist exists before a scan starts.
pub fn require_allowlist(scope: &api_tester_domain::ScopeConfig) -> Result<(), ScanError> {
    if scope.include_hosts.is_empty() {
        return Err(ScanError::NoTargetsAllowed);
    }
    Ok(())
}
