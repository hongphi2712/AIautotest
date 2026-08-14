use thiserror::Error;

use api_tester_ports::PortError;

#[derive(Debug, Error)]
pub enum ScanError {
    #[error("transport error: {0}")]
    Transport(#[from] PortError),
    #[error("request timed out")]
    Timeout,
    #[error("target outside authorized scope ({host}{path}): set include_hosts to allow")]
    ScopeViolation { host: String, path: String },
    #[error("no explicit target allowlist: scope.include_hosts is empty")]
    NoTargetsAllowed,
    #[error("invalid scope configuration: {0}")]
    InvalidScope(String),
    #[error("login flow failed while preparing replay: {0}")]
    Auth(String),
}
