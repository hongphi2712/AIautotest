use thiserror::Error;

use api_tester_ports::PortError;

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("no login flow configured")]
    NoLoginFlow,
    #[error("login step {0} failed: {1}")]
    StepFailed(usize, String),
    #[error("auth transport error: {0}")]
    Transport(#[from] PortError),
}
