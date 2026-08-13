use thiserror::Error;

#[derive(Debug, Error)]
pub enum CaptureError {
    #[error(transparent)]
    Port(#[from] api_tester_ports::PortError),
}
