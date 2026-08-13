use thiserror::Error;

#[derive(Debug, Error)]
pub enum ProxyError {
    #[error("invalid regex pattern: {0}")]
    Regex(String),
}
