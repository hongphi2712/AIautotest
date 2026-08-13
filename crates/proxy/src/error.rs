use thiserror::Error;

#[derive(Debug, Error)]
pub enum ProxyError {
    #[error("invalid regex pattern: {0}")]
    Regex(String),
    #[error("certificate error: {0}")]
    Cert(String),
    #[error("upstream error: {0}")]
    Upstream(String),
    #[error("proxy error: {0}")]
    Runtime(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}
