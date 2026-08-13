use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum DomainError {
    #[error("invalid domain value: {0}")]
    InvalidValue(String),
}
