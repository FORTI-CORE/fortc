use std::io;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum FortiCoreError {
    #[error("Network error: {0}")]
    NetworkError(String),

    #[error("Scan error: {0}")]
    ScanError(String),

    #[error("Exploit error: {0}")]
    ExploitError(String),

    #[error("Report generation error: {0}")]
    ReportError(String),

    #[error("Configuration error: {0}")]
    ConfigError(String),

    #[error("Input error: {0}")]
    InputError(String),

    #[error("IO error: {0}")]
    IoError(#[from] io::Error),

    #[error("Request error: {0}")]
    RequestError(#[from] reqwest::Error),

    #[error("JSON serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),

    #[error("Unknown error: {0}")]
    Unknown(String),
}

pub type FortiCoreResult<T> = Result<T, FortiCoreError>;
