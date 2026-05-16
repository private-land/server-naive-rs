use std::io;
use thiserror::Error;

#[derive(Error, Debug)]
#[allow(dead_code)]
pub enum NaiveError {
    #[error("IO error: {0}")]
    Io(#[from] io::Error),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Protocol parse error: {0}")]
    ProtocolParse(String),

    #[error("Authentication error: {0}")]
    Authentication(String),

    #[error("TLS error: {0}")]
    Tls(String),

    #[error("Network connection error: {0}")]
    Connection(String),

    #[error("Transport error: {0}")]
    Transport(String),

    #[error("{0}")]
    Other(String),
}

#[allow(dead_code)]
pub type Result<T> = std::result::Result<T, NaiveError>;

impl From<anyhow::Error> for NaiveError {
    fn from(err: anyhow::Error) -> Self {
        NaiveError::Other(err.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_io_error_display() {
        let io_err = io::Error::new(io::ErrorKind::NotFound, "file not found");
        let err: NaiveError = io_err.into();
        assert!(format!("{}", err).contains("IO error"));
    }

    #[test]
    fn test_config_error_display() {
        let err = NaiveError::Config("invalid port".to_string());
        assert!(format!("{}", err).contains("Configuration error"));
    }

    #[test]
    fn test_authentication_error_display() {
        let err = NaiveError::Authentication("invalid password".to_string());
        assert!(format!("{}", err).contains("Authentication error"));
    }

    #[test]
    fn test_from_anyhow_error() {
        let anyhow_err = anyhow::anyhow!("some anyhow error");
        let err: NaiveError = anyhow_err.into();
        assert!(format!("{}", err).contains("some anyhow error"));
    }
}
