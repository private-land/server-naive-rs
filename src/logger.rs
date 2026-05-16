use std::str::FromStr;
use tracing::level_filters::LevelFilter;
use tracing_subscriber::{fmt::time::LocalTime, layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LogLevel {
    Trace,
    Debug,
    #[default]
    Info,
    Warn,
    Error,
}

impl FromStr for LogLevel {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "trace" => Ok(LogLevel::Trace),
            "debug" => Ok(LogLevel::Debug),
            "info" => Ok(LogLevel::Info),
            "warn" => Ok(LogLevel::Warn),
            "error" => Ok(LogLevel::Error),
            _ => Err(()),
        }
    }
}

impl LogLevel {
    pub fn to_level_filter(self) -> LevelFilter {
        match self {
            LogLevel::Trace => LevelFilter::TRACE,
            LogLevel::Debug => LevelFilter::DEBUG,
            LogLevel::Info => LevelFilter::INFO,
            LogLevel::Warn => LevelFilter::WARN,
            LogLevel::Error => LevelFilter::ERROR,
        }
    }
}

const LOG_TIME_FORMAT: &[time::format_description::FormatItem<'static>] = time::macros::format_description!(
    "[year repr:last_two]-[month]-[day] [hour]:[minute]:[second]"
);

pub fn init_logger(log_level_str: &str) {
    let level = LogLevel::from_str(log_level_str).unwrap_or_default();

    let filter = tracing_subscriber::filter::Targets::new()
        .with_targets(vec![
            ("server_naive_rs", level.to_level_filter()),
            ("server", level.to_level_filter()),
        ])
        .with_default(LevelFilter::INFO);

    let registry = tracing_subscriber::registry();
    registry
        .with(filter)
        .with(
            tracing_subscriber::fmt::layer()
                .with_target(true)
                .with_timer(LocalTime::new(LOG_TIME_FORMAT)),
        )
        .init();
}

pub mod log {
    pub use tracing::{debug, error, info, warn};

    pub fn connection(addr: std::net::SocketAddr, event: &str) {
        debug!(peer = %addr, event = event, "Connection");
    }

    pub fn authentication(addr: std::net::SocketAddr, success: bool) {
        if success {
            debug!(peer = %addr, "Authentication successful");
        } else {
            debug!(peer = %addr, "Authentication failed");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log_level_from_str_valid() {
        assert_eq!(LogLevel::from_str("trace"), Ok(LogLevel::Trace));
        assert_eq!(LogLevel::from_str("debug"), Ok(LogLevel::Debug));
        assert_eq!(LogLevel::from_str("info"), Ok(LogLevel::Info));
        assert_eq!(LogLevel::from_str("warn"), Ok(LogLevel::Warn));
        assert_eq!(LogLevel::from_str("error"), Ok(LogLevel::Error));
    }

    #[test]
    fn test_log_level_from_str_case_insensitive() {
        assert_eq!(LogLevel::from_str("TRACE"), Ok(LogLevel::Trace));
        assert_eq!(LogLevel::from_str("DEBUG"), Ok(LogLevel::Debug));
        assert_eq!(LogLevel::from_str("INFO"), Ok(LogLevel::Info));
    }

    #[test]
    fn test_log_level_from_str_invalid() {
        assert!(LogLevel::from_str("invalid").is_err());
        assert!(LogLevel::from_str("").is_err());
    }

    #[test]
    fn test_log_level_default() {
        assert_eq!(LogLevel::default(), LogLevel::Info);
    }

    #[test]
    fn test_log_time_format_is_valid() {
        use time::OffsetDateTime;
        let now = OffsetDateTime::now_utc();
        let formatted = now.format(LOG_TIME_FORMAT);
        assert!(formatted.is_ok());
    }
}
