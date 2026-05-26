// Public API — only what examples and integration tests need.
// Internal modules stay pub(crate) to prevent accidental external coupling.
pub mod config;
pub mod core;
pub mod logger;
pub mod server_runner;
pub mod transport;

pub(crate) mod acl;
pub(crate) mod business;
pub(crate) mod config_auto;
pub(crate) mod error;
pub(crate) mod handler;
pub(crate) mod net;
pub(crate) mod uot;
