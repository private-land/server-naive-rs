//! Transport layer for Naive proxy (TLS + HTTP/2)

mod h2;
mod tls;

pub use h2::H2Transport;
pub use tls::load_tls_config;
