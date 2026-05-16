//! Transport layer for Naive proxy (TLS + HTTP/2)

mod h2;
mod padding;
mod tls;

pub use h2::H2Transport;
pub use padding::{generate_padding_header, NaivePaddedH2Transport};
pub use tls::load_tls_config;
