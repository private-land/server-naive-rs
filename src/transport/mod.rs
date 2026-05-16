//! Transport layer for Naive proxy (TLS + HTTP/2 and HTTP/3 over QUIC)

mod h2;
mod h3;
mod padding;
mod tls;

pub use h2::H2Transport;
pub use h3::H3Transport;
pub use padding::{generate_padding_header, NaivePaddedTransport};
pub use tls::{load_h3_tls_config, load_tls_config};
