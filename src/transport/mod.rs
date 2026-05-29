//! Transport layer for Naive proxy (TLS + HTTP/2 and HTTP/3 over QUIC)

mod padding;
pub(crate) mod pingora_session;
pub(crate) mod quiche_stream;
pub(crate) mod quiche_tls;

pub use padding::{generate_padding_header, NaivePaddedTransport};
