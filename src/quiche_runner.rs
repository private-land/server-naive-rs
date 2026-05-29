//! H3/QUIC accept loop built on tokio-quiche (PoC migration; see plan
//! `quiet-tinkering-raven.md`).
//!
//! This module sits alongside `server_runner.rs` during the PoC: the runtime
//! `--h3_backend` CLI flag selects between the legacy quinn+h3 path
//! ([`crate::server_runner::run_h3_server`]) and the new tokio-quiche path
//! ([`run_h3_server_quiche`]).
//!
//! The current step (A3) is just the `make_quiche_settings` builder.

use crate::config;
use tokio_quiche::settings::QuicSettings;

/// Build a `QuicSettings` for the tokio-quiche server, mirroring the tuning
/// `server_runner::make_transport_config` applies to the quinn `TransportConfig`.
///
/// Returned as a free function so unit tests can exercise every CC variant
/// without spinning up a real QUIC endpoint.
#[allow(dead_code)] // wired into runtime starting in A5; kept allow until then.
pub fn make_quiche_settings(_cc: &config::CongestionControl) -> QuicSettings {
    // `QuicSettings` is `#[non_exhaustive]`, so we start from Default and
    // overwrite only the fields we care about.  tokio-quiche already defaults
    // `alpn` to `[b"h3"]`, but we set it explicitly to document the contract:
    // a regression that nukes the field would still fail A3 here.
    let mut settings = QuicSettings::default();
    settings.alpn = vec![b"h3".to_vec()];
    settings
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::CongestionControl;

    /// A3 — The H3 backend must advertise ALPN `h3` so QUIC clients (cronet,
    /// sing-box, quinn) can negotiate the H3 protocol on the connection.
    #[test]
    fn quiche_make_settings_alpn_h3() {
        let settings = make_quiche_settings(&CongestionControl::Cubic);
        assert_eq!(
            settings.alpn,
            vec![b"h3".to_vec()],
            "QUIC settings must advertise ALPN h3"
        );
    }
}
