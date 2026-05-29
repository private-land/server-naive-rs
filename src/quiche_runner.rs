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

    // A4 — Map config::CongestionControl variants to the strings quiche's
    // `CongestionControlAlgorithm::FromStr` accepts.  Validated against the
    // quiche 0.29 docs:
    //   Reno              -> "reno"
    //   CUBIC             -> "cubic"
    //   Bbr2Gcongestion   -> "bbr2_gcongestion"   (requires `gcongestion` feature)

    #[test]
    fn quiche_make_settings_bbr2_when_bbr_requested() {
        let settings = make_quiche_settings(&CongestionControl::Bbr);
        assert_eq!(
            settings.cc_algorithm, "bbr2_gcongestion",
            "CC::Bbr must map to BBRv2 from the gcongestion branch"
        );
    }

    #[test]
    fn quiche_make_settings_cubic_when_cubic_requested() {
        let settings = make_quiche_settings(&CongestionControl::Cubic);
        assert_eq!(settings.cc_algorithm, "cubic");
    }

    #[test]
    fn quiche_make_settings_reno_when_newreno_requested() {
        let settings = make_quiche_settings(&CongestionControl::NewReno);
        assert_eq!(settings.cc_algorithm, "reno");
    }
}
