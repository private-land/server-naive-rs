//! Business logic implementations
//!
//! Thin wrappers bridging panel-core types to core::hooks traits.
//! The key difference from Trojan: Naive uses UUID strings as auth keys
//! (no SHA-224 hashing), so UserManager<String> with identity derive_key.

use std::sync::Arc;

use crate::core::hooks::{Authenticator, StatsCollector};
use crate::core::UserId;

pub use panel_core::{
    BackgroundTasks, NodeConfigEnum, NodeType, PanelApi, StatsCollector as PanelStatsCollector,
    TaskConfig, UserManager,
};
pub use panel_http::{HttpApiManager as ApiManager, HttpPanelConfig as PanelConfig, IpVersion};

/// Naive-specific UserManager using UUID strings as keys directly.
pub type NaiveUserManager = UserManager<String>;

/// Naive authenticator wrapping panel-core's UserManager.
///
/// Authenticates by matching the HTTP Basic Auth password (UUID) against the
/// user map. No hashing — the credential is the raw UUID string.
pub struct NaiveAuthenticator(pub Arc<NaiveUserManager>);

impl Authenticator for NaiveAuthenticator {
    fn authenticate(&self, credential: &str) -> Option<UserId> {
        self.0.authenticate(&credential.to_string())
    }
}

/// Naive stats collector wrapping panel-core's StatsCollector.
pub struct NaiveStatsCollector(pub Arc<PanelStatsCollector>);

impl StatsCollector for NaiveStatsCollector {
    fn record_request(&self, user_id: UserId) {
        self.0.record_request(user_id);
    }

    fn record_upload(&self, user_id: UserId, bytes: u64) {
        self.0.record_upload(user_id, bytes);
    }

    fn record_download(&self, user_id: UserId, bytes: u64) {
        self.0.record_download(user_id, bytes);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_naive_authenticator_empty() {
        let user_manager = Arc::new(NaiveUserManager::new(|uuid: &str| uuid.to_string()));
        let auth = NaiveAuthenticator(user_manager);
        assert_eq!(auth.authenticate("some-uuid-that-doesnt-exist"), None);
    }

    #[test]
    fn test_naive_authenticator_with_users() {
        let user_manager = Arc::new(NaiveUserManager::new(|uuid: &str| uuid.to_string()));
        let users = vec![panel_core::User {
            id: 42,
            uuid: "test-uuid-123".to_string(),
        }];
        user_manager.init(&users);

        let auth = NaiveAuthenticator(Arc::clone(&user_manager));
        assert_eq!(auth.authenticate("test-uuid-123"), Some(42));
        assert_eq!(auth.authenticate("wrong-uuid"), None);
    }

    #[test]
    fn test_naive_stats_collector() {
        let panel_stats = Arc::new(PanelStatsCollector::new());
        let stats = NaiveStatsCollector(Arc::clone(&panel_stats));

        stats.record_request(1);
        stats.record_upload(1, 100);
        stats.record_download(1, 200);

        let snapshot = panel_stats.get_stats(1).unwrap();
        assert_eq!(snapshot.request_count, 1);
        assert_eq!(snapshot.upload_bytes, 100);
        assert_eq!(snapshot.download_bytes, 200);
    }
}
