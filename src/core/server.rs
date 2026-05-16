//! Core proxy server implementation

use std::sync::Arc;

use super::connection::ConnectionManager;
use super::hooks::{Authenticator, DirectRouter, OutboundRouter, StatsCollector};
use crate::config::ConnConfig;
use dns_cache_rs::DnsCache;

pub struct Server {
    pub authenticator: Arc<dyn Authenticator>,
    pub stats: Arc<dyn StatsCollector>,
    pub router: Arc<dyn OutboundRouter>,
    pub conn_manager: ConnectionManager,
    pub conn_config: ConnConfig,
    pub dns_cache: DnsCache,
}

impl Server {
    pub fn builder() -> ServerBuilder {
        ServerBuilder::new()
    }
}

pub struct ServerBuilder {
    authenticator: Option<Arc<dyn Authenticator>>,
    stats: Option<Arc<dyn StatsCollector>>,
    router: Option<Arc<dyn OutboundRouter>>,
    conn_manager: Option<ConnectionManager>,
    conn_config: Option<ConnConfig>,
    dns_cache: Option<DnsCache>,
}

impl Default for ServerBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl ServerBuilder {
    pub fn new() -> Self {
        Self {
            authenticator: None,
            stats: None,
            router: None,
            conn_manager: None,
            conn_config: None,
            dns_cache: None,
        }
    }

    pub fn authenticator(mut self, auth: Arc<dyn Authenticator>) -> Self {
        self.authenticator = Some(auth);
        self
    }

    pub fn stats(mut self, stats: Arc<dyn StatsCollector>) -> Self {
        self.stats = Some(stats);
        self
    }

    pub fn router(mut self, router: Arc<dyn OutboundRouter>) -> Self {
        self.router = Some(router);
        self
    }

    pub fn conn_manager(mut self, manager: ConnectionManager) -> Self {
        self.conn_manager = Some(manager);
        self
    }

    pub fn conn_config(mut self, config: ConnConfig) -> Self {
        self.conn_config = Some(config);
        self
    }

    pub fn dns_cache(mut self, cache: DnsCache) -> Self {
        self.dns_cache = Some(cache);
        self
    }

    pub fn build(self) -> Server {
        let dns_cache = self.dns_cache.expect("dns_cache is required");
        Server {
            authenticator: self.authenticator.expect("authenticator is required"),
            stats: self.stats.expect("stats collector is required"),
            router: self
                .router
                .unwrap_or_else(|| Arc::new(DirectRouter::with_cache(true, dns_cache.clone()))),
            conn_manager: self.conn_manager.unwrap_or_default(),
            conn_config: self.conn_config.expect("conn_config is required"),
            dns_cache,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::UserId;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Duration;

    struct TestAuthenticator;

    impl Authenticator for TestAuthenticator {
        fn authenticate(&self, _credential: &str) -> Option<UserId> {
            Some(1)
        }
    }

    struct TestStatsCollector {
        requests: AtomicU64,
    }

    impl TestStatsCollector {
        fn new() -> Self {
            Self { requests: AtomicU64::new(0) }
        }
    }

    impl StatsCollector for TestStatsCollector {
        fn record_request(&self, _user_id: UserId) {
            self.requests.fetch_add(1, Ordering::Relaxed);
        }
        fn record_upload(&self, _user_id: UserId, _bytes: u64) {}
        fn record_download(&self, _user_id: UserId, _bytes: u64) {}
    }

    fn test_conn_config() -> ConnConfig {
        ConnConfig {
            idle_timeout: Duration::from_secs(300),
            uplink_only_timeout: Duration::from_secs(2),
            downlink_only_timeout: Duration::from_secs(5),
            connect_timeout: Duration::from_secs(5),
            request_timeout: Duration::from_secs(5),
            tls_handshake_timeout: Duration::from_secs(10),
            buffer_size: 32 * 1024,
            tcp_backlog: 1024,
            tcp_nodelay: true,
            max_connections: 65535,
        }
    }

    #[test]
    fn test_server_builder() {
        let _server = Server::builder()
            .authenticator(Arc::new(TestAuthenticator))
            .stats(Arc::new(TestStatsCollector::new()))
            .conn_config(test_conn_config())
            .dns_cache(dns_cache_rs::DnsCache::new())
            .build();
    }

    #[test]
    fn test_server_builder_with_conn_manager() {
        let conn_manager = ConnectionManager::new();
        let _server = Server::builder()
            .authenticator(Arc::new(TestAuthenticator))
            .stats(Arc::new(TestStatsCollector::new()))
            .conn_manager(conn_manager)
            .conn_config(test_conn_config())
            .dns_cache(dns_cache_rs::DnsCache::new())
            .build();
    }
}
