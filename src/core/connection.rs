//! Connection management module

use dashmap::DashMap;
use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio_util::sync::CancellationToken;

use super::hooks::UserId;

pub type ConnectionId = u64;

#[derive(Debug, Clone)]
struct ConnectionInfo {
    user_id: UserId,
    #[allow(dead_code)]
    peer_addr: SocketAddr,
    #[allow(dead_code)]
    connected_at: Instant,
}

#[derive(Debug)]
struct ActiveConnection {
    info: ConnectionInfo,
    cancel_token: CancellationToken,
}

#[derive(Debug, Clone)]
pub struct ConnectionManager {
    next_conn_id: Arc<AtomicU64>,
    connections: Arc<DashMap<ConnectionId, ActiveConnection>>,
    user_connections: Arc<DashMap<UserId, HashSet<ConnectionId>>>,
}

impl Default for ConnectionManager {
    fn default() -> Self {
        Self::new()
    }
}

impl ConnectionManager {
    pub fn new() -> Self {
        Self {
            next_conn_id: Arc::new(AtomicU64::new(1)),
            connections: Arc::new(DashMap::new()),
            user_connections: Arc::new(DashMap::new()),
        }
    }

    pub fn register(
        &self,
        user_id: UserId,
        peer_addr: SocketAddr,
    ) -> (ConnectionId, CancellationToken) {
        let conn_id = self.next_conn_id.fetch_add(1, Ordering::Relaxed);
        let cancel_token = CancellationToken::new();

        let info = ConnectionInfo {
            user_id,
            peer_addr,
            connected_at: Instant::now(),
        };
        let conn = ActiveConnection {
            info,
            cancel_token: cancel_token.clone(),
        };

        self.connections.insert(conn_id, conn);
        self.user_connections
            .entry(user_id)
            .or_default()
            .insert(conn_id);

        (conn_id, cancel_token)
    }

    pub fn unregister(&self, conn_id: ConnectionId) {
        if let Some((_, conn)) = self.connections.remove(&conn_id) {
            let user_id = conn.info.user_id;
            self.user_connections
                .remove_if_mut(&user_id, |_, conn_ids| {
                    conn_ids.remove(&conn_id);
                    conn_ids.is_empty()
                });
        }
    }

    pub fn kick_user(&self, user_id: UserId) -> usize {
        let mut kicked = 0;
        if let Some(conn_ids) = self.user_connections.get(&user_id) {
            for &conn_id in conn_ids.iter() {
                if let Some(conn) = self.connections.get(&conn_id) {
                    conn.cancel_token.cancel();
                    kicked += 1;
                }
            }
        }
        kicked
    }

    pub fn cancel_all(&self) -> usize {
        let mut cancelled = 0;
        for entry in self.connections.iter() {
            entry.value().cancel_token.cancel();
            cancelled += 1;
        }
        cancelled
    }

    pub fn connection_count(&self) -> usize {
        self.connections.len()
    }

    #[allow(dead_code)]
    pub fn user_count(&self) -> usize {
        self.user_connections.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_and_unregister() {
        let manager = ConnectionManager::new();
        let (conn_id, _token) = manager.register(1, "127.0.0.1:1234".parse().unwrap());
        assert_eq!(manager.connection_count(), 1);
        manager.unregister(conn_id);
        assert_eq!(manager.connection_count(), 0);
        assert_eq!(manager.user_count(), 0);
    }

    #[test]
    fn test_kick_user() {
        let manager = ConnectionManager::new();
        let (_, token1) = manager.register(1, "127.0.0.1:1234".parse().unwrap());
        let (_, token2) = manager.register(1, "127.0.0.1:1235".parse().unwrap());
        let (_, token3) = manager.register(2, "127.0.0.1:1236".parse().unwrap());

        let kicked = manager.kick_user(1);
        assert_eq!(kicked, 2);
        assert!(token1.is_cancelled());
        assert!(token2.is_cancelled());
        assert!(!token3.is_cancelled());
    }

    #[test]
    fn test_cancel_all() {
        let manager = ConnectionManager::new();
        let (_, token1) = manager.register(1, "127.0.0.1:1234".parse().unwrap());
        let (_, token2) = manager.register(2, "127.0.0.1:1235".parse().unwrap());

        let cancelled = manager.cancel_all();
        assert_eq!(cancelled, 2);
        assert!(token1.is_cancelled());
        assert!(token2.is_cancelled());
    }

    #[tokio::test(start_paused = true)]
    async fn test_shutdown_drain() {
        use std::time::Duration;

        let manager = ConnectionManager::new();

        for i in 0..10i64 {
            let m = manager.clone();
            let (conn_id, cancel_token) =
                manager.register(i, SocketAddr::from(([127, 0, 0, 1], (1000 + i) as u16)));
            tokio::spawn(async move {
                cancel_token.cancelled().await;
                tokio::time::sleep(Duration::from_millis(10)).await;
                m.unregister(conn_id);
            });
        }

        manager.cancel_all();

        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            if manager.connection_count() == 0 {
                break;
            }
            assert!(tokio::time::Instant::now() < deadline);
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert_eq!(manager.connection_count(), 0);
    }
}
