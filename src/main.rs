//! NaiveProxy server agent with panel integration
//!
//! Architecture:
//! - `core/`: Core proxy logic with hook traits for extensibility
//! - `transport/`: H2 transport layer (TLS + HTTP/2)
//! - `business/`: Business layer (panel API, auth, stats)
//! - `handler`: HTTP/2 CONNECT request processing
//! - `server_runner`: Server startup and accept loop

mod acl;
mod business;
mod config;
mod config_auto;
mod core;
mod error;
mod handler;
mod logger;
mod net;
mod quiche_runner;
mod server_runner;
mod transport;
mod uot;

// jemalloc: actively returns freed memory to OS, preventing RSS growth under high connection churn
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

use logger::log;

use anyhow::Result;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

use crate::business::{
    ApiManager, BackgroundTasks, NaiveAuthenticator, NaiveStatsCollector, NaiveUserManager,
    NodeType, PanelApi, PanelConfig, PanelStatsCollector, TaskConfig,
};
use crate::core::{ConnectionManager, Server};

#[tokio::main]
async fn main() -> Result<()> {
    // Install aws-lc-rs as the default crypto provider for rustls
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    let cli = config::CliArgs::parse_args();
    cli.validate()?;

    logger::init_logger(&cli.log_mode);

    log::info!(
        server_host = %cli.server_host,
        port = cli.port,
        node = cli.node,
        "Starting Naive proxy server agent"
    );

    let conn_manager = ConnectionManager::new();

    let panel_config = PanelConfig {
        server_host: cli.server_host.clone(),
        server_port: cli.port,
        node_id: cli.node,
        node_type: NodeType::Naive,
        data_dir: cli.data_dir.clone(),
        api_timeout: cli.api_timeout,
        server_name: cli
            .server_name
            .clone()
            .unwrap_or_else(|| cli.server_host.clone()),
        ca_cert_path: cli.ca_file.clone(),
        ip_version: cli.panel_ip_version,
    };

    let api_manager = Arc::new(ApiManager::new(panel_config));

    // UserManager<String>: UUID strings used directly as auth keys (no hashing)
    let user_manager = Arc::new(NaiveUserManager::new(|uuid: &str| uuid.to_string()));

    // Fetch configuration from panel
    let node_config = api_manager.fetch_config().await?;
    let naive_config = config::parse_naive_config(node_config)?;

    log::info!(
        network = %naive_config.network,
        port = naive_config.server_port,
        "Node config fetched"
    );

    let use_h3 = naive_config.network == config::NaiveNetwork::Udp;

    // Register node with panel
    api_manager.initialize(naive_config.server_port).await?;
    log::info!("Node initialized");

    // Fetch initial user list
    if let Some(users) = api_manager.fetch_users().await? {
        user_manager.init(&users);
        log::info!(count = users.len(), "Initial users loaded");
    }

    let server_config = config::ServerConfig::from_remote(&naive_config, &cli)?;

    let authenticator = Arc::new(NaiveAuthenticator(Arc::clone(&user_manager)));
    let panel_stats = Arc::new(PanelStatsCollector::new());
    let stats_collector = Arc::new(NaiveStatsCollector(Arc::clone(&panel_stats)));

    // Shared DNS cache (DnsCache: Clone is cheap — Arc-backed)
    let dns_cache = dns_cache_rs::DnsCache::new();

    let router =
        server_runner::build_router(&server_config, cli.refresh_geodata, dns_cache.clone()).await?;

    // Resolve max_connections once and log the result
    let resolved_max = config_auto::resolve(cli.max_connections);
    let bd = resolved_max.breakdown;
    let mode = match resolved_max.mode {
        config_auto::ResolveMode::Auto => "auto",
        config_auto::ResolveMode::Fixed => "fixed",
    };
    log::info!(
        mode = mode,
        value = resolved_max.value,
        cpus = resolved_max.cpus,
        total_mem_kb = resolved_max.total_mem_kb,
        nofile_soft = resolved_max.nofile_soft,
        cpu_cap = bd.cpu_cap,
        mem_cap = bd.mem_cap,
        fd_cap = bd.fd_cap,
        limiting = bd.limiting.as_str(),
        "max_connections resolved"
    );
    if resolved_max.mode == config_auto::ResolveMode::Fixed
        && config_auto::fixed_exceeds_auto_cap(resolved_max.value, &bd)
    {
        log::warn!(
            value = resolved_max.value,
            "max_connections=fixed exceeds the auto-derived safe cap"
        );
    }

    let conn_config = config::ConnConfig::from_cli(&cli, resolved_max.value);

    let conn_manager_for_shutdown = conn_manager.clone();

    let server = Arc::new(
        Server::builder()
            .authenticator(authenticator)
            .stats(Arc::clone(&stats_collector) as Arc<dyn core::hooks::StatsCollector>)
            .router(router)
            .conn_manager(conn_manager)
            .conn_config(conn_config)
            .dns_cache(dns_cache)
            .build(),
    );

    // Background tasks: user sync, traffic reporting, heartbeat
    let task_config = TaskConfig {
        fetch_users_interval: cli.fetch_users_interval,
        report_traffic_interval: cli.report_traffics_interval,
        heartbeat_interval: cli.heartbeat_interval,
    };

    let conn_manager_for_kicks = conn_manager_for_shutdown.clone();
    let background_tasks = BackgroundTasks::new(
        task_config,
        Arc::clone(&api_manager),
        Arc::clone(&user_manager),
        Arc::clone(&panel_stats),
    )
    .on_user_diff(Arc::new(move |diff| {
        let kick_ids: Vec<i64> = diff
            .removed_ids
            .iter()
            .chain(diff.uuid_changed_ids.iter())
            .copied()
            .collect();
        if !kick_ids.is_empty() {
            let mut total_kicked = 0usize;
            for &uid in &kick_ids {
                total_kicked += conn_manager_for_kicks.kick_user(uid);
            }
            if total_kicked > 0 {
                log::info!(
                    kicked = total_kicked,
                    removed = diff.removed,
                    uuid_changed = diff.uuid_changed,
                    "Kicked connections for removed/changed users"
                );
            }
        }
    }));
    let background_handle = background_tasks.start();

    let cancel_token = CancellationToken::new();
    let cancel_token_clone = cancel_token.clone();

    let api_for_shutdown = Arc::clone(&api_manager);
    let shutdown_handle = tokio::spawn(async move {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{signal, SignalKind};
            let mut sigint = signal(SignalKind::interrupt()).expect("Failed to setup SIGINT");
            let mut sigterm = signal(SignalKind::terminate()).expect("Failed to setup SIGTERM");
            tokio::select! {
                _ = sigint.recv() => { log::info!("SIGINT received, shutting down..."); }
                _ = sigterm.recv() => { log::info!("SIGTERM received, shutting down..."); }
                _ = cancel_token_clone.cancelled() => {}
            }
        }
        #[cfg(not(unix))]
        {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => { log::info!("Shutdown signal received..."); }
                _ = cancel_token_clone.cancelled() => {}
            }
        }
        cancel_token_clone.cancel();
        api_for_shutdown
    });

    let server_result = tokio::select! {
        result = async {
            if use_h3 {
                match cli.h3_backend {
                    config::H3Backend::Quinn => {
                        log::info!(backend = "quinn", "H3 backend selected");
                        server_runner::run_h3_server(server, &server_config).await
                    }
                    config::H3Backend::Quiche => {
                        log::info!(backend = "quiche", "H3 backend selected");
                        quiche_runner::run_h3_server_quiche(server, &server_config).await
                    }
                }
            } else {
                server_runner::run_server(server, &server_config).await
            }
        } => result,
        _ = cancel_token.cancelled() => Ok(()),
    };

    cancel_token.cancel();

    log::info!("Server stopped, performing graceful shutdown...");

    let cancelled = conn_manager_for_shutdown.cancel_all();
    if cancelled > 0 {
        log::info!("Cancelled {cancelled} connections, draining...");
        let drain_deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            let remaining = conn_manager_for_shutdown.connection_count();
            if remaining == 0 {
                log::info!("All connections drained");
                break;
            }
            if tokio::time::Instant::now() >= drain_deadline {
                log::warn!("{remaining} connections remaining after drain timeout");
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    }

    if let Ok(api_for_shutdown) = shutdown_handle.await {
        log::info!("Unregistering node...");
        if let Err(e) = api_for_shutdown.unregister().await {
            log::warn!(error = %e, "Failed to unregister node");
        } else {
            log::info!("Node unregistered successfully");
        }
        background_handle.shutdown().await;
    }

    log::info!("Shutdown complete");
    server_result
}
