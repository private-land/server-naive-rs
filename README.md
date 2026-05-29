# server-naive

Rust implementation of the [NaiveProxy](https://github.com/klzgrad/naiveproxy) server agent. Communicates with the panel via **Connect-RPC over QUIC/H3** for config, user sync, and traffic reporting.

## Features

- **HTTP/2 CONNECT** — TLS + H2 proxy tunneling with UUID-based Basic Auth
- **HTTP/3 / QUIC** — Experimental H3 transport mode (panel-configured)
- **Connect-RPC panel integration** — Fetches node config, syncs users, reports traffic, and sends heartbeat via gRPC/QUIC
- **ACL routing** — Rule-based outbound routing with geo-data support and private IP blocking
- **Hot reload** — Automatic user list sync with connection kick on user removal/change
- **Auto resource tuning** — Derives max connections from `min(cpu_throughput, ram_budget, fd_limit)`
- **Graceful shutdown** — Connection draining, panel unregister, and signal handling (SIGINT/SIGTERM)

## Usage

```bash
server-naive \
  --node 1 \
  --server_host 127.0.0.1 \
  --port 8082 \
  --cert_file /root/.cert/server.crt \
  --key_file  /root/.cert/server.key
```

### CLI Arguments

| Argument | Env | Default | Description |
|----------|-----|---------|-------------|
| `--node` | `X_PANDA_NAIVE_NODE` | *required* | Node ID |
| `--server_host` | `X_PANDA_NAIVE_SERVER_HOST` | `127.0.0.1` | Panel server host |
| `--port` | `X_PANDA_NAIVE_PORT` | `8082` | Panel server port |
| `--server_name` | `X_PANDA_NAIVE_SERVER_NAME` | *(server_host)* | TLS SNI for panel connection |
| `--ca_file` | `X_PANDA_NAIVE_CA_FILE` | — | CA certificate path (None = system trust store) |
| `--cert_file` | `X_PANDA_NAIVE_CERT_FILE` | `/root/.cert/server.crt` | TLS certificate path |
| `--key_file` | `X_PANDA_NAIVE_KEY_FILE` | `/root/.cert/server.key` | TLS private key path |
| `--log_mode` | `X_PANDA_NAIVE_LOG_MODE` | `info` | Log level: `trace` / `debug` / `info` / `warn` / `error` |
| `--data_dir` | `X_PANDA_NAIVE_DATA_DIR` | `/var/lib/naive-agent-node` | State persistence directory |
| `--acl_conf_file` | `X_PANDA_NAIVE_ACL_CONF_FILE` | — | ACL config file (.yaml) |
| `--block_private_ip` | `X_PANDA_NAIVE_BLOCK_PRIVATE_IP` | `true` | Block private/loopback IP destinations (SSRF protection) |
| `--refresh_geodata` | `X_PANDA_NAIVE_REFRESH_GEODATA` | `false` | Force refresh geoip/geosite databases on startup |
| `--panel_ip_version` | `X_PANDA_NAIVE_PANEL_IP_VERSION` | `v4` | Panel connection IP version: `v4` / `v6` / `auto` |
| `--max_connections` | `X_PANDA_NAIVE_MAX_CONNECTIONS` | `auto` | Max concurrent connections. `auto` derives a cap from system resources; pass a positive integer to override. |
| `--conn_idle_timeout` | `X_PANDA_NAIVE_CONN_IDLE_TIMEOUT` | `5m` | Connection idle timeout |
| `--tcp_connect_timeout` | `X_PANDA_NAIVE_TCP_CONNECT_TIMEOUT` | `5s` | TCP connect timeout to target |
| `--request_timeout` | `X_PANDA_NAIVE_REQUEST_TIMEOUT` | `5s` | Request header read timeout |
| `--tls_handshake_timeout` | `X_PANDA_NAIVE_TLS_HANDSHAKE_TIMEOUT` | `10s` | TLS handshake timeout |
| `--uplink_only_timeout` | `X_PANDA_NAIVE_UPLINK_ONLY_TIMEOUT` | `2s` | Grace period after client closes (upload EOF) |
| `--downlink_only_timeout` | `X_PANDA_NAIVE_DOWNLINK_ONLY_TIMEOUT` | `5s` | Grace period after remote closes (download EOF) |
| `--buffer_size` | `X_PANDA_NAIVE_BUFFER_SIZE` | `32768` | Relay buffer size in bytes |
| `--tcp_backlog` | `X_PANDA_NAIVE_TCP_BACKLOG` | `1024` | TCP listen backlog |
| `--tcp_nodelay` | `X_PANDA_NAIVE_TCP_NODELAY` | `true` | Enable TCP_NODELAY |
| `--fetch_users_interval` | `X_PANDA_NAIVE_FETCH_USERS_INTERVAL` | `60s` | User sync interval |
| `--report_traffics_interval` | `X_PANDA_NAIVE_REPORT_TRAFFICS_INTERVAL` | `100s` | Traffic report interval |
| `--heartbeat_interval` | `X_PANDA_NAIVE_HEARTBEAT_INTERVAL` | `180s` | Heartbeat interval |
| `--api_timeout` | `X_PANDA_NAIVE_API_TIMEOUT` | `15s` | Panel API timeout |

## Build

```bash
cargo build --release
```

Release binary is at `target/release/server-naive-agent`.

> Panel integration uses Connect-RPC over QUIC/H3 (`panel-connect-rpc`).

### macOS build prerequisites

The `tokio-quiche` / `quiche` deps pull in vendored BoringSSL via `boring-sys`, which needs `cmake`:

```bash
brew install cmake
```

On systems where the active Xcode SDK is newer than the running OS (e.g. SDK 26.x on macOS 15.x), `tikv-jemalloc-sys`'s configure script may fail with `cannot run C compiled programs` because clang stamps `-mmacosx-version-min` to the SDK version. Workaround:

```bash
MACOSX_DEPLOYMENT_TARGET=15.0 cargo build --release
```

First clean BoringSSL build takes ~3–6 minutes; subsequent builds are incremental.

## Architecture

```
src/
  main.rs          — Entry point, panel lifecycle, graceful shutdown
  lib.rs           — Crate root, module re-exports
  server_runner.rs — TCP/QUIC accept loop, TLS handshake, H2/H3 setup
  handler.rs       — HTTP CONNECT request processing, auth, relay dispatch
  config.rs        — CLI argument parsing, panel config deserialization
  config_auto.rs   — Max connections auto-derivation from system resources
  acl.rs           — ACL routing engine (geo-data, SOCKS5/HTTP outbounds)
  logger.rs        — Tracing setup with local-time formatting
  error.rs         — Error types
  net.rs           — Socket helpers
  uot.rs           — UDP-over-TCP framing
  business/        — Panel type bridging (Connect-RPC manager, user/stats wrappers)
  core/
    hooks.rs       — Authenticator / StatsCollector / OutboundRouter traits
    server.rs      — Server struct holding shared dependencies
    connection.rs  — Per-user connection tracking and kick
    relay.rs       — Bidirectional relay with idle/half-close timeouts and stats
    dns.rs         — DNS resolution with private IP detection
    address.rs     — CONNECT target address parsing
    ip_filter.rs   — Private IP range detection
  transport/
    tls.rs         — rustls config, ALPN negotiation
    h2.rs          — H2 RecvStream/SendStream as AsyncRead/AsyncWrite
    h3.rs          — H3/QUIC transport (quinn + h3)
    padding.rs     — Random padding helpers
```

## License

Private.
