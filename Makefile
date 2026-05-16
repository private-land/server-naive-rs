# ──────────────────────────────────────────────
# server-naive-rs  Development Makefile
# ──────────────────────────────────────────────

# ── Panel / node settings ──────────────────────
NODE          ?= 1
PANEL_API     ?= http://127.0.0.1:8080
PANEL_TOKEN   ?=

# ── Naive proxy TLS (client-facing) ───────────
CERT_DIR      ?= .cert
CERT_DAYS     ?= 365
CERT_CN       ?= localhost
CERT_FILE     = $(CERT_DIR)/server.crt
KEY_FILE      = $(CERT_DIR)/server.key

# ── Misc ───────────────────────────────────────
DATA_DIR      ?= /tmp/naive-agent-data
LOG_MODE      ?= info
BINARY        = target/release/server-naive-agent
DEBUG_BINARY  = target/debug/server-naive-agent

# ──────────────────────────────────────────────
# Build
# ──────────────────────────────────────────────

.PHONY: build
build:
	cargo build --release

.PHONY: build-debug
build-debug:
	cargo build

# ──────────────────────────────────────────────
# Run  (requires: make cert + server-agent running)
# ──────────────────────────────────────────────

.PHONY: run
run: $(CERT_FILE)
	cargo run -- \
		--node    $(NODE) \
		--api     $(PANEL_API) \
		--token   "$(PANEL_TOKEN)" \
		--cert_file $(CERT_FILE) \
		--key_file  $(KEY_FILE) \
		--data_dir  $(DATA_DIR) \
		--log_mode  $(LOG_MODE) \
		--fetch_users_interval     10s \
		--report_traffics_interval 30s \
		--heartbeat_interval       60s

.PHONY: dev
dev: $(CERT_FILE)
	cargo run -- \
		--node    $(NODE) \
		--api     $(PANEL_API) \
		--token   "$(PANEL_TOKEN)" \
		--cert_file $(CERT_FILE) \
		--key_file  $(KEY_FILE) \
		--data_dir  $(DATA_DIR) \
		--log_mode  debug \
		--fetch_users_interval     10s \
		--report_traffics_interval 30s \
		--heartbeat_interval       60s

# ──────────────────────────────────────────────
# TLS certificate (client-facing naive proxy)
# ──────────────────────────────────────────────

.PHONY: cert
cert: $(CERT_FILE)

$(CERT_FILE):
	@mkdir -p $(CERT_DIR)
	@echo "Generating self-signed TLS certificate for naive proxy..."
	openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
		-days $(CERT_DAYS) -nodes \
		-keyout $(CERT_DIR)/server.key \
		-out    $(CERT_DIR)/server.crt \
		-subj   "/CN=$(CERT_CN)" \
		-addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
	@echo "Certificate written to $(CERT_DIR)/ (server.crt, server.key)"

# ──────────────────────────────────────────────
# Code quality
# ──────────────────────────────────────────────

.PHONY: fmt
fmt:
	cargo fmt

.PHONY: fmt-check
fmt-check:
	cargo fmt --check

.PHONY: lint
lint:
	cargo clippy --all-targets --all-features

.PHONY: check
check: fmt-check lint

.PHONY: test
test:
	cargo test

.PHONY: test-verbose
test-verbose:
	cargo test -- --nocapture

# ──────────────────────────────────────────────
# Misc
# ──────────────────────────────────────────────

.PHONY: clean
clean:
	cargo clean

.PHONY: help
help:
	@echo "Targets:"
	@echo "  make cert          Generate self-signed TLS cert for the naive proxy server"
	@echo "  make run           Run with info logging (NODE=$(NODE), panel=$(PANEL_HOST):$(PANEL_PORT))"
	@echo "  make dev           Run with debug logging"
	@echo "  make build         Release build"
	@echo "  make build-debug   Debug build"
	@echo "  make test          Run all tests"
	@echo "  make lint          cargo clippy"
	@echo "  make fmt           cargo fmt"
	@echo "  make check         fmt-check + lint"
	@echo "  make clean         cargo clean"
	@echo ""
	@echo "Override variables:"
	@echo "  NODE=$(NODE)  PANEL_API=$(PANEL_API)  PANEL_TOKEN=..."
	@echo "  LOG_MODE=$(LOG_MODE)"
