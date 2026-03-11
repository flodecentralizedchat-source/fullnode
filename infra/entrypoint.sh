#!/bin/bash
# ── fullnode entrypoint ──────────────────────────────────────────────────────
# Translates environment variables to fullnode CLI arguments.
# All env vars have sane defaults for local testnet usage.

set -euo pipefail

DATA_DIR="${DATA_DIR:-/data}"
CHAIN_ID="${CHAIN_ID:-31337}"
SYNC_MODE="${SYNC_MODE:-snap}"
VALIDATOR_ENABLED="${VALIDATOR_ENABLED:-false}"
MAX_PEERS="${MAX_PEERS:-50}"
BOOT_NODES="${BOOT_NODES:-}"
HTTP_ENABLED="${HTTP_ENABLED:-true}"
HTTP_ADDR="${HTTP_ADDR:-127.0.0.1:8545}"
WS_ADDR="${WS_ADDR:-127.0.0.1:8546}"
LISTEN_ADDR="${LISTEN_ADDR:-0.0.0.0:30303}"
KEYSTORE_PATH="${KEYSTORE_PATH:-${DATA_DIR}/keystore}"
FEE_RECIPIENT="${FEE_RECIPIENT:-0x0000000000000000000000000000000000000000}"

mkdir -p "$DATA_DIR"

# Build args array
ARGS=(
  "--data-dir"   "$DATA_DIR"
  "--chain-id"   "$CHAIN_ID"
  "--sync-mode"  "$SYNC_MODE"
  "--listen-addr" "$LISTEN_ADDR"
  "--max-peers"  "$MAX_PEERS"
)

if [ -n "$BOOT_NODES" ]; then
  # comma-separated list → multiple --boot-node flags
  IFS=',' read -ra BN_ARRAY <<< "$BOOT_NODES"
  for bn in "${BN_ARRAY[@]}"; do
    ARGS+=("--boot-node" "$bn")
  done
fi

if [ "$HTTP_ENABLED" = "true" ]; then
  ARGS+=("--http" "--http-addr" "$HTTP_ADDR" "--ws-addr" "$WS_ADDR")
fi

if [ "$VALIDATOR_ENABLED" = "true" ]; then
  ARGS+=("--validator" "--keystore" "$KEYSTORE_PATH" "--fee-recipient" "$FEE_RECIPIENT")
fi

echo "▶ fullnode ${ARGS[*]}"
exec /usr/local/bin/fullnode "${ARGS[@]}"
