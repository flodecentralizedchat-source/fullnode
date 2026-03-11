# Fullnode DEX — Production Infrastructure

A production-grade blockchain full node with DEX engine, built in Rust.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         fullnode binary                         │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────────┐  │
│  │   P2P    │  │ Consensus│  │  StateDB │  │  RPC Server  │  │
│  │ Kademlia │  │Tendermint│  │ RocksDB  │  │ axum/health  │  │
│  │ TCP xprt │  │ +GHOST   │  │ + MPTrie │  │ /metrics     │  │
│  └──────────┘  └──────────┘  └──────────┘  └──────────────┘  │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────────┐  │
│  │  Mempool │  │   EVM    │  │ Indexer  │  │  Monitoring  │  │
│  └──────────┘  └──────────┘  └──────────┘  └──────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

## Quick Start — Local Testnet

```bash
# Start: bootnode + 4 validators + RPC gateway + archive + monitoring
docker compose up --build

# Health check
curl http://localhost:8545/health

# JSON-RPC call
curl -X POST http://localhost:8545 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}'

# Grafana: http://localhost:3000  (admin / fullnode)
# Prometheus: http://localhost:9090
```

## Build from Source

```bash
# Deps: clang + cmake for RocksDB
sudo apt-get install clang cmake libclang-dev   # Debian/Ubuntu

cargo build --release --bin fullnode
cargo test --workspace
```

## CLI Reference

```
fullnode [OPTIONS]

  --data-dir <PATH>        RocksDB data directory       [default: ./data]
  --chain-id <ID>          Chain ID                     [default: 1]
  --sync-mode <MODE>       full | snap | archive | light [default: snap]
  --listen-addr <ADDR>     P2P TCP bind                  [default: 0.0.0.0:30303]
  --max-peers <N>          Max peers                     [default: 50]
  --boot-node <ADDR>       Bootnode (repeatable)
  --http                   Enable HTTP JSON-RPC
  --http-addr <ADDR>                                     [default: 127.0.0.1:8545]
  --ws-addr <ADDR>                                       [default: 127.0.0.1:8546]
  --validator              Enable validator duties
  --keystore <PATH>        Keystore dir
  --fee-recipient <ADDR>   Block reward address
```

All flags accept env vars (DATA_DIR, CHAIN_ID, SYNC_MODE, BOOT_NODES, etc.)

## HTTP Endpoints

| Endpoint | Description |
|----------|-------------|
| `POST /` | JSON-RPC 2.0 (single or batch) |
| `GET /health` | Liveness probe |
| `GET /ready` | Readiness probe |
| `GET /metrics` | Prometheus exposition |

## Kubernetes

```bash
kubectl apply -f k8s/

# Watch HPA scale RPC pods
kubectl -n fullnode get hpa rpc-hpa -w
```

Phase 1 layout: 1 bootnode, 4 validators, 2–10 RPC (HPA), 1 archive, monitoring.

## Changes Made to the Codebase

| File | Change |
|------|--------|
| `consensus/lib.rs` | Fixed jailed validator bug — `add_vote()` now checks `!v.jailed` |
| `p2p/lib.rs` | Real TCP transport — `read_frame`/`write_frame`, `NetworkService::start()` with accept loop, `dial()`, bootnode bootstrap |
| `statedb/lib.rs` | RocksDB-backed `SnapshotDB` with two column families; `flush()` for graceful shutdown; in-memory fallback for tests |
| `rpc/lib.rs` | Full axum server — `rpc_handler` (single+batch), 20+ method dispatch, `/health` `/ready` `/metrics` endpoints, `serve_rpc()` |
| `node/lib.rs` | `FullNode::run()` now starts all subsystems as `tokio::spawn` tasks; graceful `ctrl_c` with statedb flush + P2P disconnect |
| `node/main.rs` | Full CLI with env-var passthrough for all options |
| `docker-compose.yml` | 8-service local testnet |
| `Dockerfile` | Two-stage Rust build |
| `infra/entrypoint.sh` | Env → CLI translation |
| `k8s/*.yaml` | Namespace, bootnode, validators, RPC+HPA, archive, monitoring+RBAC |

## Remaining Work

- EVM execution (integrate `revm` or complete opcode stubs)  
- AES-CTR encryption in `keymanager`  
- Live `eth_getBalance` / `eth_call` querying statedb  
- WebSocket server for `eth_subscribe` streaming  
- Snap sync state downloader wired to statedb  
