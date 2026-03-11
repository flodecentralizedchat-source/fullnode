# ─── Build stage ──────────────────────────────────────────────────────────────
FROM rust:1.85-slim-bookworm AS builder

# System deps for RocksDB
RUN apt-get update && apt-get install -y \
    clang \
    cmake \
    libclang-dev \
    libssl-dev \
    pkg-config \
    netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Cache dependency fetch separately from source compile
COPY Cargo.toml Cargo.lock ./
COPY crates/types/Cargo.toml       crates/types/Cargo.toml
COPY crates/common/Cargo.toml      crates/common/Cargo.toml
COPY crates/p2p/Cargo.toml         crates/p2p/Cargo.toml
COPY crates/consensus/Cargo.toml   crates/consensus/Cargo.toml
COPY crates/execution/Cargo.toml   crates/execution/Cargo.toml
COPY crates/statedb/Cargo.toml     crates/statedb/Cargo.toml
COPY crates/rpc/Cargo.toml         crates/rpc/Cargo.toml
COPY crates/mempool/Cargo.toml     crates/mempool/Cargo.toml
COPY crates/sync/Cargo.toml        crates/sync/Cargo.toml
COPY crates/monitoring/Cargo.toml  crates/monitoring/Cargo.toml
COPY crates/dex/Cargo.toml         crates/dex/Cargo.toml
COPY crates/keymanager/Cargo.toml  crates/keymanager/Cargo.toml
COPY crates/indexer/Cargo.toml     crates/indexer/Cargo.toml
COPY crates/node/Cargo.toml        crates/node/Cargo.toml

# Create stub src files so cargo can resolve deps without full source
RUN for crate in types common p2p consensus execution statedb rpc mempool sync monitoring dex keymanager indexer; do \
    mkdir -p crates/$crate/src && echo "// stub" > crates/$crate/src/lib.rs; \
    done && \
    mkdir -p crates/node/src && \
    echo "fn main(){}" > crates/node/src/main.rs && \
    echo "// stub" > crates/node/src/lib.rs

RUN cargo build --release 2>/dev/null || true

# Now copy real source and do a proper build
COPY crates/ crates/
RUN cargo build --release --bin fullnode

# ─── Runtime stage ────────────────────────────────────────────────────────────
FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    netcat-openbsd \
    curl \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m -u 1000 -s /bin/bash fullnode

COPY --from=builder /build/target/release/fullnode /usr/local/bin/fullnode
COPY --from=builder /build/target/release/fullnode /usr/local/bin/

RUN chmod +x /usr/local/bin/fullnode

USER fullnode
WORKDIR /home/fullnode

# Config via environment variables parsed by entrypoint
COPY --chown=fullnode:fullnode infra/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 8545 8546 30303 9100

VOLUME ["/data"]

ENTRYPOINT ["/entrypoint.sh"]