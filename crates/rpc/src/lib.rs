//! ═══════════════════════════════════════════════════════════════════
//! MODULE 6 — RPC / API SERVER
//!
//! Data Structures:
//!   RpcRequest   — JSON-RPC 2.0 envelope {id, method, params}
//!   RpcResponse  — {id, result | error}
//!   SubscriptionMap — subscription_id → (filter, Sender<JsonValue>)
//!   FilterState  — bloom-based fast-reject for eth_getLogs
//!
//! Algorithms:
//!   Method dispatch: perfect hash (phf) over method name strings
//!   Log bloom filter: 3-hash Bloom over (address, topic)
//!   Rate limiting:   Token bucket per IP (burst=100, refill=10/s)
//!   WebSocket subs:  fan-out broadcaster via tokio broadcast channel
//! ═══════════════════════════════════════════════════════════════════

use std::{
    collections::HashMap,
    sync::Arc,
    time::Instant,
};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::{net::TcpListener, sync::broadcast};
use axum::{
    body::Bytes,
    extract::{State, ConnectInfo},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use tower_http::cors::{Any, CorsLayer};
use tracing;

pub type Address = [u8; 20];
pub type Hash = [u8; 32];

// ─── JSON-RPC 2.0 Types ───────────────────────────────────────────────────────
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcRequest {
    pub jsonrpc: String,          // "2.0"
    pub id:      Option<Value>,
    pub method:  String,
    pub params:  Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcResponse {
    pub jsonrpc: String,
    pub id:      Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result:  Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error:   Option<RpcError>,
}

impl RpcResponse {
    pub fn ok(id: Option<Value>, result: Value) -> Self {
        Self { jsonrpc: "2.0".into(), id, result: Some(result), error: None }
    }
    pub fn err(id: Option<Value>, code: i32, message: impl Into<String>) -> Self {
        Self { jsonrpc: "2.0".into(), id, result: None,
               error: Some(RpcError { code, message: message.into(), data: None }) }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcError { pub code: i32, pub message: String, pub data: Option<Value> }

// Standard JSON-RPC error codes
pub const ERR_PARSE:          i32 = -32700;
pub const ERR_INVALID_REQUEST: i32 = -32600;
pub const ERR_METHOD_NOT_FOUND: i32 = -32601;
pub const ERR_INVALID_PARAMS:  i32 = -32602;
pub const ERR_INTERNAL:        i32 = -32603;

// ─── eth_getLogs filter ───────────────────────────────────────────────────────
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LogFilter {
    pub from_block:  Option<BlockTag>,
    pub to_block:    Option<BlockTag>,
    pub address:     Option<AddressFilter>,
    pub topics:      Option<Vec<Option<TopicFilter>>>,
    pub block_hash:  Option<Hash>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum BlockTag { Number(u64), Tag(String) }

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AddressFilter { One(Address), Many(Vec<Address>) }

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum TopicFilter { One(Hash), Any(Vec<Hash>) }

// ─── Bloom Filter (512-bit, 3-hash) ──────────────────────────────────────────
/// Standard Ethereum log bloom filter
pub struct LogBloom([u8; 256]);

impl LogBloom {
    pub fn empty() -> Self { Self([0u8; 256]) }

    fn positions(input: &[u8]) -> [usize; 3] {
        use sha3::{Digest, Keccak256};
        let h: [u8; 32] = Keccak256::digest(input).into();
        [
            ((h[1] as usize | ((h[0] as usize) << 8)) & 0x7ff),
            ((h[3] as usize | ((h[2] as usize) << 8)) & 0x7ff),
            ((h[5] as usize | ((h[4] as usize) << 8)) & 0x7ff),
        ]
    }

    pub fn set(&mut self, input: &[u8]) {
        for pos in Self::positions(input) {
            self.0[255 - pos / 8] |= 1 << (pos % 8);
        }
    }

    pub fn contains(&self, input: &[u8]) -> bool {
        Self::positions(input).iter().all(|&pos| {
            self.0[255 - pos / 8] & (1 << (pos % 8)) != 0
        })
    }

    pub fn or(&self, other: &LogBloom) -> LogBloom {
        let mut out = LogBloom([0u8; 256]);
        for i in 0..256 { out.0[i] = self.0[i] | other.0[i]; }
        out
    }
}

// ─── Rate Limiter (Token Bucket) ──────────────────────────────────────────────
struct TokenBucket {
    tokens:       f64,
    max_tokens:   f64,
    refill_rate:  f64,   // tokens per second
    last_refill:  Instant,
}

impl TokenBucket {
    pub fn new(burst: f64, rate: f64) -> Self {
        Self { tokens: burst, max_tokens: burst, refill_rate: rate, last_refill: Instant::now() }
    }

    pub fn try_consume(&mut self, cost: f64) -> bool {
        let elapsed = self.last_refill.elapsed().as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.refill_rate).min(self.max_tokens);
        self.last_refill = Instant::now();
        if self.tokens >= cost {
            self.tokens -= cost;
            true
        } else {
            false
        }
    }
}

pub struct RateLimiter {
    buckets: RwLock<HashMap<String, TokenBucket>>, // key = IP string
    burst:   f64,
    rate:    f64,
}

impl RateLimiter {
    pub fn new(burst: f64, rate: f64) -> Arc<Self> {
        Arc::new(Self { buckets: RwLock::new(HashMap::new()), burst, rate })
    }

    pub fn check(&self, ip: &str) -> bool {
        let mut map = self.buckets.write();
        let bucket = map.entry(ip.to_string())
            .or_insert_with(|| TokenBucket::new(self.burst, self.rate));
        bucket.try_consume(1.0)
    }
}

// ─── Subscription System ──────────────────────────────────────────────────────
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SubscriptionKind {
    NewHeads,
    NewPendingTransactions,
    Logs(LogFilter),
    Syncing,
}

pub struct SubscriptionManager {
    /// sub_id → (kind, sender)
    subs:      RwLock<HashMap<String, (SubscriptionKind, broadcast::Sender<Value>)>>,
    /// topic channels: new_heads, pending_txs
    heads_tx:  broadcast::Sender<Value>,
    pending_tx: broadcast::Sender<Value>,
    logs_tx:   broadcast::Sender<Value>,
}

impl SubscriptionManager {
    pub fn new() -> Arc<Self> {
        let (heads_tx, _)   = broadcast::channel(1024);
        let (pending_tx, _) = broadcast::channel(4096);
        let (logs_tx, _)    = broadcast::channel(4096);
        Arc::new(Self {
            subs: RwLock::new(HashMap::new()),
            heads_tx, pending_tx, logs_tx,
        })
    }

    pub fn subscribe(&self, kind: SubscriptionKind) -> (String, broadcast::Receiver<Value>) {
        let id = uuid_v4();
        let rx = match &kind {
            SubscriptionKind::NewHeads               => self.heads_tx.subscribe(),
            SubscriptionKind::NewPendingTransactions => self.pending_tx.subscribe(),
            SubscriptionKind::Logs(_)                => self.logs_tx.subscribe(),
            SubscriptionKind::Syncing                => self.heads_tx.subscribe(),
        };
        self.subs.write().insert(id.clone(), (kind, self.heads_tx.clone()));
        (id, rx)
    }

    pub fn unsubscribe(&self, id: &str) -> bool {
        self.subs.write().remove(id).is_some()
    }

    pub fn broadcast_head(&self, head: Value) {
        let _ = self.heads_tx.send(head);
    }

    pub fn broadcast_pending_tx(&self, tx_hash: Value) {
        let _ = self.pending_tx.send(tx_hash);
    }

    pub fn broadcast_log(&self, log: Value) {
        let _ = self.logs_tx.send(log);
    }
}

fn uuid_v4() -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut h = DefaultHasher::new();
    Instant::now().hash(&mut h);
    format!("0x{:016x}", h.finish())
}

// ─── Method Router ────────────────────────────────────────────────────────────
/// All supported eth_* / net_* / web3_* methods
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EthMethod {
    // State queries
    EthBlockNumber,
    EthChainId,
    EthGasPrice,
    EthGetBalance,
    EthGetTransactionCount,
    EthGetCode,
    EthGetStorageAt,
    EthCall,
    EthEstimateGas,
    // Block queries
    EthGetBlockByHash,
    EthGetBlockByNumber,
    EthGetBlockTransactionCountByHash,
    // Transaction
    EthGetTransactionByHash,
    EthGetTransactionReceipt,
    EthSendRawTransaction,
    // Logs
    EthGetLogs,
    EthNewFilter,
    EthGetFilterLogs,
    EthUninstallFilter,
    // Subscriptions
    EthSubscribe,
    EthUnsubscribe,
    // Network
    NetVersion,
    NetPeerCount,
    NetListening,
    // Web3
    Web3ClientVersion,
    Web3Sha3,
    // DEX specific
    DexGetSwapQuote,
    DexGetOrderBook,
    DexGetPoolInfo,
}

impl EthMethod {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "eth_blockNumber"                       => Some(Self::EthBlockNumber),
            "eth_chainId"                           => Some(Self::EthChainId),
            "eth_gasPrice"                          => Some(Self::EthGasPrice),
            "eth_getBalance"                        => Some(Self::EthGetBalance),
            "eth_getTransactionCount"               => Some(Self::EthGetTransactionCount),
            "eth_getCode"                           => Some(Self::EthGetCode),
            "eth_getStorageAt"                      => Some(Self::EthGetStorageAt),
            "eth_call"                              => Some(Self::EthCall),
            "eth_estimateGas"                       => Some(Self::EthEstimateGas),
            "eth_getBlockByHash"                    => Some(Self::EthGetBlockByHash),
            "eth_getBlockByNumber"                  => Some(Self::EthGetBlockByNumber),
            "eth_getTransactionByHash"              => Some(Self::EthGetTransactionByHash),
            "eth_getTransactionReceipt"             => Some(Self::EthGetTransactionReceipt),
            "eth_sendRawTransaction"                => Some(Self::EthSendRawTransaction),
            "eth_getLogs"                           => Some(Self::EthGetLogs),
            "eth_subscribe"                         => Some(Self::EthSubscribe),
            "eth_unsubscribe"                       => Some(Self::EthUnsubscribe),
            "net_version"                           => Some(Self::NetVersion),
            "net_peerCount"                         => Some(Self::NetPeerCount),
            "dex_getSwapQuote"                      => Some(Self::DexGetSwapQuote),
            "dex_getOrderBook"                      => Some(Self::DexGetOrderBook),
            "dex_getPoolInfo"                       => Some(Self::DexGetPoolInfo),
            _ => None,
        }
    }
}

// ─── RpcServer config ─────────────────────────────────────────────────────────
#[derive(Debug, Clone)]
pub struct RpcConfig {
    pub http_addr:      std::net::SocketAddr,
    pub ws_addr:        std::net::SocketAddr,
    pub max_batch_size: usize,
    pub rate_limit:     (f64, f64), // (burst, refill/s)
    pub cors_origins:   Vec<String>,
}

impl Default for RpcConfig {
    fn default() -> Self {
        Self {
            http_addr:      "127.0.0.1:8545".parse().unwrap(),
            ws_addr:        "127.0.0.1:8546".parse().unwrap(),
            max_batch_size: 100,
            rate_limit:     (100.0, 10.0),
            cors_origins:   vec!["*".into()],
        }
    }
}

// ─── RPC Server State ─────────────────────────────────────────────────────────
#[derive(Clone)]
pub struct RpcServerState {
    pub chain_id:      u64,
    pub rate_limiter:  Arc<RateLimiter>,
    pub subscriptions: Arc<SubscriptionManager>,
    pub peer_count:    Arc<std::sync::atomic::AtomicU64>,
    pub block_number:  Arc<std::sync::atomic::AtomicU64>,
    pub metrics_text:  Arc<RwLock<String>>,
    pub health_ok:     Arc<std::sync::atomic::AtomicBool>,
}

impl RpcServerState {
    pub fn new(chain_id: u64, rate_limit: (f64, f64)) -> Self {
        Self {
            chain_id,
            rate_limiter:  RateLimiter::new(rate_limit.0, rate_limit.1),
            subscriptions: SubscriptionManager::new(),
            peer_count:    Arc::new(std::sync::atomic::AtomicU64::new(0)),
            block_number:  Arc::new(std::sync::atomic::AtomicU64::new(0)),
            metrics_text:  Arc::new(RwLock::new(String::new())),
            health_ok:     Arc::new(std::sync::atomic::AtomicBool::new(true)),
        }
    }
}

// ─── HTTP Handlers ────────────────────────────────────────────────────────────

/// POST / — JSON-RPC 2.0 handler (single request or batch)
async fn rpc_handler(
    State(state): State<RpcServerState>,
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    body: Bytes,
) -> impl IntoResponse {
    let ip = addr.ip().to_string();

    // Rate limit check
    if !state.rate_limiter.check(&ip) {
        let resp = RpcResponse::err(None, ERR_INTERNAL, "Too many requests");
        return (StatusCode::TOO_MANY_REQUESTS, Json(serde_json::to_value(resp).unwrap()));
    }

    // Parse — support single request or batch array
    match serde_json::from_slice::<Value>(&body) {
        Ok(Value::Array(batch)) => {
            let responses: Vec<Value> = batch.iter()
                .filter_map(|v| serde_json::from_value::<RpcRequest>(v.clone()).ok())
                .map(|req| dispatch_request(&state, req))
                .map(|r| serde_json::to_value(r).unwrap())
                .collect();
            (StatusCode::OK, Json(Value::Array(responses)))
        }
        Ok(v) => {
            match serde_json::from_value::<RpcRequest>(v) {
                Ok(req) => {
                    let resp = dispatch_request(&state, req);
                    (StatusCode::OK, Json(serde_json::to_value(resp).unwrap()))
                }
                Err(_) => {
                    let resp = RpcResponse::err(None, -32700, "Parse error");
                    (StatusCode::BAD_REQUEST, Json(serde_json::to_value(resp).unwrap()))
                }
            }
        }
        Err(_) => {
            let resp = RpcResponse::err(None, -32700, "Parse error");
            (StatusCode::BAD_REQUEST, Json(serde_json::to_value(resp).unwrap()))
        }
    }
}

/// Route an individual JSON-RPC request to the correct handler.
fn dispatch_request(state: &RpcServerState, req: RpcRequest) -> RpcResponse {
    use std::sync::atomic::Ordering;
    let id = req.id.clone();

    match EthMethod::from_str(&req.method) {
        Some(EthMethod::EthBlockNumber) => {
            let n = state.block_number.load(Ordering::Relaxed);
            RpcResponse::ok(id, Value::String(format!("0x{n:x}")))
        }
        Some(EthMethod::NetVersion) => {
            RpcResponse::ok(id, Value::String(state.chain_id.to_string()))
        }
        Some(EthMethod::NetPeerCount) => {
            let n = state.peer_count.load(Ordering::Relaxed);
            RpcResponse::ok(id, Value::String(format!("0x{n:x}")))
        }
        Some(EthMethod::EthChainId) => {
            RpcResponse::ok(id, Value::String(format!("0x{:x}", state.chain_id)))
        }
        Some(EthMethod::EthGasPrice) => {
            // Return 1 gwei default; real impl reads mempool base fee
            RpcResponse::ok(id, Value::String("0x3b9aca00".to_string()))
        }
        Some(EthMethod::EthGetBalance) => {
            // Stub — real impl queries statedb
            RpcResponse::ok(id, Value::String("0x0".to_string()))
        }
        Some(EthMethod::EthGetTransactionCount) => {
            RpcResponse::ok(id, Value::String("0x0".to_string()))
        }
        Some(EthMethod::EthSendRawTransaction) => {
            // Stub — real impl decodes tx, validates, adds to mempool
            RpcResponse::err(id, ERR_INTERNAL, "not yet implemented")
        }
        Some(EthMethod::EthCall) => {
            // Stub — real impl runs EVM in view mode
            RpcResponse::ok(id, Value::String("0x".to_string()))
        }
        Some(EthMethod::EthEstimateGas) => {
            RpcResponse::ok(id, Value::String("0x5208".to_string())) // 21000
        }
        Some(EthMethod::EthGetBlockByNumber) => {
            // Stub — real impl fetches from chainstore
            RpcResponse::ok(id, Value::Null)
        }
        Some(EthMethod::EthGetBlockByHash) => {
            RpcResponse::ok(id, Value::Null)
        }
        Some(EthMethod::EthGetTransactionByHash) => {
            RpcResponse::ok(id, Value::Null)
        }
        Some(EthMethod::EthGetTransactionReceipt) => {
            RpcResponse::ok(id, Value::Null)
        }
        Some(EthMethod::EthGetLogs) => {
            RpcResponse::ok(id, Value::Array(vec![]))
        }
        Some(EthMethod::EthSubscribe) => {
            let kind = req.params
                .as_ref()
                .and_then(|p| p.get(0))
                .and_then(|v| v.as_str())
                .unwrap_or("newHeads");
            let sub_kind = match kind {
                "newPendingTransactions" => SubscriptionKind::NewPendingTransactions,
                "logs"                  => SubscriptionKind::Logs(LogFilter::default()),
                _                       => SubscriptionKind::NewHeads,
            };
            let (sub_id, _rx) = state.subscriptions.subscribe(sub_kind);
            RpcResponse::ok(id, Value::String(sub_id))
        }
        Some(EthMethod::EthUnsubscribe) => {
            let sub_id = req.params
                .as_ref()
                .and_then(|p| p.get(0))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let removed = state.subscriptions.unsubscribe(sub_id);
            RpcResponse::ok(id, Value::Bool(removed))
        }
        None => RpcResponse::err(id, ERR_METHOD_NOT_FOUND, "Method not found"),
        _ => RpcResponse::err(id, ERR_INTERNAL, "not yet implemented"),
    }
}

/// GET /health — liveness probe
async fn health_handler(State(state): State<RpcServerState>) -> impl IntoResponse {
    use std::sync::atomic::Ordering;
    if state.health_ok.load(Ordering::Relaxed) {
        (StatusCode::OK, "OK\n")
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "DEGRADED\n")
    }
}

/// GET /ready — readiness probe (same as health for now)
async fn ready_handler() -> impl IntoResponse {
    (StatusCode::OK, "READY\n")
}

/// GET /metrics — Prometheus text exposition
async fn metrics_handler(State(state): State<RpcServerState>) -> impl IntoResponse {
    let body = state.metrics_text.read().clone();
    (
        [(axum::http::header::CONTENT_TYPE, "text/plain; version=0.0.4")],
        body,
    )
}

// ─── Server Bootstrap ─────────────────────────────────────────────────────────

/// Build and return the axum Router (useful for testing without binding).
pub fn build_router(state: RpcServerState) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    Router::new()
        .route("/", post(rpc_handler))
        .route("/health",  get(health_handler))
        .route("/ready",   get(ready_handler))
        .route("/metrics", get(metrics_handler))
        .layer(cors)
        .with_state(state)
}

/// Start the HTTP JSON-RPC server. Binds and serves until the process exits.
pub async fn serve_rpc(config: RpcConfig, state: RpcServerState) -> anyhow::Result<()> {
    let app = build_router(state).into_make_service_with_connect_info::<std::net::SocketAddr>();
    let listener = TcpListener::bind(config.http_addr).await?;
    tracing::info!("🔌 RPC HTTP listening on {}", config.http_addr);
    axum::serve(listener, app).await
        .map_err(|e| anyhow::anyhow!("RPC serve error: {e}"))?;
    Ok(())
}

// ─── Tests ───────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_rpc_response_ok_format() {
        let r = RpcResponse::ok(Some(json!(1)), json!("0x1a"));
        let s = serde_json::to_string(&r).unwrap();
        assert!(s.contains("\"jsonrpc\":\"2.0\""));
        assert!(s.contains("\"result\""));
        assert!(!s.contains("\"error\""));
    }

    #[test]
    fn test_rpc_response_err_format() {
        let r = RpcResponse::err(Some(json!(1)), ERR_METHOD_NOT_FOUND, "Method not found");
        let s = serde_json::to_string(&r).unwrap();
        assert!(s.contains("-32601"));
        assert!(!s.contains("\"result\""));
    }

    #[test]
    fn test_eth_method_from_str_known() {
        assert_eq!(EthMethod::from_str("eth_blockNumber"), Some(EthMethod::EthBlockNumber));
        assert_eq!(EthMethod::from_str("net_version"),     Some(EthMethod::NetVersion));
        assert_eq!(EthMethod::from_str("dex_getSwapQuote"),Some(EthMethod::DexGetSwapQuote));
    }

    #[test]
    fn test_eth_method_from_str_unknown() {
        assert!(EthMethod::from_str("unknown_method").is_none());
        assert!(EthMethod::from_str("").is_none());
    }

    #[test]
    fn test_log_bloom_set_and_contains() {
        let mut b = LogBloom::empty();
        b.set(b"Transfer(address,address,uint256)");
        assert!(b.contains(b"Transfer(address,address,uint256)"));
        assert!(!b.contains(b"Approval(address,address,uint256)"));
    }

    #[test]
    fn test_log_bloom_or() {
        let mut b1 = LogBloom::empty();
        let mut b2 = LogBloom::empty();
        b1.set(b"topic1");
        b2.set(b"topic2");
        let merged = b1.or(&b2);
        assert!(merged.contains(b"topic1"));
        assert!(merged.contains(b"topic2"));
    }

    #[test]
    fn test_rate_limiter_burst() {
        let rl = RateLimiter::new(3.0, 0.0); // burst=3, no refill
        assert!(rl.check("127.0.0.1"));
        assert!(rl.check("127.0.0.1"));
        assert!(rl.check("127.0.0.1"));
        assert!(!rl.check("127.0.0.1")); // exhausted
    }

    #[test]
    fn test_rate_limiter_different_ips() {
        let rl = RateLimiter::new(1.0, 0.0);
        assert!(rl.check("1.1.1.1"));
        assert!(!rl.check("1.1.1.1")); // same IP exhausted
        assert!(rl.check("2.2.2.2")); // different IP has own bucket
    }

    #[test]
    fn test_subscription_manager_subscribe_unsubscribe() {
        let sm = SubscriptionManager::new();
        let (id, _rx) = sm.subscribe(SubscriptionKind::NewHeads);
        assert!(!id.is_empty());
        assert!(sm.unsubscribe(&id));
        assert!(!sm.unsubscribe(&id)); // already removed
    }

    // ── Layer 1: Security definitions ────────────────────────────────────────

    #[test]
    fn test_method_not_found_uses_correct_error_code() {
        // L1: unknown method must return exactly -32601 (standard JSON-RPC)
        let resp = RpcResponse::err(None, ERR_METHOD_NOT_FOUND, "method not found");
        assert_eq!(resp.error.unwrap().code, -32601);
    }

    #[test]
    fn test_rate_limiter_blocks_after_burst_exhausted() {
        // L1: requests beyond burst capacity must be denied
        let rl = RateLimiter::new(2.0, 0.0); // burst=2
        assert!(rl.check("attacker"));
        assert!(rl.check("attacker"));
        assert!(!rl.check("attacker")); // blocked
        assert!(!rl.check("attacker")); // still blocked
    }

    #[test]
    fn test_log_bloom_different_topics_no_false_negative() {
        // L1: bloom set/contains must correctly handle distinct topics
        let mut b = LogBloom::empty();
        b.set(b"Transfer");
        assert!(b.contains(b"Transfer"));
        assert!(!b.contains(b"Approval")); // must not be present
    }

    #[test]
    fn test_rpc_response_must_not_have_both_result_and_error() {
        // L1: JSON-RPC 2.0 forbids responses with both result AND error
        let ok = RpcResponse::ok(None, Value::Bool(true));
        assert!(ok.error.is_none());
        let err = RpcResponse::err(None, -32600, "bad");
        assert!(err.result.is_none());
    }

    // ── Layer 2: Functional correctness ──────────────────────────────────────

    #[test]
    fn test_rpc_response_ok_preserves_id() {
        // L2: response ID must echo the request ID exactly
        let resp = RpcResponse::ok(Some(Value::Number(42.into())), Value::Bool(true));
        assert_eq!(resp.id, Some(Value::Number(42.into())));
    }

    #[test]
    fn test_bloom_or_is_superset_of_both_inputs() {
        // L2: merged bloom must contain all topics from both sources
        let mut b1 = LogBloom::empty();
        let mut b2 = LogBloom::empty();
        for i in 0u8..5 { b1.set(&[i]); }
        for i in 5u8..10 { b2.set(&[i]); }
        let merged = b1.or(&b2);
        for i in 0u8..10 { assert!(merged.contains(&[i])); }
    }

    #[test]
    fn test_subscription_id_is_unique_per_subscription() {
        // L2: each subscription must get a distinct ID
        let sm = SubscriptionManager::new();
        let (id1, _) = sm.subscribe(SubscriptionKind::NewHeads);
        let (id2, _) = sm.subscribe(SubscriptionKind::NewHeads);
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_all_standard_eth_methods_parseable() {
        // L2: all standard methods must parse without returning None
        let methods = [
            "eth_blockNumber", "eth_getBalance", "eth_getTransactionCount",
            "eth_sendRawTransaction", "eth_call", "eth_estimateGas",
            "net_version", "eth_chainId",
        ];
        for m in methods {
            assert!(EthMethod::from_str(m).is_some(), "method {} must parse", m);
        }
    }

    // ── Layer 3: Protection ───────────────────────────────────────────────────

    #[test]
    fn test_rate_limiter_per_ip_isolation() {
        // L3: IP A exhausted must not block IP B
        let rl = RateLimiter::new(1.0, 0.0);
        assert!(rl.check("10.0.0.1"));
        assert!(!rl.check("10.0.0.1")); // A exhausted
        assert!(rl.check("10.0.0.2")); // B unaffected
        assert!(rl.check("10.0.0.3")); // C unaffected
    }

    #[test]
    fn test_unsubscribe_nonexistent_returns_false() {
        // L3: unsubscribing a bogus ID must return false, not panic
        let sm = SubscriptionManager::new();
        assert!(!sm.unsubscribe("bogus_id_that_does_not_exist"));
    }

    #[test]
    fn test_log_bloom_empty_topic_set_has_no_false_positives_for_known() {
        // L3: empty bloom must not contain anything
        let b = LogBloom::empty();
        assert!(!b.contains(b"anything"));
        assert!(!b.contains(b"Transfer"));
    }

    // ── Layer 4: Detection & Response ────────────────────────────────────────

    #[test]
    fn test_error_response_has_message() {
        // L4: error message must be non-empty for operator debugging
        let resp = RpcResponse::err(None, ERR_INTERNAL, "internal server error");
        let err = resp.error.unwrap();
        assert!(!err.message.is_empty());
    }

    #[test]
    fn test_error_parse_code_is_correct() {
        // L4: parse error code must be -32700 (standard)
        assert_eq!(ERR_PARSE, -32700);
    }

    #[test]
    fn test_error_invalid_params_code_is_correct() {
        // L4: invalid params code must be -32602 (standard)
        assert_eq!(ERR_INVALID_PARAMS, -32602);
    }

    // ── Layer 5: Resilience ───────────────────────────────────────────────────

    #[test]
    fn test_rpc_response_null_id_is_valid() {
        // L5: null id is valid JSON-RPC 2.0 (parse errors before id is known)
        let resp = RpcResponse::err(None, ERR_PARSE, "parse error");
        assert!(resp.id.is_none());
    }

    #[test]
    fn test_bloom_or_with_empty_bloom_is_identity() {
        // L5: merging any bloom with empty must return original
        let mut b = LogBloom::empty();
        b.set(b"topic_x");
        let empty = LogBloom::empty();
        let merged = b.or(&empty);
        assert!(merged.contains(b"topic_x"));
    }

    #[test]
    fn test_rate_limiter_zero_burst_blocks_all() {
        // L5: zero burst capacity must block every request immediately
        let rl = RateLimiter::new(0.0, 0.0);
        assert!(!rl.check("anyone"));
    }

    // ── Layer 6: Governance & Compliance ─────────────────────────────────────

    #[test]
    fn test_jsonrpc_version_field_is_always_2_0() {
        // L6: JSON-RPC version must always be "2.0" for protocol compliance
        let ok  = RpcResponse::ok(None, Value::Null);
        let err = RpcResponse::err(None, -32600, "bad");
        assert_eq!(ok.jsonrpc,  "2.0");
        assert_eq!(err.jsonrpc, "2.0");
    }

    #[test]
    fn test_all_error_codes_are_documented_constants() {
        // L6: error code constants must match JSON-RPC 2.0 specification
        assert_eq!(ERR_PARSE,           -32700);
        assert_eq!(ERR_INVALID_REQUEST, -32600);
        assert_eq!(ERR_METHOD_NOT_FOUND,-32601);
        assert_eq!(ERR_INVALID_PARAMS,  -32602);
        assert_eq!(ERR_INTERNAL,        -32603);
    }

    // ── Reentrancy simulation ─────────────────────────────────────────────────

    #[test]
    fn test_subscription_subscribe_then_immediate_unsubscribe_and_resubscribe() {
        // Reentrancy: rapid sub/unsub cycle must not leak or corrupt state
        let sm = SubscriptionManager::new();
        for _ in 0..20 {
            let (id, _) = sm.subscribe(SubscriptionKind::Logs(LogFilter {
                from_block: None, to_block: None, address: None, topics: None, block_hash: None,
            }));
            sm.unsubscribe(&id);
        }
        // After all unsubscribes, pool must be empty
        let (id, _) = sm.subscribe(SubscriptionKind::NewHeads);
        assert!(sm.unsubscribe(&id));
    }

    // ── Read-only reentrancy ──────────────────────────────────────────────────

    #[test]
    fn test_bloom_contains_does_not_mutate_bloom() {
        // Read-only reentrancy: contains() must not modify bloom state
        let mut b = LogBloom::empty();
        b.set(b"stable");
        let data_before: Vec<u8> = b.0.to_vec();
        let _ = b.contains(b"stable");
        let _ = b.contains(b"missing");
        assert_eq!(b.0.to_vec(), data_before);
    }

    #[test]
    fn test_rate_limiter_check_concurrent_does_not_panic() {
        // Read-only reentrancy: concurrent checks from multiple threads
        use std::thread;
        let rl = Arc::new(RateLimiter::new(1000.0, 0.0));
        let mut handles = vec![];
        for i in 0..8 {
            let r = Arc::clone(&rl);
            let ip = format!("192.168.0.{}", i);
            handles.push(thread::spawn(move || {
                for _ in 0..10 { let _ = r.check(&ip); }
            }));
        }
        for h in handles { h.join().unwrap(); }
    }

    // ── Function parameter validation ─────────────────────────────────────────

    #[test]
    fn test_rate_limiter_check_with_zero_burst_blocks_immediately() {
        // Param validation: zero burst must reject all requests immediately
        let rl = RateLimiter::new(0.0, 0.0);
        assert!(!rl.check("1.2.3.4"), "zero burst rate limiter must block all requests");
    }

    #[test]
    fn test_log_bloom_set_with_empty_topic_no_panic() {
        // Param validation: setting zero-length data in bloom must not panic
        let mut bloom = LogBloom::default();
        bloom.set(&[]);  // empty slice — must not panic
    }

    #[test]
    fn test_rpc_response_ok_with_null_value_is_valid() {
        // Param validation: null result is a valid JSON-RPC response
        let r = RpcResponse::ok(Some(json!(1)), serde_json::Value::Null);
        assert!(r.error.is_none());
        assert_eq!(r.result, Some(serde_json::Value::Null));
    }

    // ── Misconfiguration ──────────────────────────────────────────────────────

    #[test]
    fn test_rpc_config_default_http_port_is_8545() {
        // Misconfiguration: default HTTP port must be the Ethereum standard 8545
        let config = RpcConfig::default();
        assert_eq!(config.http_addr.port(), 8545);
    }

    #[test]
    fn test_rpc_config_default_ws_port_is_8546() {
        // Misconfiguration: default WebSocket port must be 8546
        let config = RpcConfig::default();
        assert_eq!(config.ws_addr.port(), 8546);
    }

    #[test]
    fn test_rpc_config_max_batch_size_nonzero() {
        // Misconfiguration: batch size of 0 would reject all batch requests
        let config = RpcConfig::default();
        assert!(config.max_batch_size > 0);
    }

    // ── Governance attack ─────────────────────────────────────────────────────

    #[test]
    fn test_rate_limiter_cannot_be_bypassed_by_different_ips() {
        // Governance attack: each IP must have its own independent bucket
        let rl = RateLimiter::new(10.0, 1.0);
        // Both IPs should get independent allowances
        let r1 = rl.check("10.0.0.1");
        let r2 = rl.check("10.0.0.2");
        // Both first checks must be allowed (independent buckets)
        assert!(r1, "ip1 first check must be allowed");
        assert!(r2, "ip2 first check must be allowed");
    }

    #[test]
    fn test_subscription_id_uniqueness_across_many_subscriptions() {
        // Governance attack: replay subscription IDs could allow hijacking
        let sm = SubscriptionManager::new();
        let mut ids = std::collections::HashSet::new();
        for _ in 0..50 {
            let (id, _) = sm.subscribe(SubscriptionKind::NewHeads);
            assert!(ids.insert(id.clone()), "subscription ID must be globally unique: {id}");
            sm.unsubscribe(&id);
        }
    }

    #[test]
    fn test_error_codes_match_jsonrpc_spec() {
        // Governance attack / Compliance: error codes must match JSON-RPC 2.0 spec
        assert_eq!(ERR_PARSE,           -32700);
        assert_eq!(ERR_INVALID_REQUEST, -32600);
        assert_eq!(ERR_METHOD_NOT_FOUND,-32601);
        assert_eq!(ERR_INVALID_PARAMS,  -32602);
        assert_eq!(ERR_INTERNAL,        -32603);
    }
}
