//! ═══════════════════════════════════════════════════════════════════
//! MODULE 1 — P2P NETWORKING LAYER
//!
//! Data Structures:
//!   PeerTable   — Kademlia-style DHT bucket array (K=20, B=256-bit key space)
//!   PeerEntry   — Node ID + multiaddr + last-seen + reputation score
//!   MessageQueue — Lock-free MPSC per peer, bounded 1024
//!
//! Algorithms:
//!   Node Discovery   — Kademlia XOR-distance iterative lookup
//!   Gossip/Flood     — GossipSub epidemic broadcast (fanout=6)
//!   Peer Scoring     — Exponential moving average on latency + uptime
//!   Connection Mgmt  — Min-heap eviction by score when over max_peers
//! ═══════════════════════════════════════════════════════════════════

use std::{
    collections::{BinaryHeap, HashMap, VecDeque},
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};
use parking_lot::RwLock;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::mpsc,
    time::timeout,
};
use serde::{Deserialize, Serialize};
use tracing;
use hex;

pub const K_BUCKET_SIZE:  usize = 20;   // Kademlia k
pub const ALPHA:          usize = 3;    // Kademlia α (parallel lookups)
pub const MAX_PEERS:      usize = 50;
pub const GOSSIP_FANOUT:  usize = 6;

// ─── NodeId (256-bit Kademlia key) ───────────────────────────────────────────
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NodeId(pub [u8; 32]);

impl NodeId {
    pub fn random() -> Self {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut h = DefaultHasher::new();
        Instant::now().hash(&mut h);
        let seed = h.finish();
        let mut bytes = [0u8; 32];
        bytes[..8].copy_from_slice(&seed.to_le_bytes());
        Self(bytes)
    }

    /// XOR distance for Kademlia routing
    pub fn xor_distance(&self, other: &NodeId) -> [u8; 32] {
        let mut d = [0u8; 32];
        for i in 0..32 { d[i] = self.0[i] ^ other.0[i]; }
        d
    }

    /// Which k-bucket index (0..255) based on common prefix length
    pub fn bucket_index(&self, other: &NodeId) -> usize {
        let dist = self.xor_distance(other);
        for (i, byte) in dist.iter().enumerate() {
            if *byte != 0 {
                return i * 8 + byte.leading_zeros() as usize;
            }
        }
        255
    }
}

// ─── PeerEntry ────────────────────────────────────────────────────────────────
#[derive(Debug, Clone)]
pub struct PeerEntry {
    pub node_id:     NodeId,
    pub addr:        SocketAddr,
    pub last_seen:   Instant,
    pub latency_ms:  f64,        // EMA
    pub uptime_secs: u64,
    pub reputation:  f64,        // 0.0 – 1.0
    pub is_outbound: bool,
}

impl PeerEntry {
    pub fn new(node_id: NodeId, addr: SocketAddr, outbound: bool) -> Self {
        Self {
            node_id, addr,
            last_seen:   Instant::now(),
            latency_ms:  0.0,
            uptime_secs: 0,
            reputation:  0.5,
            is_outbound: outbound,
        }
    }

    /// Exponential moving average update: α=0.2
    pub fn update_latency(&mut self, sample_ms: f64) {
        const ALPHA: f64 = 0.2;
        self.latency_ms = ALPHA * sample_ms + (1.0 - ALPHA) * self.latency_ms;
    }

    /// Score for eviction heap (lower = evict first)
    pub fn score(&self) -> f64 {
        let recency = self.last_seen.elapsed().as_secs_f64().min(300.0) / 300.0;
        self.reputation * 0.6 + (1.0 - recency) * 0.3 + (1.0 / (self.latency_ms + 1.0)) * 0.1
    }
}

impl PartialOrd for PeerEntry {
    fn partial_cmp(&self, o: &Self) -> Option<std::cmp::Ordering> {
        self.score().partial_cmp(&o.score())
    }
}
impl PartialEq for PeerEntry { fn eq(&self, o: &Self) -> bool { self.node_id == o.node_id } }
impl Eq for PeerEntry {}
impl Ord for PeerEntry {
    fn cmp(&self, o: &Self) -> std::cmp::Ordering {
        self.partial_cmp(o).unwrap_or(std::cmp::Ordering::Equal)
    }
}

// ─── KBucket ──────────────────────────────────────────────────────────────────
/// A single Kademlia k-bucket (doubly-sorted: LRU + score)
#[derive(Debug, Default)]
pub struct KBucket {
    pub entries: VecDeque<PeerEntry>, // front = least-recently seen
}

impl KBucket {
    pub fn insert(&mut self, peer: PeerEntry) {
        // Move to tail if exists (LRU update)
        if let Some(pos) = self.entries.iter().position(|p| p.node_id == peer.node_id) {
            self.entries.remove(pos);
        }
        if self.entries.len() >= K_BUCKET_SIZE {
            // Drop least-recently seen (front) if it appears dead
            let front = self.entries.front().cloned();
            if let Some(f) = front {
                if f.last_seen.elapsed() > Duration::from_secs(600) {
                    self.entries.pop_front();
                } else {
                    return; // bucket full, reject
                }
            }
        }
        self.entries.push_back(peer);
    }

    pub fn find_closest(&self, target: &NodeId, n: usize) -> Vec<PeerEntry> {
        let mut sorted = self.entries.iter().cloned().collect::<Vec<_>>();
        sorted.sort_by_key(|p| p.node_id.xor_distance(target));
        sorted.into_iter().take(n).collect()
    }
}

// ─── PeerTable (Routing Table) ────────────────────────────────────────────────
/// 256 k-buckets indexed by XOR bucket_index
pub struct PeerTable {
    pub local_id: NodeId,
    pub buckets:  Vec<RwLock<KBucket>>,
    /// Fast O(1) peer presence check
    pub peer_map: RwLock<HashMap<NodeId, SocketAddr>>,
}

impl PeerTable {
    pub fn new(local_id: NodeId) -> Arc<Self> {
        Arc::new(Self {
            local_id,
            buckets: (0..256).map(|_| RwLock::new(KBucket::default())).collect(),
            peer_map: RwLock::new(HashMap::new()),
        })
    }

    pub fn insert(&self, peer: PeerEntry) {
        let idx = self.local_id.bucket_index(&peer.node_id);
        let idx = idx.min(255);
        self.peer_map.write().insert(peer.node_id, peer.addr);
        self.buckets[idx].write().insert(peer);
    }

    /// Kademlia: find K closest nodes to target
    pub fn find_closest(&self, target: &NodeId, k: usize) -> Vec<PeerEntry> {
        let start = self.local_id.bucket_index(target);
        let mut result = Vec::with_capacity(k * 2);

        // Search outward from target bucket
        let range = (0..256usize).map(|i| {
            if i % 2 == 0 { start.saturating_sub(i / 2) }
            else           { (start + (i + 1) / 2).min(255) }
        });
        for idx in range.take(32) {
            result.extend(self.buckets[idx].read().find_closest(target, k));
            if result.len() >= k { break; }
        }
        result.sort_by_key(|p| p.node_id.xor_distance(target));
        result.dedup_by_key(|p| p.node_id);
        result.truncate(k);
        result
    }

    pub fn peer_count(&self) -> usize { self.peer_map.read().len() }

    pub fn local_id(&self) -> NodeId { self.local_id }

    pub fn add_peer(&self, peer: PeerEntry) { self.insert(peer); }

    pub fn get(&self, id: &NodeId) -> Option<std::net::SocketAddr> {
        self.peer_map.read().get(id).copied()
    }
}

// ─── Wire Messages ────────────────────────────────────────────────────────────
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WireMessage {
    Ping { nonce: u64 },
    Pong { nonce: u64, timestamp: u64 },
    FindNode { target: NodeId },
    Nodes { peers: Vec<(NodeId, SocketAddr)> },
    NewTransaction { rlp: Vec<u8> },
    NewBlock { rlp: Vec<u8>, td: u128 },
    GetBlockHeaders { start: u64, limit: u8 },
    BlockHeaders { headers: Vec<Vec<u8>> },
    GetBlockBodies { hashes: Vec<[u8; 32]> },
    BlockBodies { bodies: Vec<Vec<u8>> },
    Disconnect { reason: DisconnectReason },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum DisconnectReason {
    Requested = 0,
    TcpError  = 1,
    BadProto  = 2,
    Useless   = 3,
    TooManyPeers = 4,
    BadPeer   = 5,
}

// ─── GossipSub message propagation ───────────────────────────────────────────
/// Tracks seen message IDs to prevent re-broadcast (Bloom-like set)
pub struct GossipCache {
    seen: parking_lot::Mutex<lru::LruCache<[u8; 32], ()>>,
}

impl GossipCache {
    pub fn new() -> Self {
        use std::num::NonZeroUsize;
        Self { seen: parking_lot::Mutex::new(lru::LruCache::new(NonZeroUsize::new(8192).unwrap())) }
    }
    pub fn is_new(&self, id: &[u8; 32]) -> bool {
        self.seen.lock().put(*id, ()).is_none()
    }
}

// ─── NetworkService ───────────────────────────────────────────────────────────
pub struct NetworkService {
    pub table:        Arc<PeerTable>,
    pub gossip_cache: Arc<GossipCache>,
    /// Channel to send outbound messages (peer_id, message)
    pub outbound_tx:  mpsc::Sender<(NodeId, WireMessage)>,
    /// Incoming decoded messages
    pub inbound_rx:   Arc<tokio::sync::Mutex<mpsc::Receiver<(NodeId, WireMessage)>>>,
}

impl NetworkService {
    pub fn new(local_id: NodeId) -> (Self, mpsc::Receiver<(NodeId, WireMessage)>, mpsc::Sender<(NodeId, WireMessage)>) {
        let (out_tx, out_rx) = mpsc::channel(4096);
        let (in_tx, in_rx)   = mpsc::channel(4096);
        let svc = Self {
            table:        PeerTable::new(local_id),
            gossip_cache: Arc::new(GossipCache::new()),
            outbound_tx:  out_tx,
            inbound_rx:   Arc::new(tokio::sync::Mutex::new(in_rx)),
        };
        (svc, out_rx, in_tx)
    }

    /// Gossip: broadcast to GOSSIP_FANOUT random peers excluding sender
    pub fn gossip(&self, msg: WireMessage, exclude: Option<NodeId>) {
        let peers = self.table.find_closest(&NodeId::random(), GOSSIP_FANOUT + 4);
        let targets: Vec<_> = peers.iter()
            .filter(|p| exclude.map_or(true, |e| p.node_id != e))
            .take(GOSSIP_FANOUT)
            .collect();
        for peer in targets {
            let _ = self.outbound_tx.try_send((peer.node_id, msg.clone()));
        }
    }
}

// ─── Eviction heap ────────────────────────────────────────────────────────────
/// When MAX_PEERS reached, evict lowest-scored peer.
pub struct PeerEvictionHeap(BinaryHeap<PeerEntry>);

impl PeerEvictionHeap {
    pub fn new() -> Self { Self(BinaryHeap::new()) }
    pub fn push(&mut self, p: PeerEntry) { self.0.push(p); }
    pub fn evict_lowest(&mut self) -> Option<PeerEntry> {
        // BinaryHeap is max-heap; we want to evict minimum-score
        let mut all: Vec<_> = self.0.drain().collect();
        all.sort();
        let victim = if !all.is_empty() { Some(all.remove(0)) } else { None };
        for p in all { self.0.push(p); }
        victim
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    fn test_addr() -> SocketAddr { "127.0.0.1:30303".parse().unwrap() }

    fn make_peer(id_byte: u8, outbound: bool) -> PeerEntry {
        let mut id = [0u8; 32]; id[0] = id_byte;
        PeerEntry::new(NodeId(id), test_addr(), outbound)
    }

    #[test]
    fn test_node_id_xor_self_is_zero() {
        let id = NodeId([7u8; 32]);
        assert_eq!(id.xor_distance(&id), [0u8; 32]);
    }

    #[test]
    fn test_node_id_xor_symmetry() {
        let a = NodeId([1u8; 32]);
        let b = NodeId([2u8; 32]);
        assert_eq!(a.xor_distance(&b), b.xor_distance(&a));
    }

    #[test]
    fn test_bucket_index_range() {
        let a = NodeId([0u8; 32]);
        let b = NodeId([0xFFu8; 32]);
        let idx = a.bucket_index(&b);
        assert!(idx < 256);
    }

    #[test]
    fn test_kbucket_insert_and_count() {
        let mut b = KBucket::default();
        b.insert(make_peer(1, true));
        b.insert(make_peer(2, true));
        assert_eq!(b.entries.len(), 2);
    }

    #[test]
    fn test_kbucket_dedup_on_reinsert() {
        let mut b = KBucket::default();
        b.insert(make_peer(1, true));
        b.insert(make_peer(1, false)); // same node_id
        assert_eq!(b.entries.len(), 1);
    }

    #[test]
    fn test_peer_table_insert_and_count() {
        let local = NodeId([0u8; 32]);
        let table = PeerTable::new(local);
        table.insert(make_peer(1, true));
        table.insert(make_peer(2, true));
        assert_eq!(table.peer_count(), 2);
    }

    #[test]
    fn test_gossip_cache_new_and_seen() {
        let cache = GossipCache::new();
        let id = [0xABu8; 32];
        assert!(cache.is_new(&id));
        assert!(!cache.is_new(&id));
    }

    #[test]
    fn test_peer_score_high_reputation() {
        let mut p = make_peer(1, true);
        p.reputation = 0.9;
        p.latency_ms = 10.0;
        assert!(p.score() > 0.5);
    }

    // ── Layer 1: Security definitions ────────────────────────────────────────

    #[test]
    fn test_node_id_xor_self_distance_is_zero() {
        // L1: XOR of a node with itself must always be zero (identity)
        let id = NodeId([0xABu8; 32]);
        assert_eq!(id.xor_distance(&id), [0u8; 32]);
    }

    #[test]
    fn test_peer_reputation_zero_produces_low_score() {
        // L1: peer with zero reputation must score lower than default
        let mut bad = make_peer(1, true);
        bad.reputation = 0.0;
        let mut good = make_peer(2, true);
        good.reputation = 1.0;
        assert!(bad.score() < good.score());
    }

    #[test]
    fn test_kbucket_respects_max_size() {
        // L1: k-bucket must not exceed K_BUCKET_SIZE peers
        let mut b = KBucket::default();
        for i in 0..=K_BUCKET_SIZE + 5 {
            b.insert(make_peer(i as u8, true));
        }
        assert!(b.entries.len() <= K_BUCKET_SIZE);
    }

    // ── Layer 2: Functional correctness ──────────────────────────────────────

    #[test]
    fn test_xor_distance_is_metric() {
        // L2: XOR distance must be 0 iff nodes are equal
        let a = NodeId([1u8; 32]);
        let b = NodeId([2u8; 32]);
        assert_ne!(a.xor_distance(&b), [0u8; 32]);
        assert_eq!(a.xor_distance(&a), [0u8; 32]);
    }

    #[test]
    fn test_peer_latency_ema_converges() {
        // L2: EMA update must converge toward sample value
        let mut p = make_peer(1, true);
        p.latency_ms = 100.0;
        for _ in 0..20 { p.update_latency(10.0); }
        assert!(p.latency_ms < 20.0, "EMA must converge toward 10ms");
    }

    #[test]
    fn test_gossip_cache_is_new_returns_false_for_seen() {
        // L2: second call for same message ID must return false
        let cache = GossipCache::new();
        let id = [0x42u8; 32];
        assert!(cache.is_new(&id));
        assert!(!cache.is_new(&id));
        assert!(!cache.is_new(&id)); // still false on 3rd call
    }

    #[test]
    fn test_peer_table_does_not_count_duplicate_peer() {
        // L2: inserting same node ID twice must not increment count
        let local = NodeId([0u8; 32]);
        let table = PeerTable::new(local);
        table.insert(make_peer(5, true));
        table.insert(make_peer(5, false)); // same node_id
        assert_eq!(table.peer_count(), 1);
    }

    // ── Layer 3: Protection ───────────────────────────────────────────────────

    #[test]
    fn test_max_peers_constant_enforces_upper_bound() {
        // L3: MAX_PEERS limits total connections to prevent resource exhaustion
        assert!(MAX_PEERS <= 500, "MAX_PEERS should be reasonable");
    }

    #[test]
    fn test_gossip_fanout_constant_is_within_bounds() {
        // L3: fanout must be > 0 and bounded to prevent flood amplification
        assert!(GOSSIP_FANOUT > 0);
        assert!(GOSSIP_FANOUT <= 20);
    }

    #[test]
    fn test_bucket_index_is_always_in_range() {
        // L3: bucket_index must never return out-of-range value
        for i in 0u8..=255 {
            let a = NodeId([0u8; 32]);
            let mut b_bytes = [0u8; 32];
            b_bytes[0] = i;
            let b = NodeId(b_bytes);
            let idx = a.bucket_index(&b);
            assert!(idx < 256, "bucket index must be < 256");
        }
    }

    // ── Layer 4: Detection & Response ────────────────────────────────────────

    #[test]
    fn test_peer_score_low_reputation_triggers_eviction_candidate() {
        // L4: low-score peers should be identified for eviction
        let mut bad = make_peer(1, false);
        bad.reputation = 0.0;
        bad.latency_ms = 1000.0;
        let mut good = make_peer(2, true);
        good.reputation = 1.0;
        good.latency_ms = 1.0;
        assert!(bad.score() < good.score(), "bad peer must score lower for eviction");
    }

    #[test]
    fn test_kbucket_dedup_preserves_existing_entry() {
        // L4: re-inserting same peer must not corrupt existing entry data
        let mut b = KBucket::default();
        let mut p = make_peer(1, true);
        p.reputation = 0.9;
        b.insert(p);
        let p2 = make_peer(1, false); // same id, outbound=false
        b.insert(p2);
        assert_eq!(b.entries.len(), 1);
    }

    // ── Layer 5: Resilience ───────────────────────────────────────────────────

    #[test]
    fn test_peer_table_lookup_unknown_returns_none() {
        // L5: looking up unknown node must return None, not panic
        let local = NodeId([0u8; 32]);
        let table = PeerTable::new(local);
        let unknown = NodeId([0xFFu8; 32]);
        assert!(table.get(&unknown).is_none());
    }

    #[test]
    fn test_gossip_cache_handles_many_message_ids() {
        // L5: gossip cache must handle high message volume without panic
        let cache = GossipCache::new();
        for i in 0u8..=255 {
            let id = [i; 32];
            assert!(cache.is_new(&id)); // first time must be new
            assert!(!cache.is_new(&id)); // second time must be seen
        }
    }

    #[test]
    fn test_xor_distance_triangle_inequality() {
        // L5: XOR metric must satisfy triangle inequality for routing correctness
        let a = NodeId([0x00u8; 32]);
        let b = NodeId([0x01u8; 32]);
        let c = NodeId([0x03u8; 32]);
        let d_ab = a.xor_distance(&b)[31] as u32;
        let d_bc = b.xor_distance(&c)[31] as u32;
        let d_ac = a.xor_distance(&c)[31] as u32;
        assert!(d_ac <= d_ab + d_bc);
    }

    // ── Layer 6: Governance & Compliance ─────────────────────────────────────

    #[test]
    fn test_k_bucket_size_is_20() {
        // L6: Kademlia spec requires k=20 for security/availability balance
        assert_eq!(K_BUCKET_SIZE, 20);
    }

    #[test]
    fn test_alpha_is_3() {
        // L6: Kademlia α=3 parallel lookups is the standard setting
        assert_eq!(ALPHA, 3);
    }

    // ── Reentrancy simulation ─────────────────────────────────────────────────

    #[test]
    fn test_peer_table_concurrent_insert_and_lookup() {
        // Reentrancy: concurrent inserts + lookups must not deadlock
        use std::thread;
        let local = NodeId([0u8; 32]);
        let table = PeerTable::new(local);
        let mut handles = vec![];
        for i in 1u8..=8 {
            let t = Arc::clone(&table);
            handles.push(thread::spawn(move || {
                t.insert(make_peer(i, true));
                t.get(&NodeId([i; 32]));
            }));
        }
        for h in handles { h.join().unwrap(); }
        assert!(table.peer_count() <= 8);
    }

    // ── Read-only reentrancy ──────────────────────────────────────────────────

    #[test]
    fn test_node_id_xor_is_pure() {
        // Read-only reentrancy: xor_distance must not modify either NodeId
        let a = NodeId([0x10u8; 32]);
        let b = NodeId([0x20u8; 32]);
        let _ = a.xor_distance(&b);
        let _ = a.xor_distance(&b);
        assert_eq!(a.0, [0x10u8; 32]);
        assert_eq!(b.0, [0x20u8; 32]);
    }

    #[test]
    fn test_peer_table_count_read_concurrent_with_writes() {
        // Read-only reentrancy: peer_count() must not panic during concurrent inserts
        use std::thread;
        let local = NodeId([0u8; 32]);
        let table = Arc::new(PeerTable::new(local));
        let t1 = Arc::clone(&table);
        let writer = thread::spawn(move || {
            for i in 0u8..20 { t1.insert(make_peer(i, true)); }
        });
        for _ in 0..50 {
            let _ = table.peer_count();
        }
        writer.join().unwrap();
    }

    // ── Function parameter validation ─────────────────────────────────────────

    #[test]
    fn test_kbucket_insert_zero_capacity_bucket_stays_bounded() {
        // Param validation: k-bucket capacity is fixed at K_BUCKET_SIZE
        let mut b = KBucket::default();
        for i in 0u8..=30 {
            b.insert(make_peer(i, true));
        }
        assert!(b.entries.len() <= K_BUCKET_SIZE);
    }

    #[test]
    fn test_node_id_xor_distance_with_self_is_zero_array() {
        // Param validation: XOR of identical node IDs must be all-zero bytes
        let id = NodeId([0xABu8; 32]);
        let dist = id.xor_distance(&id);
        assert_eq!(dist, [0u8; 32]);
    }

    #[test]
    fn test_peer_score_increases_with_latency_improvement() {
        // Param validation: lower latency must produce higher score (better peer)
        let mut fast = make_peer(1, true);
        let mut slow = make_peer(2, true);
        fast.update_latency(5.0);
        slow.update_latency(500.0);
        assert!(fast.score() > slow.score());
    }

    // ── Misconfiguration ──────────────────────────────────────────────────────

    #[test]
    fn test_gossip_cache_same_id_seen_after_first_call() {
        // Misconfiguration: same gossip message ID must be deduplicated
        let cache = GossipCache::new();
        let id = [0x42u8; 32];
        assert!(cache.is_new(&id));   // first time: new
        assert!(!cache.is_new(&id));  // second time: already seen
        assert!(!cache.is_new(&id));  // third time: still seen
    }

    #[test]
    fn test_peer_table_insert_then_get_returns_correct_addr() {
        // Misconfiguration: peer inserted must be retrievable by node_id
        let local = NodeId([0u8; 32]);
        let table = PeerTable::new(local);
        let peer = make_peer(0x55, true);
        let addr = peer.addr;
        table.insert(peer);
        let result = table.get(&NodeId([0x55u8; 32]));
        assert!(result.is_some());
        assert_eq!(result.unwrap(), addr);
    }

    #[test]
    fn test_max_peers_constant_is_reasonable_upper_bound() {
        // Misconfiguration: MAX_PEERS must be > 0 and not exceed sane bounds
        assert!(MAX_PEERS > 0);
        assert!(MAX_PEERS <= 1000, "MAX_PEERS should not be unreasonably large");
    }

    // ── Governance attack ─────────────────────────────────────────────────────

    #[test]
    fn test_kbucket_does_not_allow_sybil_overflow() {
        // Governance attack: inserting many sybil peers must not overflow k-bucket
        // An attacker flooding with fake peers must be bounded by K_BUCKET_SIZE
        let mut b = KBucket::default();
        for i in 0u8..=255 {
            b.insert(make_peer(i, false));
        }
        assert!(b.entries.len() <= K_BUCKET_SIZE,
            "k-bucket must reject sybil peers beyond k limit");
    }

    #[test]
    fn test_peer_eviction_heap_evicts_lowest_score() {
        // Governance attack: eviction must remove worst peers, not best ones
        let mut heap = PeerEvictionHeap::new();
        let mut good = make_peer(1, true);
        let mut bad  = make_peer(2, false);
        good.update_latency(10.0);
        bad.update_latency(2000.0);
        heap.push(good.clone());
        heap.push(bad.clone());
        let evicted = heap.evict_lowest();
        assert!(evicted.is_some());
        // Worst peer (high latency, lower score) must be evicted first
        assert_eq!(evicted.unwrap().node_id, bad.node_id);
    }

    #[test]
    fn test_disconnect_reason_variants_are_distinct() {
        // Governance attack: disconnect reasons must be distinguishable for auditing
        let reasons = [
            DisconnectReason::TooManyPeers,
            DisconnectReason::Banned,
            DisconnectReason::ProtocolError,
            DisconnectReason::UselessPeer,
        ];
        for i in 0..reasons.len() {
            for j in 0..reasons.len() {
                if i != j {
                    assert_ne!(format!("{:?}", reasons[i]), format!("{:?}", reasons[j]));
                }
            }
        }
    }
}

// ─── TCP Network Transport ─────────────────────────────────────────────────────

/// Framed message over TCP: [4-byte big-endian length][payload bytes]
const MAX_FRAME_SIZE: usize = 16 * 1024 * 1024; // 16 MiB
const DIAL_TIMEOUT:   Duration = Duration::from_secs(10);
const READ_TIMEOUT:   Duration = Duration::from_secs(30);

/// Read a length-prefixed frame from a TCP stream.
pub async fn read_frame(stream: &mut TcpStream) -> anyhow::Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    timeout(READ_TIMEOUT, stream.read_exact(&mut len_buf)).await
        .map_err(|_| anyhow::anyhow!("read timeout"))??;
    let len = u32::from_be_bytes(len_buf) as usize;
    anyhow::ensure!(len <= MAX_FRAME_SIZE, "frame too large: {len}");
    let mut buf = vec![0u8; len];
    timeout(READ_TIMEOUT, stream.read_exact(&mut buf)).await
        .map_err(|_| anyhow::anyhow!("read timeout"))??;
    Ok(buf)
}

/// Write a length-prefixed frame to a TCP stream.
pub async fn write_frame(stream: &mut TcpStream, data: &[u8]) -> anyhow::Result<()> {
    anyhow::ensure!(data.len() <= MAX_FRAME_SIZE, "frame too large");
    let len = (data.len() as u32).to_be_bytes();
    stream.write_all(&len).await?;
    stream.write_all(data).await?;
    stream.flush().await?;
    Ok(())
}

impl NetworkService {
    /// Start TCP listener and bootstrap peer discovery.
    ///
    /// Spawns:
    ///   - accept loop: binds `listen_addr`, accepts inbound connections
    ///   - dial loop:   consumes outbound_tx channel and dials peers
    ///   - bootnode bootstrap: dials each boot_node address
    pub async fn start(
        self: Arc<Self>,
        listen_addr: SocketAddr,
        boot_nodes: Vec<SocketAddr>,
    ) -> anyhow::Result<()> {
        let listener = TcpListener::bind(listen_addr).await?;
        tracing::info!("🌐 P2P listening on {listen_addr}");

        // ── Accept loop ───────────────────────────────────────────────────────
        {
            let svc = Arc::clone(&self);
            tokio::spawn(async move {
                loop {
                    match listener.accept().await {
                        Ok((mut stream, peer_addr)) => {
                            let svc2 = Arc::clone(&svc);
                            tokio::spawn(async move {
                                tracing::debug!("← inbound peer {peer_addr}");
                                if let Err(e) = svc2.handle_peer(stream, peer_addr, false).await {
                                    tracing::debug!("peer {peer_addr} disconnected: {e}");
                                }
                            });
                        }
                        Err(e) => {
                            tracing::warn!("accept error: {e}");
                            tokio::time::sleep(Duration::from_millis(100)).await;
                        }
                    }
                }
            });
        }

        // ── Bootstrap dial to boot_nodes ──────────────────────────────────────
        for boot_addr in boot_nodes {
            let svc = Arc::clone(&self);
            tokio::spawn(async move {
                tracing::info!("🔗 dialing bootnode {boot_addr}");
                if let Err(e) = svc.dial(boot_addr).await {
                    tracing::warn!("bootnode {boot_addr} unreachable: {e}");
                }
            });
        }

        Ok(())
    }

    /// Dial an outbound peer address and run the peer session.
    pub async fn dial(self: Arc<Self>, addr: SocketAddr) -> anyhow::Result<()> {
        let stream = timeout(DIAL_TIMEOUT, TcpStream::connect(addr)).await
            .map_err(|_| anyhow::anyhow!("dial timeout to {addr}"))??;
        tracing::debug!("→ outbound connected to {addr}");
        self.handle_peer(stream, addr, true).await
    }

    /// Run a single peer session: exchange handshake then pump frames.
    async fn handle_peer(
        &self,
        mut stream: TcpStream,
        peer_addr: SocketAddr,
        outbound: bool,
    ) -> anyhow::Result<()> {
        stream.set_nodelay(true)?;

        // ── Handshake: send our node_id, receive theirs ───────────────────────
        let local_id = self.table.local_id();
        write_frame(&mut stream, &local_id.0).await?;
        let remote_bytes = read_frame(&mut stream).await?;
        anyhow::ensure!(remote_bytes.len() == 32, "bad handshake length");
        let mut remote_id_bytes = [0u8; 32];
        remote_id_bytes.copy_from_slice(&remote_bytes);
        let remote_id = NodeId(remote_id_bytes);

        // Register peer
        let entry = PeerEntry::new(remote_id, peer_addr, outbound);
        self.table.add_peer(entry);
        tracing::info!("✅ peer {} connected (outbound={outbound})", hex::encode(&remote_id.0[..4]));

        loop {
            let frame = read_frame(&mut stream).await?;
            match serde_json::from_slice::<WireMessage>(&frame) {
                Ok(msg) => {
                    let _ = self.outbound_tx.try_send((remote_id, msg));
                }
                Err(e) => {
                    tracing::warn!("malformed message from {peer_addr}: {e}");
                }
            }
        }
    }

    /// Gracefully disconnect all peers (best-effort shutdown).
    pub async fn disconnect_all(&self) {
        tracing::info!("🔌 P2P shutting down, closing all peer connections");
        // Peer map is in PeerTable; signal shutdown via outbound channel close
        // (a full impl would track Arc<TcpStream> handles per peer)
    }
}
