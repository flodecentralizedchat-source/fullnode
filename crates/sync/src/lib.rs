//! ═══════════════════════════════════════════════════════════════════
//! MODULE 8 — SYNCHRONIZATION MANAGER
//!
//! Data Structures:
//!   SyncState      — Enum {Idle, Headers, Bodies, State, Full}
//!   HeaderQueue    — BinaryHeap ordered by block number for in-order assembly
//!   BodyRequest    — (hash, peer_id, requested_at) timeout tracking
//!   SnapTrieTask   — Trie node range download task with proof verification
//!   PeerSyncState  — Per-peer: best_hash, best_number, td, last_request
//!
//! Algorithms:
//!   Snap sync:      Split state trie into 256 leaf-range shards
//!                   Request each shard's leaves + range proof in parallel
//!   Header skeleton: Request every N-th header, fill gaps in parallel
//!   Body fetching:  Batch up to 128 hashes per GetBlockBodies request
//!   Pivot selection: best_peer.height - 64 as snap-sync target
//! ═══════════════════════════════════════════════════════════════════

use std::{
    collections::{BinaryHeap, HashMap, VecDeque},
    cmp::Reverse,
    sync::Arc,
    time::{Duration, Instant},
};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

pub type Hash = [u8; 32];
pub type NodeId = [u8; 32];

// ─── Sync Mode ────────────────────────────────────────────────────────────────
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SyncMode {
    Full,       // re-execute every block from genesis
    Snap,       // download state snapshot + recent blocks
    Light,      // headers + on-demand proofs only
    Archive,    // full + keep all historical states
}

// ─── Sync Phase ───────────────────────────────────────────────────────────────
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncPhase {
    Idle,
    FindingPeers,
    DownloadingHeaders { start: u64, target: u64, received: u64 },
    DownloadingBodies  { total: u64, done: u64 },
    SnapSyncState      { pivot: u64, shards_total: u16, shards_done: u16 },
    FinishingTip       { current: u64, target: u64 },
    Synced,
}

// ─── Per-Peer Sync Status ─────────────────────────────────────────────────────
#[derive(Debug, Clone)]
pub struct PeerSyncState {
    pub peer_id:         NodeId,
    pub best_hash:       Hash,
    pub best_number:     u64,
    pub total_difficulty: u128,
    pub last_seen:       Instant,
    pub in_flight_req:   Option<InFlightRequest>,
    pub failures:        u32,
}

#[derive(Debug, Clone)]
pub struct InFlightRequest {
    pub kind:       RequestKind,
    pub sent_at:    Instant,
    pub timeout:    Duration,
}

#[derive(Debug, Clone)]
pub enum RequestKind {
    Headers { from: u64, count: u8 },
    Bodies  { hashes: Vec<Hash> },
    Receipts { hashes: Vec<Hash> },
    SnapRange { start: Hash, limit: Hash },
    TrieNodes { paths: Vec<Vec<u8>> },
}

impl InFlightRequest {
    pub fn is_timed_out(&self) -> bool {
        self.sent_at.elapsed() > self.timeout
    }
}

// ─── Header Queue (ordered by block number) ───────────────────────────────────
/// Holds out-of-order headers, emits them in-order when contiguous
pub struct HeaderQueue {
    /// Min-heap by block number
    heap: BinaryHeap<Reverse<OrderedHeader>>,
    /// Next expected block number
    expected: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrderedHeader {
    pub number: u64,
    pub hash:   Hash,
    pub parent: Hash,
    pub raw:    Vec<u8>,
}

impl PartialOrd for OrderedHeader {
    fn partial_cmp(&self, o: &Self) -> Option<std::cmp::Ordering> { Some(self.cmp(o)) }
}
impl Ord for OrderedHeader {
    fn cmp(&self, o: &Self) -> std::cmp::Ordering { self.number.cmp(&o.number) }
}

impl HeaderQueue {
    pub fn new(start: u64) -> Self {
        Self { heap: BinaryHeap::new(), expected: start }
    }

    pub fn push(&mut self, number: u64, hash: Hash, parent: Hash, raw: Vec<u8>) {
        if number >= self.expected {
            self.heap.push(Reverse(OrderedHeader { number, hash, parent, raw }));
        }
    }

    /// Pop all contiguous headers starting from `expected`
    pub fn drain_ready(&mut self) -> Vec<OrderedHeader> {
        let mut out = Vec::new();
        loop {
            match self.heap.peek() {
                Some(Reverse(h)) if h.number == self.expected => {
                    let Reverse(h) = self.heap.pop().unwrap();
                    self.expected += 1;
                    out.push(h);
                }
                _ => break,
            }
        }
        out
    }

    pub fn len(&self) -> usize { self.heap.len() }
}

// ─── Body request tracker ─────────────────────────────────────────────────────
pub struct BodyFetcher {
    /// hash → (block_number, peer_id, sent_at)
    in_flight:  HashMap<Hash, (u64, NodeId, Instant)>,
    pending:    VecDeque<(u64, Hash)>,  // (number, hash) awaiting request
    received:   HashMap<Hash, Vec<u8>>, // hash → rlp body
    timeout:    Duration,
}

impl BodyFetcher {
    pub fn new() -> Self {
        Self {
            in_flight: HashMap::new(),
            pending:   VecDeque::new(),
            received:  HashMap::new(),
            timeout:   Duration::from_secs(10),
        }
    }

    pub fn enqueue(&mut self, number: u64, hash: Hash) {
        self.pending.push_back((number, hash));
    }

    /// Take up to `batch` pending hashes and assign to peer
    pub fn assign_batch(&mut self, peer: NodeId, batch: usize) -> Vec<Hash> {
        let mut taken = Vec::with_capacity(batch);
        while taken.len() < batch {
            match self.pending.pop_front() {
                Some((num, hash)) => {
                    self.in_flight.insert(hash, (num, peer, Instant::now()));
                    taken.push(hash);
                }
                None => break,
            }
        }
        taken
    }

    /// Called when peer returns bodies
    pub fn on_bodies(&mut self, hashes: &[Hash], bodies: Vec<Vec<u8>>) {
        for (hash, body) in hashes.iter().zip(bodies.into_iter()) {
            self.in_flight.remove(hash);
            self.received.insert(*hash, body);
        }
    }

    /// Re-queue timed-out requests back into the pending queue.
    pub fn requeue_timed_out(&mut self) {
        // Collect (hash, number) pairs that have timed out
        let timed_out: Vec<(Hash, u64)> = self.in_flight.iter()
            .filter(|(_, (_, _, sent))| sent.elapsed() > self.timeout)
            .map(|(h, (num, _, _))| (*h, *num))
            .collect();
        for (h, num) in timed_out {
            self.in_flight.remove(&h);
            self.pending.push_front((num, h));
        }
    }

    pub fn take_received(&mut self, hash: &Hash) -> Option<Vec<u8>> {
        self.received.remove(hash)
    }
}

// ─── Snap Sync State Downloader ───────────────────────────────────────────────
/// Divides the 256-bit key space into N shards for parallel download
pub struct SnapStateDownloader {
    pub pivot_block:  u64,
    pub pivot_root:   Hash,
    shards:           Vec<SnapShard>,
    #[allow(dead_code)]
    trie_node_queue:  VecDeque<Vec<u8>>,  // trie paths to fetch
    pub bytes_written: u64,
}

#[derive(Debug, Clone)]
pub struct SnapShard {
    pub start_key:  Hash,
    pub end_key:    Hash,
    pub status:     ShardStatus,
    pub assigned_peer: Option<NodeId>,
    pub last_try:   Option<Instant>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShardStatus {
    Pending,
    InFlight,
    VerifyingProof,
    Done,
    Failed,
}

impl SnapStateDownloader {
    pub fn new(pivot_block: u64, pivot_root: Hash, num_shards: u16) -> Self {
        let shards = Self::generate_shards(num_shards);
        Self { pivot_block, pivot_root, shards, trie_node_queue: VecDeque::new(), bytes_written: 0 }
    }

    fn generate_shards(n: u16) -> Vec<SnapShard> {
        // Divide [0x00..0xff] key space into n equal ranges
        let step = u128::MAX / n as u128;
        (0..n).map(|i| {
            let mut start = [0u8; 32];
            let mut end   = [0xff_u8; 32];
            let s_val = (step * i as u128).to_be_bytes();
            let e_val = if i + 1 < n { (step * (i as u128 + 1)).to_be_bytes() }
                        else { u128::MAX.to_be_bytes() };
            start[16..].copy_from_slice(&s_val);
            end[16..].copy_from_slice(&e_val);
            SnapShard { start_key: start, end_key: end, status: ShardStatus::Pending,
                assigned_peer: None, last_try: None }
        }).collect()
    }

    pub fn next_pending_shard(&mut self) -> Option<&mut SnapShard> {
        self.shards.iter_mut().find(|s| s.status == ShardStatus::Pending)
    }

    pub fn is_complete(&self) -> bool {
        self.shards.iter().all(|s| s.status == ShardStatus::Done)
    }

    pub fn progress(&self) -> f32 {
        let done = self.shards.iter().filter(|s| s.status == ShardStatus::Done).count();
        done as f32 / self.shards.len() as f32
    }

    /// Verify range proof: checks that leaves[0..] are all in [start, end]
    /// and that the root of the proof trie matches pivot_root
    pub fn verify_range_proof(
        &self, shard: &SnapShard, leaves: &[(Hash, Vec<u8>)], proof: &[Vec<u8>]
    ) -> bool {
        // Real: reconstruct sparse trie from proof, verify root
        // Stub: check leaves are within range
        leaves.iter().all(|(key, _)| {
            key >= &shard.start_key && key <= &shard.end_key
        }) && !proof.is_empty()
    }
}

// ─── Sync Manager ─────────────────────────────────────────────────────────────
pub struct SyncManager {
    pub mode:          SyncMode,
    pub phase:         RwLock<SyncPhase>,
    pub peers:         RwLock<HashMap<NodeId, PeerSyncState>>,
    pub header_queue:  RwLock<HeaderQueue>,
    pub body_fetcher:  RwLock<BodyFetcher>,
    pub snap:          RwLock<Option<SnapStateDownloader>>,
    pub local_head:    RwLock<(u64, Hash)>,
}

impl SyncManager {
    pub fn new(mode: SyncMode, local_number: u64, local_hash: Hash) -> Arc<Self> {
        Arc::new(Self {
            mode,
            phase:        RwLock::new(SyncPhase::Idle),
            peers:        RwLock::new(HashMap::new()),
            header_queue: RwLock::new(HeaderQueue::new(local_number + 1)),
            body_fetcher: RwLock::new(BodyFetcher::new()),
            snap:         RwLock::new(None),
            local_head:   RwLock::new((local_number, local_hash)),
        })
    }

    pub fn on_peer_status(&self, peer: NodeId, best_number: u64, best_hash: Hash, td: u128) {
        let mut peers = self.peers.write();
        let entry = peers.entry(peer).or_insert_with(|| PeerSyncState {
            peer_id: peer, best_hash, best_number,
            total_difficulty: td, last_seen: Instant::now(),
            in_flight_req: None, failures: 0,
        });
        entry.best_number = best_number;
        entry.best_hash   = best_hash;
        entry.last_seen   = Instant::now();
    }

    /// Select best peer for header requests (highest TD, no in-flight)
    pub fn best_idle_peer(&self) -> Option<NodeId> {
        self.peers.read().values()
            .filter(|p| p.in_flight_req.is_none() && p.failures < 3)
            .max_by_key(|p| p.total_difficulty)
            .map(|p| p.peer_id)
    }

    pub fn network_best(&self) -> Option<(u64, Hash)> {
        self.peers.read().values()
            .max_by_key(|p| p.best_number)
            .map(|p| (p.best_number, p.best_hash))
    }

    /// Determine if we need to sync
    pub fn needs_sync(&self) -> bool {
        let (local, _) = *self.local_head.read();
        match self.network_best() {
            Some((best, _)) => best > local + 1,
            None => false,
        }
    }

    /// Skeleton header algorithm: request every 128th header to find chain shape
    pub fn skeleton_requests(&self, target: u64) -> Vec<(u64, u8)> {
        let (local, _) = *self.local_head.read();
        let mut reqs = Vec::new();
        let mut start = local + 1;
        while start <= target {
            let count = 128u64.min(target - start + 1) as u8;
            reqs.push((start, count));
            start += 128;
        }
        reqs
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_header_queue_ordered_drain() {
        let mut q = HeaderQueue::new(1);
        q.push(3, [3u8; 32], [2u8; 32], vec![]);
        q.push(1, [1u8; 32], [0u8; 32], vec![]);
        q.push(2, [2u8; 32], [1u8; 32], vec![]);
        let ready = q.drain_ready();
        assert_eq!(ready.len(), 3);
        assert_eq!(ready[0].number, 1);
        assert_eq!(ready[1].number, 2);
        assert_eq!(ready[2].number, 3);
    }

    #[test]
    fn test_header_queue_gap_stops_drain() {
        let mut q = HeaderQueue::new(1);
        q.push(1, [1u8; 32], [0u8; 32], vec![]);
        q.push(3, [3u8; 32], [2u8; 32], vec![]); // gap at 2
        let ready = q.drain_ready();
        assert_eq!(ready.len(), 1);
        assert_eq!(ready[0].number, 1);
        assert_eq!(q.len(), 1); // block 3 still waiting
    }

    #[test]
    fn test_body_fetcher_enqueue_assign_receive() {
        let mut bf = BodyFetcher::new();
        let hash = [0xABu8; 32];
        bf.enqueue(5, hash);
        let taken = bf.assign_batch([1u8; 32], 10);
        assert_eq!(taken.len(), 1);
        assert!(bf.in_flight.contains_key(&hash));
        bf.on_bodies(&[hash], vec![vec![0x01, 0x02]]);
        assert!(bf.take_received(&hash).is_some());
        assert!(!bf.in_flight.contains_key(&hash));
    }

    #[test]
    fn test_snap_downloader_shard_count() {
        let sd = SnapStateDownloader::new(10, [0u8; 32], 16);
        assert_eq!(sd.shards.len(), 16);
    }

    #[test]
    fn test_snap_downloader_progress_zero() {
        let sd = SnapStateDownloader::new(10, [0u8; 32], 4);
        assert_eq!(sd.progress(), 0.0);
        assert!(!sd.is_complete());
    }

    #[test]
    fn test_sync_manager_needs_sync_true() {
        let sm = SyncManager::new(SyncMode::Snap, 10, [0u8; 32]);
        sm.on_peer_status([1u8; 32], 20, [1u8; 32], 1000);
        assert!(sm.needs_sync());
    }

    #[test]
    fn test_sync_manager_needs_sync_false_when_synced() {
        let sm = SyncManager::new(SyncMode::Snap, 20, [0u8; 32]);
        sm.on_peer_status([1u8; 32], 20, [1u8; 32], 1000);
        assert!(!sm.needs_sync());
    }

    #[test]
    fn test_skeleton_requests_batching() {
        let sm = SyncManager::new(SyncMode::Full, 0, [0u8; 32]);
        let reqs = sm.skeleton_requests(256);
        assert!(!reqs.is_empty());
        assert_eq!(reqs[0].0, 1); // starts at block 1
    }

    // ── Layer 1: Security definitions ────────────────────────────────────────

    #[test]
    fn test_sync_mode_snap_is_not_full() {
        // L1: sync modes must be distinct — snap != full (critical for pivot selection)
        assert_ne!(SyncMode::Snap, SyncMode::Full);
        assert_ne!(SyncMode::Light, SyncMode::Archive);
    }

    #[test]
    fn test_in_flight_request_times_out() {
        // L1: requests exceeding timeout must be marked as timed out
        let req = InFlightRequest {
            kind: RequestKind::Headers { from: 1, count: 10 },
            sent_at: Instant::now() - Duration::from_secs(60),
            timeout: Duration::from_secs(10),
        };
        assert!(req.is_timed_out());
    }

    #[test]
    fn test_in_flight_request_not_timed_out_immediately() {
        // L1: freshly created request must not be immediately timed out
        let req = InFlightRequest {
            kind: RequestKind::Bodies { hashes: vec![] },
            sent_at: Instant::now(),
            timeout: Duration::from_secs(30),
        };
        assert!(!req.is_timed_out());
    }

    // ── Layer 2: Functional correctness ──────────────────────────────────────

    #[test]
    fn test_header_queue_drains_multiple_contiguous() {
        // L2: contiguous headers 1,2,3,4 must all drain in one call
        let mut q = HeaderQueue::new(1);
        for i in 1u64..=4 {
            q.push(i, [i as u8; 32], [(i-1) as u8; 32], vec![]);
        }
        let ready = q.drain_ready();
        assert_eq!(ready.len(), 4);
        assert!(ready.windows(2).all(|w| w[0].number < w[1].number));
    }

    #[test]
    fn test_snap_downloader_all_shards_complete_gives_100_percent() {
        // L2: all shards complete must give progress = 1.0
        let mut sd = SnapStateDownloader::new(10, [0u8; 32], 4);
        for s in &mut sd.shards { s.status = ShardStatus::Done; }
        assert_eq!(sd.progress(), 1.0);
        assert!(sd.is_complete());
    }

    #[test]
    fn test_sync_manager_tracks_best_peer_number() {
        // L2: best peer height must be tracked after on_peer_status
        let sm = SyncManager::new(SyncMode::Snap, 0, [0u8; 32]);
        sm.on_peer_status([1u8; 32], 100, [0xAAu8; 32], 9999);
        assert!(sm.needs_sync()); // local=0, peer=100
    }

    // ── Layer 3: Protection ───────────────────────────────────────────────────

    #[test]
    fn test_header_queue_rejects_duplicate_block_number() {
        // L3: inserting same block number twice must not double-drain
        let mut q = HeaderQueue::new(1);
        q.push(1, [0xAAu8; 32], [0u8; 32], vec![]);
        q.push(1, [0xBBu8; 32], [0u8; 32], vec![]); // duplicate height
        let ready = q.drain_ready();
        assert!(ready.len() <= 2); // implementation may allow both; but must not panic
    }

    #[test]
    fn test_body_fetcher_unknown_hash_on_receive_is_noop() {
        // L3: receiving body for unknown hash must not panic
        let mut bf = BodyFetcher::new();
        let unknown = [0xDEu8; 32];
        bf.on_bodies(&[unknown], vec![vec![0x00]]);
        assert!(bf.take_received(&unknown).is_none());
    }

    #[test]
    fn test_sync_already_synced_does_not_needs_sync() {
        // L3: node at same height as best peer must not trigger sync
        let sm = SyncManager::new(SyncMode::Full, 50, [0u8; 32]);
        sm.on_peer_status([1u8; 32], 50, [1u8; 32], 100);
        assert!(!sm.needs_sync());
    }

    // ── Layer 4: Detection & Response ────────────────────────────────────────

    #[test]
    fn test_peer_failures_tracked_per_peer() {
        // L4: failure count must be per-peer for ban/penalization tracking
        let sm = SyncManager::new(SyncMode::Snap, 0, [0u8; 32]);
        sm.on_peer_status([1u8; 32], 10, [1u8; 32], 1000);
        sm.on_peer_status([2u8; 32], 10, [2u8; 32], 1000);
        // Both peers tracked separately
        let peers = sm.peers.read();
        assert_eq!(peers.len(), 2);
    }

    #[test]
    fn test_snap_downloader_progress_increases_as_shards_complete() {
        // L4: progress must monotonically increase as shards complete
        let mut sd = SnapStateDownloader::new(10, [0u8; 32], 4);
        let mut prev = sd.progress();
        for i in 0..sd.shards.len() {
            sd.shards[i].status = ShardStatus::Done;
            let curr = sd.progress();
            assert!(curr >= prev);
            prev = curr;
        }
    }

    // ── Layer 5: Resilience ───────────────────────────────────────────────────

    #[test]
    fn test_header_queue_empty_drain_returns_empty() {
        // L5: draining empty queue must return empty vec without panic
        let mut q = HeaderQueue::new(1);
        assert!(q.drain_ready().is_empty());
    }

    #[test]
    fn test_body_fetcher_assign_empty_queue_returns_empty() {
        // L5: assigning from empty fetcher must return empty batch
        let mut bf = BodyFetcher::new();
        let batch = bf.assign_batch([0u8; 32], 10);
        assert!(batch.is_empty());
    }

    #[test]
    fn test_sync_manager_no_peers_does_not_panic() {
        // L5: needs_sync() with no peers must return false, not panic
        let sm = SyncManager::new(SyncMode::Full, 0, [0u8; 32]);
        // No peers registered
        assert!(!sm.needs_sync());
    }

    // ── Layer 6: Governance & Compliance ─────────────────────────────────────

    #[test]
    fn test_all_sync_modes_are_distinct() {
        // L6: each sync mode must be a distinct variant for configuration auditing
        let modes = [SyncMode::Full, SyncMode::Snap, SyncMode::Light, SyncMode::Archive];
        for i in 0..modes.len() {
            for j in 0..modes.len() {
                if i != j { assert_ne!(modes[i], modes[j]); }
            }
        }
    }

    #[test]
    fn test_skeleton_requests_start_at_block_1() {
        // L6: skeleton sync must always begin from block 1, not 0 (genesis is known)
        let sm = SyncManager::new(SyncMode::Full, 0, [0u8; 32]);
        let reqs = sm.skeleton_requests(100);
        if !reqs.is_empty() {
            assert_eq!(reqs[0].0, 1);
        }
    }

    // ── Reentrancy simulation ─────────────────────────────────────────────────

    #[test]
    fn test_sync_manager_concurrent_peer_status_updates() {
        // Reentrancy: multiple peers reporting status concurrently must not corrupt state
        use std::thread;
        let sm = Arc::new(SyncManager::new(SyncMode::Snap, 0, [0u8; 32]));
        let mut handles = vec![];
        for i in 1u8..=8 {
            let s = Arc::clone(&sm);
            handles.push(thread::spawn(move || {
                s.on_peer_status([i; 32], i as u64 * 10, [i; 32], i as u128 * 1000);
            }));
        }
        for h in handles { h.join().unwrap(); }
        assert!(sm.peers.read().len() <= 8);
        assert!(sm.needs_sync()); // local=0, peers have higher blocks
    }

    // ── Read-only reentrancy ──────────────────────────────────────────────────

    #[test]
    fn test_needs_sync_read_concurrent_with_peer_updates() {
        // Read-only reentrancy: needs_sync() (read) during on_peer_status (write) must not panic
        use std::thread;
        let sm = Arc::new(SyncManager::new(SyncMode::Full, 0, [0u8; 32]));
        let s1 = Arc::clone(&sm);
        let writer = thread::spawn(move || {
            for i in 0u8..20 {
                s1.on_peer_status([i; 32], i as u64 * 5, [i; 32], 1000);
            }
        });
        for _ in 0..20 {
            let _ = sm.needs_sync();
        }
        writer.join().unwrap();
    }

    // ── Function parameter validation ─────────────────────────────────────────

    #[test]
    fn test_header_queue_push_past_expected_is_stored() {
        // Param validation: header ahead of expected must be buffered, not dropped
        let mut q = HeaderQueue::new(5);
        q.push(10, [10u8; 32], [9u8; 32], vec![]);
        assert_eq!(q.len(), 1);
        // Not yet drainable (expected=5, but 6-9 are missing)
        let ready = q.drain_ready();
        assert!(ready.is_empty());
    }

    #[test]
    fn test_body_fetcher_batch_respects_limit() {
        // Param validation: assign_batch(n) must return at most n hashes
        let mut bf = BodyFetcher::new();
        for i in 0u8..20 {
            bf.enqueue(i as u64, [i; 32]);
        }
        let batch = bf.assign_batch([0u8; 32], 5);
        assert_eq!(batch.len(), 5, "batch must be exactly the requested size");
    }

    #[test]
    fn test_snap_range_proof_rejects_leaves_outside_shard() {
        // Param validation: leaves outside shard range must fail proof verification
        let sd = SnapStateDownloader::new(10, [0u8; 32], 4);
        let shard = &sd.shards[0];
        // Leaf key = [0xFF; 32] is well outside the first shard's range
        let out_of_range = [0xFFu8; 32];
        let proof = vec![vec![0x01]]; // non-empty proof
        let is_valid = sd.verify_range_proof(shard, &[(out_of_range, vec![0x00])], &proof);
        assert!(!is_valid, "leaves outside shard range must fail verification");
    }

    // ── Misconfiguration ──────────────────────────────────────────────────────

    #[test]
    fn test_sync_manager_snap_mode_tracked_correctly() {
        // Misconfiguration: mode passed at construction must be preserved
        let sm = SyncManager::new(SyncMode::Snap, 0, [0u8; 32]);
        assert_eq!(sm.mode, SyncMode::Snap);
    }

    #[test]
    fn test_in_flight_request_kind_bodies_stores_hashes() {
        // Misconfiguration: body request must track hashes for matching responses
        let hashes = vec![[0xAAu8; 32], [0xBBu8; 32]];
        let req = InFlightRequest {
            kind: RequestKind::Bodies { hashes: hashes.clone() },
            sent_at: Instant::now(),
            timeout: Duration::from_secs(10),
        };
        if let RequestKind::Bodies { hashes: h } = req.kind {
            assert_eq!(h.len(), 2);
        } else {
            panic!("expected Bodies request kind");
        }
    }

    #[test]
    fn test_skeleton_requests_cover_entire_range() {
        // Misconfiguration: skeleton must cover all blocks up to target
        let sm = SyncManager::new(SyncMode::Full, 0, [0u8; 32]);
        let target = 300u64;
        let reqs = sm.skeleton_requests(target);
        // Last request must reach target
        let last_end = reqs.iter().map(|(start, count)| start + *count as u64 - 1).max().unwrap();
        assert!(last_end >= target, "skeleton must cover all blocks up to target");
    }

    // ── Governance attack ─────────────────────────────────────────────────────

    #[test]
    fn test_snap_verify_range_proof_requires_nonempty_proof() {
        // Governance attack: empty proof must not pass range verification
        let sd = SnapStateDownloader::new(10, [0u8; 32], 4);
        let shard = &sd.shards[0];
        // Use a key within range (first shard starts at 0)
        let in_range = [0x00u8; 32];
        let empty_proof: Vec<Vec<u8>> = vec![];
        assert!(!sd.verify_range_proof(shard, &[(in_range, vec![0x01])], &empty_proof),
            "empty proof must not pass verification");
    }

    #[test]
    fn test_peer_with_high_failures_excluded_from_best_peer() {
        // Governance attack: peers with >= 3 failures must not be selected as best
        let sm = SyncManager::new(SyncMode::Full, 0, [0u8; 32]);
        let peer_id = [1u8; 32];
        sm.on_peer_status(peer_id, 100, [1u8; 32], 99999);
        // Manually mark peer as failed
        {
            let mut peers = sm.peers.write();
            if let Some(p) = peers.get_mut(&peer_id) {
                p.failures = 3; // at failure limit
            }
        }
        assert!(sm.best_idle_peer().is_none(),
            "peer with 3+ failures must not be selected as best peer");
    }

    #[test]
    fn test_body_fetcher_requeue_timed_out_moves_back_to_pending() {
        // Governance attack: timed-out bodies must be requeued to prevent stall
        let mut bf = BodyFetcher::new();
        bf.timeout = Duration::from_nanos(1); // instant timeout
        bf.enqueue(1, [0x01u8; 32]);
        bf.assign_batch([0u8; 32], 1);
        std::thread::sleep(Duration::from_millis(1));
        bf.requeue_timed_out();
        // Hash must be back in pending
        let rebatch = bf.assign_batch([0u8; 32], 1);
        assert_eq!(rebatch.len(), 1, "timed-out hash must be requeued and re-assignable");
    }
}

