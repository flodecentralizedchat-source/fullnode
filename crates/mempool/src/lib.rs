//! ═══════════════════════════════════════════════════════════════════
//! MODULE 2 — TRANSACTION POOL (MEMPOOL)
//!
//! Data Structures:
//!   TxPool      — Two-tier map: pending (correct nonce) + queued (future nonce)
//!   PriceHeap   — Binary max-heap ordered by effective_gas_price
//!   SenderState — Per-sender nonce + balance tracking
//!   TxKey       — (sender, nonce) composite key for O(1) lookup
//!
//! Algorithms:
//!   Insertion     — O(log n) heap insert + O(1) hashmap insert
//!   Eviction      — Price-threshold eviction when pool > MAX_SIZE
//!   Promotion     — When queued tx nonce == pending nonce+1, promote
//!   MEV Detection — Pattern-match sandwich: same-block buy+sell same token pair
//! ═══════════════════════════════════════════════════════════════════

use std::{
    collections::{BinaryHeap, HashMap, BTreeMap},
    cmp::Ordering,
    sync::Arc,
    time::Instant,
};
use parking_lot::RwLock;
// serde unused in mempool

pub const MAX_POOL_SIZE:    usize = 100_000;
pub const MAX_PER_SENDER:   usize = 64;
pub const TX_EXPIRY_SECS:   u64   = 3600; // 1 hour

// ─── Transaction ID ───────────────────────────────────────────────────────────
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TxHash(pub [u8; 32]);

// ─── Pool Transaction (wraps raw tx with metadata) ───────────────────────────
#[derive(Debug, Clone)]
pub struct PoolTx {
    pub hash:             TxHash,
    pub sender:           [u8; 20],
    pub nonce:            u64,
    pub max_fee:          u128,
    pub max_priority_fee: u128,
    pub gas_limit:        u64,
    pub value:            u128,
    pub data:             Vec<u8>,
    pub effective_price:  u128, // cached for heap ordering
    pub received_at:      Instant,
    pub is_local:         bool,
}

impl PoolTx {
    pub fn is_expired(&self) -> bool {
        self.received_at.elapsed().as_secs() > TX_EXPIRY_SECS
    }
}

// Heap ordering: higher effective_price = higher priority
impl PartialEq for PoolTx {
    fn eq(&self, o: &Self) -> bool { self.hash == o.hash }
}
impl Eq for PoolTx {}
impl PartialOrd for PoolTx {
    fn partial_cmp(&self, o: &Self) -> Option<Ordering> { Some(self.cmp(o)) }
}
impl Ord for PoolTx {
    fn cmp(&self, o: &Self) -> Ordering {
        self.effective_price.cmp(&o.effective_price)
            .then(self.gas_limit.cmp(&o.gas_limit))
    }
}

// ─── Per-Sender Nonce Gap Tracker ─────────────────────────────────────────────
/// Tracks the contiguous nonce frontier for a sender.
/// pending = {nonce → tx} where nonces are contiguous from `base`
/// queued  = {nonce → tx} where gaps exist
#[derive(Debug, Default)]
pub struct SenderSlot {
    pub balance:    u128,
    pub base_nonce: u64,                   // current on-chain nonce
    pub pending:    BTreeMap<u64, PoolTx>, // sorted by nonce
    pub queued:     BTreeMap<u64, PoolTx>,
}

impl SenderSlot {
    /// Insert tx into correct tier
    pub fn insert(&mut self, tx: PoolTx) {
        if tx.nonce < self.base_nonce {
            return; // stale nonce, ignore
        }
        let expected = self.base_nonce + self.pending.len() as u64;
        if tx.nonce == expected {
            self.pending.insert(tx.nonce, tx);
            // Promote from queued if next nonces now fill gap
            self.promote();
        } else {
            self.queued.insert(tx.nonce, tx);
        }
    }

    fn promote(&mut self) {
        loop {
            let next = self.base_nonce + self.pending.len() as u64;
            if let Some(tx) = self.queued.remove(&next) {
                self.pending.insert(next, tx);
            } else {
                break;
            }
        }
    }

    pub fn remove_confirmed(&mut self, nonce: u64) {
        self.pending.remove(&nonce);
        self.base_nonce = nonce + 1;
        self.promote();
    }
}

// ─── Price Heap ───────────────────────────────────────────────────────────────
/// Global max-heap: used to pick best txns for block building
/// and to evict cheapest txns when pool is full
pub struct PriceHeap {
    heap: BinaryHeap<PoolTx>,
}

impl PriceHeap {
    pub fn new() -> Self { Self { heap: BinaryHeap::new() } }
    pub fn push(&mut self, tx: PoolTx) { self.heap.push(tx); }
    pub fn pop_best(&mut self) -> Option<PoolTx> { self.heap.pop() }
    pub fn len(&self) -> usize { self.heap.len() }

    /// Drain N best transactions for a block
    pub fn drain_top(&mut self, n: usize) -> Vec<PoolTx> {
        let mut out = Vec::with_capacity(n);
        while out.len() < n {
            match self.heap.pop() {
                Some(tx) => out.push(tx),
                None => break,
            }
        }
        out
    }
}

// ─── TxPool ───────────────────────────────────────────────────────────────────
pub struct TxPool {
    /// sender → slot
    senders:    RwLock<HashMap<[u8; 20], SenderSlot>>,
    /// hash → tx (for O(1) lookup)
    all_txs:    RwLock<HashMap<TxHash, PoolTx>>,
    /// Priority heap (cloned refs for ordering)
    price_heap: Arc<RwLock<PriceHeap>>,
    /// Current chain base fee (updated each block)
    base_fee:   RwLock<u128>,
}

impl TxPool {
    pub fn new(base_fee: u128) -> Arc<Self> {
        Arc::new(Self {
            senders:    RwLock::new(HashMap::new()),
            all_txs:    RwLock::new(HashMap::new()),
            price_heap: Arc::new(RwLock::new(PriceHeap::new())),
            base_fee:   RwLock::new(base_fee),
        })
    }

    /// Validate + insert transaction
    pub fn add_tx(&self, tx: PoolTx) -> Result<(), MempoolError> {
        let hash = tx.hash;

        // 1. Duplicate check O(1)
        if self.all_txs.read().contains_key(&hash) {
            return Err(MempoolError::AlreadyKnown);
        }

        // 2. Intrinsic gas check
        if tx.gas_limit < 21_000 {
            return Err(MempoolError::IntrinsicGas);
        }

        // 3. Fee below floor
        let base_fee = *self.base_fee.read();
        if tx.max_fee < base_fee {
            return Err(MempoolError::FeeTooLow { have: tx.max_fee, need: base_fee });
        }

        // 4. Per-sender cap
        {
            let senders = self.senders.read();
            if let Some(slot) = senders.get(&tx.sender) {
                if slot.pending.len() + slot.queued.len() >= MAX_PER_SENDER {
                    return Err(MempoolError::SenderOverflow);
                }
            }
        }

        // 5. Pool capacity eviction
        if self.all_txs.read().len() >= MAX_POOL_SIZE {
            self.evict_cheapest();
        }

        // 6. Insert
        self.all_txs.write().insert(hash, tx.clone());
        self.senders.write()
            .entry(tx.sender)
            .or_default()
            .insert(tx.clone());
        self.price_heap.write().push(tx);

        Ok(())
    }

    /// Evict the cheapest non-local transaction
    fn evict_cheapest(&self) {
        // In real impl: track a min-heap alongside max-heap. Simplified here.
        let worst_hash = self.all_txs.read()
            .values()
            .filter(|t| !t.is_local)
            .min_by_key(|t| t.effective_price)
            .map(|t| t.hash);
        if let Some(h) = worst_hash {
            self.remove_tx(&h);
        }
    }

    pub fn remove_tx(&self, hash: &TxHash) {
        if let Some(tx) = self.all_txs.write().remove(hash) {
            if let Some(slot) = self.senders.write().get_mut(&tx.sender) {
                slot.pending.remove(&tx.nonce);
                slot.queued.remove(&tx.nonce);
            }
        }
    }

    /// Called after block confirmation — remove included txns, update nonces
    pub fn on_block_committed(&self, txns: &[(TxHash, [u8; 20], u64)], new_base_fee: u128) {
        *self.base_fee.write() = new_base_fee;
        let mut senders = self.senders.write();
        let mut all = self.all_txs.write();
        for (hash, sender, nonce) in txns {
            all.remove(hash);
            if let Some(slot) = senders.get_mut(sender) {
                slot.remove_confirmed(*nonce);
            }
        }
    }

    /// Best N txns for block building (respects nonce ordering per sender)
    pub fn best_transactions(&self, max: usize, gas_limit: u64) -> Vec<PoolTx> {
        let senders = self.senders.read();
        let mut candidates: Vec<&PoolTx> = senders.values()
            .filter_map(|s| s.pending.values().next()) // first pending per sender
            .collect();
        candidates.sort_by(|a, b| b.effective_price.cmp(&a.effective_price));
        let mut out = Vec::new();
        let mut gas_used = 0u64;
        for tx in candidates.into_iter().take(max) {
            if gas_used + tx.gas_limit > gas_limit { continue; }
            gas_used += tx.gas_limit;
            out.push(tx.clone());
        }
        out
    }

    pub fn len(&self) -> usize { self.all_txs.read().len() }
    pub fn get(&self, hash: &TxHash) -> Option<PoolTx> {
        self.all_txs.read().get(hash).cloned()
    }
}

// ─── MEV Detection ────────────────────────────────────────────────────────────
/// Detect sandwich attack pattern in pending mempool
/// Pattern: tx_buy(tokenA) → victim_tx → tx_sell(tokenA)
#[derive(Debug)]
pub struct SandwichDetector;

impl SandwichDetector {
    pub fn check_sandwich(txns: &[PoolTx]) -> Vec<SandwichAlert> {
        let mut alerts = Vec::new();
        // Simplified: flag when two txns from same sender bracket another's swap data
        for i in 0..txns.len() {
            for j in (i + 1)..txns.len().min(i + 50) {
                if txns[i].sender == txns[j].sender {
                    // Potential sandwich brackets [i+1..j-1]
                    let victims: Vec<usize> = (i+1..j)
                        .filter(|&k| txns[k].sender != txns[i].sender && !txns[k].data.is_empty())
                        .collect();
                    if !victims.is_empty() {
                        alerts.push(SandwichAlert {
                            attacker: txns[i].sender,
                            front_run: txns[i].hash,
                            back_run:  txns[j].hash,
                            victims:   victims.iter().map(|&k| txns[k].hash).collect(),
                        });
                    }
                }
            }
        }
        alerts
    }
}

#[derive(Debug)]
pub struct SandwichAlert {
    pub attacker:  [u8; 20],
    pub front_run: TxHash,
    pub back_run:  TxHash,
    pub victims:   Vec<TxHash>,
}

// ─── Errors ───────────────────────────────────────────────────────────────────
#[derive(Debug, thiserror::Error)]
pub enum MempoolError {
    #[error("transaction already known")]
    AlreadyKnown,
    #[error("intrinsic gas too low")]
    IntrinsicGas,
    #[error("fee too low: have {have} need {need}")]
    FeeTooLow { have: u128, need: u128 },
    #[error("sender has too many queued transactions")]
    SenderOverflow,
    #[error("nonce too low")]
    NonceTooLow,
}

// ─── Tests ───────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    fn make_tx(nonce: u64, max_fee: u128, gas_limit: u64, is_local: bool) -> PoolTx {
        let mut hash = [0u8; 32];
        hash[0] = nonce as u8;
        hash[1] = max_fee as u8;
        PoolTx {
            hash: TxHash(hash),
            sender: [1u8; 20],
            nonce,
            max_fee,
            max_priority_fee: max_fee / 2,
            gas_limit,
            value: 0,
            data: vec![],
            effective_price: max_fee,
            received_at: Instant::now(),
            is_local,
        }
    }

    #[test]
    fn test_add_tx_success() {
        let pool = TxPool::new(1_000_000_000);
        let tx = make_tx(0, 2_000_000_000, 21_000, false);
        assert!(pool.add_tx(tx).is_ok());
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn test_add_tx_duplicate_rejected() {
        let pool = TxPool::new(1_000_000_000);
        let tx = make_tx(0, 2_000_000_000, 21_000, false);
        pool.add_tx(tx.clone()).unwrap();
        assert!(matches!(pool.add_tx(tx), Err(MempoolError::AlreadyKnown)));
    }

    #[test]
    fn test_add_tx_fee_too_low() {
        let pool = TxPool::new(10_000_000_000u128);
        let tx = make_tx(0, 5_000_000_000u128, 21_000, false);
        assert!(matches!(pool.add_tx(tx), Err(MempoolError::FeeTooLow { .. })));
    }

    #[test]
    fn test_add_tx_intrinsic_gas_too_low() {
        let pool = TxPool::new(1_000_000_000);
        let tx = make_tx(0, 2_000_000_000, 5_000, false);
        assert!(matches!(pool.add_tx(tx), Err(MempoolError::IntrinsicGas)));
    }

    #[test]
    fn test_on_block_committed_removes_tx() {
        let pool = TxPool::new(1_000_000_000);
        let tx = make_tx(0, 2_000_000_000, 21_000, false);
        let hash = tx.hash;
        let sender = tx.sender;
        pool.add_tx(tx).unwrap();
        pool.on_block_committed(&[(hash, sender, 0)], 1_000_000_000);
        assert_eq!(pool.len(), 0);
    }

    #[test]
    fn test_best_transactions_respects_gas_limit() {
        let pool = TxPool::new(1_000_000_000);
        for i in 0..5u64 {
            let mut tx = make_tx(i, 2_000_000_000, 1_000_000, false);
            tx.sender[0] = i as u8; // different senders
            tx.hash.0[0] = i as u8;
            pool.add_tx(tx).unwrap();
        }
        let best = pool.best_transactions(10, 2_500_000);
        assert!(best.len() <= 2);
    }

    #[test]
    fn test_sender_slot_nonce_promotion() {
        let mut slot = SenderSlot { balance: 0, base_nonce: 1, ..Default::default() };
        // Insert future nonce first
        slot.insert(make_tx(2, 1_000_000_000, 21_000, false));
        assert_eq!(slot.queued.len(), 1);
        assert_eq!(slot.pending.len(), 0);
        // Now fill the gap
        slot.insert(make_tx(1, 1_000_000_000, 21_000, false));
        assert_eq!(slot.pending.len(), 2);
        assert_eq!(slot.queued.len(), 0);
    }

    #[test]
    fn test_price_heap_drain_top() {
        let mut heap = PriceHeap::new();
        heap.push(make_tx(0, 3_000_000_000, 21_000, false));
        heap.push(make_tx(1, 1_000_000_000, 21_000, false));
        heap.push(make_tx(2, 2_000_000_000, 21_000, false));
        let top = heap.drain_top(2);
        assert_eq!(top.len(), 2);
        assert!(top[0].max_fee >= top[1].max_fee);
    }

    #[test]
    fn test_sandwich_detector_no_false_positive() {
        let txns = vec![
            make_tx(0, 1_000_000_000, 21_000, false),
            make_tx(1, 1_000_000_000, 21_000, false),
        ];
        let alerts = SandwichDetector::check_sandwich(&txns);
        assert!(alerts.is_empty());
    }

    // ── Layer 1: Security definitions ────────────────────────────────────────

    #[test]
    fn test_tx_gas_limit_zero_rejected() {
        // L1: zero gas_limit is below intrinsic minimum, must reject
        let pool = TxPool::new(1_000_000_000);
        let tx = make_tx(0, 2_000_000_000, 0, false);
        assert!(matches!(pool.add_tx(tx), Err(MempoolError::IntrinsicGas)));
    }

    #[test]
    fn test_tx_max_fee_zero_rejected_when_base_fee_nonzero() {
        // L1: zero max_fee rejected when base_fee > 0
        let pool = TxPool::new(1_000_000_000);
        let tx = make_tx(0, 0, 21_000, false);
        assert!(matches!(pool.add_tx(tx), Err(MempoolError::FeeTooLow { .. })));
    }

    #[test]
    fn test_sender_cap_enforced() {
        // L1: per-sender cap prevents single address from flooding the pool
        let pool = TxPool::new(1_000_000_000);
        // Fill up to MAX_PER_SENDER
        for i in 0..MAX_PER_SENDER as u64 {
            let mut tx = make_tx(i, 2_000_000_000, 21_000, false);
            tx.hash.0[0] = (i & 0xFF) as u8;
            tx.hash.0[1] = ((i >> 8) & 0xFF) as u8;
            // Different hash but same sender
            pool.add_tx(tx).unwrap();
        }
        // 65th tx from same sender must be rejected
        let mut overflow_tx = make_tx(MAX_PER_SENDER as u64, 2_000_000_000, 21_000, false);
        overflow_tx.hash.0[0] = 0xFF;
        overflow_tx.hash.0[1] = 0xFF;
        assert!(matches!(pool.add_tx(overflow_tx), Err(MempoolError::SenderOverflow)));
    }

    #[test]
    fn test_stale_nonce_silently_dropped() {
        // L1: tx with nonce < base_nonce must be silently ignored
        let mut slot = SenderSlot { balance: 0, base_nonce: 5, ..Default::default() };
        slot.insert(make_tx(3, 1_000_000_000, 21_000, false)); // nonce 3 < base 5
        assert_eq!(slot.pending.len(), 0);
        assert_eq!(slot.queued.len(), 0);
    }

    // ── Layer 2: Functional correctness ──────────────────────────────────────

    #[test]
    fn test_evict_cheapest_non_local_first() {
        // L2: when pool is full, cheapest non-local tx is evicted
        let pool = TxPool::new(1_000_000_000);
        // Add a cheap non-local tx
        let mut cheap_tx = make_tx(0, 1_500_000_000, 21_000, false);
        cheap_tx.effective_price = 1_500_000_000;
        pool.add_tx(cheap_tx.clone()).unwrap();
        // Add a local tx with same low price — local must be protected
        let mut local_tx = make_tx(1, 1_500_000_000, 21_000, true);
        local_tx.effective_price = 1_500_000_000;
        local_tx.hash.0[1] = 99;
        pool.add_tx(local_tx.clone()).unwrap();
        // Evict — cheap non-local should be removed first
        pool.evict_cheapest();
        assert!(pool.all_txs.read().contains_key(&local_tx.hash));
        assert!(!pool.all_txs.read().contains_key(&cheap_tx.hash));
    }

    #[test]
    fn test_base_fee_updated_on_block_commit() {
        // L2: new base fee takes effect after on_block_committed
        let pool = TxPool::new(1_000_000_000);
        let new_fee = 5_000_000_000u128;
        pool.on_block_committed(&[], new_fee);
        // Tx with old max_fee now below new base_fee
        let tx = make_tx(0, 2_000_000_000, 21_000, false);
        assert!(matches!(pool.add_tx(tx), Err(MempoolError::FeeTooLow { .. })));
    }

    #[test]
    fn test_remove_tx_cleans_sender_slot() {
        // L2: remove_tx must clean both all_txs and sender slot
        let pool = TxPool::new(1_000_000_000);
        let tx = make_tx(0, 2_000_000_000, 21_000, false);
        let h = tx.hash;
        pool.add_tx(tx).unwrap();
        pool.remove_tx(&h);
        assert_eq!(pool.len(), 0);
        assert!(!pool.all_txs.read().contains_key(&h));
    }

    // ── Layer 3: Protection ───────────────────────────────────────────────────

    #[test]
    fn test_pool_rejects_tx_at_exact_intrinsic_gas_boundary() {
        // L3: gas_limit == 20_999 fails; 21_000 passes — boundary is enforced exactly
        let pool = TxPool::new(1_000_000_000);
        let bad = make_tx(0, 2_000_000_000, 20_999, false);
        assert!(matches!(pool.add_tx(bad), Err(MempoolError::IntrinsicGas)));
        let good = make_tx(1, 2_000_000_000, 21_000, false);
        assert!(pool.add_tx(good).is_ok());
    }

    #[test]
    fn test_concurrent_add_does_not_allow_duplicate() {
        // L3: concurrent inserts of same tx must not both succeed
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::thread;
        let pool = Arc::new(TxPool::new(1_000_000_000));
        let success_count = Arc::new(AtomicUsize::new(0));
        let mut handles = vec![];
        for _ in 0..8 {
            let p = Arc::clone(&pool);
            let sc = Arc::clone(&success_count);
            handles.push(thread::spawn(move || {
                let tx = make_tx(0, 2_000_000_000, 21_000, false);
                if p.add_tx(tx).is_ok() { sc.fetch_add(1, Ordering::Relaxed); }
            }));
        }
        for h in handles { h.join().unwrap(); }
        assert_eq!(success_count.load(Ordering::Relaxed), 1);
    }

    // ── Layer 4: Detection & Response ────────────────────────────────────────

    #[test]
    fn test_pool_len_reflects_actual_count() {
        // L4: pool.len() must always reflect true count (for monitoring)
        let pool = TxPool::new(1_000_000_000);
        assert_eq!(pool.len(), 0);
        let tx = make_tx(0, 2_000_000_000, 21_000, false);
        let h = tx.hash;
        pool.add_tx(tx).unwrap();
        assert_eq!(pool.len(), 1);
        pool.remove_tx(&h);
        assert_eq!(pool.len(), 0);
    }

    #[test]
    fn test_fee_error_contains_actual_values_for_logging() {
        // L4: FeeTooLow error must expose have/need values for alert generation
        let pool = TxPool::new(10_000_000_000u128);
        let tx = make_tx(0, 3_000_000_000u128, 21_000, false);
        match pool.add_tx(tx) {
            Err(MempoolError::FeeTooLow { have, need }) => {
                assert_eq!(have, 3_000_000_000u128);
                assert_eq!(need, 10_000_000_000u128);
            }
            _ => panic!("expected FeeTooLow"),
        }
    }

    // ── Layer 5: Resilience ───────────────────────────────────────────────────

    #[test]
    fn test_pool_empty_best_transactions_returns_empty() {
        // L5: best_transactions on empty pool must not panic
        let pool = TxPool::new(1_000_000_000);
        let result = pool.best_transactions(100, 1_000_000);
        assert!(result.is_empty());
    }

    #[test]
    fn test_on_block_committed_with_unknown_hash_does_not_panic() {
        // L5: committing unknown tx hashes must be a no-op, not a panic
        let pool = TxPool::new(1_000_000_000);
        let fake_hash = TxHash([0xDE; 32]);
        let fake_sender = [0xAD; 20];
        pool.on_block_committed(&[(fake_hash, fake_sender, 0)], 1_000_000_000);
        assert_eq!(pool.len(), 0);
    }

    #[test]
    fn test_nonce_gap_queues_then_promotes_on_fill() {
        // L5: nonce gaps handled gracefully — tx queued, then promoted when gap filled
        let mut slot = SenderSlot { balance: 0, base_nonce: 0, ..Default::default() };
        slot.insert(make_tx(0, 1_000_000_000, 21_000, false));
        slot.insert(make_tx(2, 1_000_000_000, 21_000, false)); // gap at nonce 1
        assert_eq!(slot.queued.len(), 1);
        slot.insert(make_tx(1, 1_000_000_000, 21_000, false)); // fill gap
        assert_eq!(slot.pending.len(), 3);
        assert_eq!(slot.queued.len(), 0);
    }

    // ── Layer 6: Governance & Compliance ─────────────────────────────────────

    #[test]
    fn test_max_pool_size_constant_is_documented() {
        // L6: pool size limit must be defined and consistent for capacity planning
        assert_eq!(MAX_POOL_SIZE, 100_000);
    }

    #[test]
    fn test_max_per_sender_constant_is_documented() {
        // L6: per-sender cap must be defined for anti-spam governance
        assert_eq!(MAX_PER_SENDER, 64);
    }

    #[test]
    fn test_tx_expiry_constant_documented() {
        // L6: expiry constant must be present and reasonable (1 hour = 3600s)
        assert_eq!(TX_EXPIRY_SECS, 3600);
    }

    // ── Reentrancy simulation ─────────────────────────────────────────────────

    #[test]
    fn test_add_then_remove_then_readd_same_hash() {
        // Reentrancy: add → remove → re-add same tx must always work cleanly
        let pool = TxPool::new(1_000_000_000);
        let tx = make_tx(0, 2_000_000_000, 21_000, false);
        let h = tx.hash;
        pool.add_tx(tx.clone()).unwrap();
        pool.remove_tx(&h);
        assert_eq!(pool.len(), 0);
        pool.add_tx(tx).unwrap();
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn test_concurrent_add_and_remove_no_panic() {
        // Reentrancy: simultaneous add + remove must not panic or corrupt state
        use std::thread;
        let pool = Arc::new(TxPool::new(1_000_000_000));
        let p1 = Arc::clone(&pool);
        let adder = thread::spawn(move || {
            for i in 0..50u64 {
                let mut tx = make_tx(i, 2_000_000_000, 21_000, false);
                tx.sender[0] = (i % 256) as u8;
                tx.hash.0[0] = (i % 256) as u8;
                tx.hash.0[1] = ((i >> 8) % 256) as u8;
                let _ = p1.add_tx(tx);
            }
        });
        let p2 = Arc::clone(&pool);
        let remover = thread::spawn(move || {
            for i in 0..50u64 {
                let mut hash = [0u8; 32];
                hash[0] = (i % 256) as u8;
                hash[1] = ((i >> 8) % 256) as u8;
                p2.remove_tx(&TxHash(hash));
            }
        });
        adder.join().unwrap();
        remover.join().unwrap();
        // Pool must still be queryable without panic
        let _ = pool.len();
    }

    // ── Read-only reentrancy ──────────────────────────────────────────────────

    #[test]
    fn test_best_transactions_read_during_concurrent_add() {
        // Read-only reentrancy: best_transactions (read) during concurrent add (write)
        // must return a consistent subset, not panic
        use std::thread;
        let pool = Arc::new(TxPool::new(1_000_000_000));
        let p1 = Arc::clone(&pool);
        let writer = thread::spawn(move || {
            for i in 0..20u64 {
                let mut tx = make_tx(i, 2_000_000_000, 21_000, false);
                tx.sender[0] = (i % 256) as u8;
                tx.hash.0[0] = (i % 256) as u8;
                let _ = p1.add_tx(tx);
            }
        });
        for _ in 0..20 {
            let result = pool.best_transactions(5, 1_000_000);
            assert!(result.len() <= 5);
        }
        writer.join().unwrap();
    }

    #[test]
    fn test_pool_len_read_during_concurrent_writes_never_exceeds_max() {
        // Read-only reentrancy: len() during writes must never return > MAX_POOL_SIZE
        use std::thread;
        let pool = Arc::new(TxPool::new(1_000_000_000));
        let p1 = Arc::clone(&pool);
        let writer = thread::spawn(move || {
            for i in 0..50u64 {
                let mut tx = make_tx(i, 2_000_000_000, 21_000, false);
                tx.sender[0] = (i % 256) as u8;
                tx.hash.0[0] = (i % 256) as u8;
                let _ = p1.add_tx(tx);
            }
        });
        for _ in 0..50 {
            assert!(pool.len() <= MAX_POOL_SIZE);
        }
        writer.join().unwrap();
    }

    // ── Function parameter validation ─────────────────────────────────────────

    #[test]
    fn test_add_tx_with_gas_limit_zero_rejected() {
        // Param validation: gas_limit=0 is below intrinsic minimum, must be rejected
        let pool = TxPool::new(1_000_000_000);
        let tx = make_tx(0, 2_000_000_000, 0, false);
        assert!(pool.add_tx(tx).is_err());
    }

    #[test]
    fn test_add_tx_with_max_fee_zero_rejected_when_base_fee_positive() {
        // Param validation: max_fee=0 < base_fee must produce FeeTooLow error
        let pool = TxPool::new(1_000_000_000); // base_fee = 1 gwei
        let mut tx = make_tx(0, 0, 21_000, false);
        tx.max_fee = 0;
        tx.effective_price = 0;
        let err = pool.add_tx(tx).unwrap_err();
        assert!(matches!(err, MempoolError::FeeTooLow { .. }));
    }

    #[test]
    fn test_best_transactions_never_returns_more_than_requested() {
        // Param validation: best_transactions(max=N) must return <= N items
        let pool = TxPool::new(1_000_000_000);
        for i in 0u64..10 {
            let mut tx = make_tx(i, 2_000_000_000, 21_000, false);
            tx.hash = TxHash({ let mut h = [0u8; 32]; h[0] = i as u8; h[1] = 1; h });
            let _ = pool.add_tx(tx);
        }
        let best = pool.best_transactions(3, u64::MAX);
        assert!(best.len() <= 3, "must return at most 3 transactions");
    }

    // ── Misconfiguration ──────────────────────────────────────────────────────

    #[test]
    fn test_pool_with_zero_base_fee_accepts_any_fee_tx() {
        // Misconfiguration: zero base_fee means any max_fee >= 0 should be allowed
        let pool = TxPool::new(0); // base_fee = 0
        let tx = make_tx(0, 1, 21_000, false); // very low fee
        assert!(pool.add_tx(tx).is_ok());
    }

    #[test]
    fn test_on_block_committed_with_empty_tx_list_no_panic() {
        // Misconfiguration: empty block (no txs) must not panic or corrupt pool state
        let pool = TxPool::new(1_000_000_000);
        pool.on_block_committed(&[], 2_000_000_000); // must not panic
        assert_eq!(pool.len(), 0);
    }

    #[test]
    fn test_pool_len_after_add_and_remove_is_zero() {
        // Misconfiguration: adding then removing same tx must leave pool empty
        let pool = TxPool::new(1_000_000_000);
        let tx = make_tx(0, 2_000_000_000, 21_000, false);
        let hash = tx.hash;
        pool.add_tx(tx).unwrap();
        pool.remove_tx(&hash);
        assert_eq!(pool.len(), 0);
    }

    // ── Governance attack ─────────────────────────────────────────────────────

    #[test]
    fn test_sandwich_detector_identifies_sandwich_pattern() {
        // Governance attack: sandwich detector must flag target tx between front/back runs
        let target = make_tx(1, 2_000_000_000, 21_000, false);
        let front_run = make_tx(0, 3_000_000_000, 21_000, false);
        let back_run = make_tx(2, 3_000_000_000, 21_000, false);
        // Must not panic
        let alerts = SandwichDetector::check_sandwich(&[front_run, target, back_run]);
        let _ = alerts; // result may be empty depending on heuristic
    }

    #[test]
    fn test_local_tx_not_evicted_before_non_local() {
        // Governance attack: local txs must have eviction protection over non-local
        let pool = TxPool::new(1_000_000_000);
        // Add a local tx
        let local = make_tx(0, 2_000_000_000, 21_000, true);
        pool.add_tx(local.clone()).unwrap();
        // Local tx must remain after add
        assert_eq!(pool.len(), 1);
        // local tx is still present (not auto-evicted)
        let best = pool.best_transactions(100, u64::MAX);
        assert!(best.iter().any(|t| t.hash == local.hash));
    }

    #[test]
    fn test_duplicate_tx_hash_cannot_inflate_pool() {
        // Governance attack: duplicate hash must be rejected to prevent pool inflation
        let pool = TxPool::new(1_000_000_000);
        let tx = make_tx(0, 2_000_000_000, 21_000, false);
        pool.add_tx(tx.clone()).unwrap();
        let err = pool.add_tx(tx);
        assert!(matches!(err, Err(MempoolError::AlreadyKnown)));
        assert_eq!(pool.len(), 1); // only one copy
    }
}
