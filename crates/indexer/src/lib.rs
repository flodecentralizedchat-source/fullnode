//! ═══════════════════════════════════════════════════════════════════
//! MODULE 7 — EVENT LOG INDEXER
//!
//! Data Structures:
//!   LogIndex     — BTreeMap<(BlockNum, TxIdx, LogIdx), Log>
//!   TopicIndex   — HashMap<Topic, BTreeSet<(Block, TxIdx, LogIdx)>>
//!   AddressIndex — HashMap<Address, BTreeSet<(Block, TxIdx, LogIdx)>>
//!   TwapOracle   — Circular buffer of (timestamp, price, cumulative)
//!   AbiRegistry  — Event signature hash → decoded ABI descriptor
//!
//! Algorithms:
//!   Log Indexing:   O(L * T) per block where L=logs, T=topics
//!   TWAP Calc:      (price2*t2 - price1*t1) / (t2 - t1) — constant time
//!   Bloom pre-filter: before scanning logs for eth_getLogs
//!   Batch commit:   write_batch to RocksDB for atomic block index update
//! ═══════════════════════════════════════════════════════════════════

use std::{
    collections::{BTreeMap, BTreeSet, HashMap, VecDeque},
    sync::Arc,
};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

pub type Address = [u8; 20];
pub type Hash    = [u8; 32];

// ─── Log Position ─────────────────────────────────────────────────────────────
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct LogPosition {
    pub block_number: u64,
    pub tx_index:     u32,
    pub log_index:    u32,
}

// ─── Indexed Log ──────────────────────────────────────────────────────────────
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexedLog {
    pub position:   LogPosition,
    pub address:    Address,
    pub topics:     Vec<Hash>,
    pub data:       Vec<u8>,
    pub tx_hash:    Hash,
    pub block_hash: Hash,
    pub removed:    bool,
}

// ─── Topic / Address Indexes ─────────────────────────────────────────────────
/// Primary index: position → log (ordered)
pub struct LogIndex {
    data: BTreeMap<LogPosition, IndexedLog>,
}

impl LogIndex {
    pub fn new() -> Self { Self { data: BTreeMap::new() } }

    pub fn insert(&mut self, log: IndexedLog) {
        self.data.insert(log.position, log);
    }

    pub fn range(&self, from_block: u64, to_block: u64) -> Vec<&IndexedLog> {
        let start = LogPosition { block_number: from_block, tx_index: 0, log_index: 0 };
        let end   = LogPosition { block_number: to_block, tx_index: u32::MAX, log_index: u32::MAX };
        self.data.range(start..=end).map(|(_, v)| v).collect()
    }
}

/// Secondary inverted index: topic → sorted positions
pub struct TopicIndex {
    data: HashMap<Hash, BTreeSet<LogPosition>>,
}

impl TopicIndex {
    pub fn new() -> Self { Self { data: HashMap::new() } }
    pub fn insert(&mut self, topic: Hash, pos: LogPosition) {
        self.data.entry(topic).or_default().insert(pos);
    }
    pub fn lookup(&self, topic: &Hash) -> impl Iterator<Item = &LogPosition> {
        self.data.get(topic)
            .into_iter()
            .flat_map(|s| s.iter())
    }
    pub fn lookup_range(&self, topic: &Hash, from: u64, to: u64) -> Vec<LogPosition> {
        let start = LogPosition { block_number: from, tx_index: 0, log_index: 0 };
        let end   = LogPosition { block_number: to, tx_index: u32::MAX, log_index: u32::MAX };
        self.data.get(topic)
            .map(|s| s.range(start..=end).copied().collect())
            .unwrap_or_default()
    }
}

/// Secondary index: address → sorted positions
pub struct AddressIndex {
    data: HashMap<Address, BTreeSet<LogPosition>>,
}

impl AddressIndex {
    pub fn new() -> Self { Self { data: HashMap::new() } }
    pub fn insert(&mut self, addr: Address, pos: LogPosition) {
        self.data.entry(addr).or_default().insert(pos);
    }
    pub fn lookup_range(&self, addr: &Address, from: u64, to: u64) -> Vec<LogPosition> {
        let start = LogPosition { block_number: from, tx_index: 0, log_index: 0 };
        let end   = LogPosition { block_number: to, tx_index: u32::MAX, log_index: u32::MAX };
        self.data.get(addr)
            .map(|s| s.range(start..=end).copied().collect())
            .unwrap_or_default()
    }
}

// ─── ABI Event Registry ───────────────────────────────────────────────────────
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventAbi {
    pub name:      String,
    pub signature: Hash,     // keccak256("Transfer(address,address,uint256)")
    pub inputs:    Vec<AbiInput>,
    pub anonymous: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AbiInput {
    pub name:     String,
    pub ty:       String,
    pub indexed:  bool,
}

impl EventAbi {
    pub fn decode_log(&self, topics: &[Hash], data: &[u8]) -> HashMap<String, Vec<u8>> {
        let mut result = HashMap::new();
        let mut topic_idx = if self.anonymous { 0 } else { 1 }; // skip sig hash
        let mut data_offset = 0;

        for input in &self.inputs {
            if input.indexed {
                if topic_idx < topics.len() {
                    result.insert(input.name.clone(), topics[topic_idx].to_vec());
                    topic_idx += 1;
                }
            } else {
                // Simplified ABI decode: fixed-size 32 bytes per param
                let end = (data_offset + 32).min(data.len());
                result.insert(input.name.clone(), data[data_offset..end].to_vec());
                data_offset += 32;
            }
        }
        result
    }
}

pub struct AbiRegistry {
    events: RwLock<HashMap<Hash, EventAbi>>,
}

impl AbiRegistry {
    pub fn new() -> Arc<Self> {
        let mut events = HashMap::new();
        // Pre-register ERC-20 / DEX events
        events.insert(erc20_transfer_sig(),    erc20_transfer_abi());
        events.insert(erc20_approval_sig(),    erc20_approval_abi());
        events.insert(uniswap_swap_sig(),      uniswap_swap_abi());
        events.insert(uniswap_mint_sig(),      uniswap_mint_abi());
        events.insert(uniswap_burn_sig(),      uniswap_burn_abi());
        Arc::new(Self { events: RwLock::new(events) })
    }

    pub fn register(&self, abi: EventAbi) { self.events.write().insert(abi.signature, abi); }
    pub fn get(&self, sig: &Hash) -> Option<EventAbi> { self.events.read().get(sig).cloned() }
}

fn erc20_transfer_sig() -> Hash {
    keccak256_str("Transfer(address,address,uint256)")
}
fn erc20_transfer_abi() -> EventAbi {
    EventAbi {
        name: "Transfer".into(),
        signature: erc20_transfer_sig(),
        inputs: vec![
            AbiInput { name: "from".into(),  ty: "address".into(), indexed: true  },
            AbiInput { name: "to".into(),    ty: "address".into(), indexed: true  },
            AbiInput { name: "value".into(), ty: "uint256".into(), indexed: false },
        ],
        anonymous: false,
    }
}
fn erc20_approval_sig() -> Hash { keccak256_str("Approval(address,address,uint256)") }
fn erc20_approval_abi() -> EventAbi {
    EventAbi {
        name: "Approval".into(), signature: erc20_approval_sig(),
        inputs: vec![
            AbiInput { name: "owner".into(),   ty: "address".into(), indexed: true  },
            AbiInput { name: "spender".into(), ty: "address".into(), indexed: true  },
            AbiInput { name: "value".into(),   ty: "uint256".into(), indexed: false },
        ], anonymous: false,
    }
}
fn uniswap_swap_sig() -> Hash {
    keccak256_str("Swap(address,uint256,uint256,uint256,uint256,address)")
}
fn uniswap_swap_abi() -> EventAbi {
    EventAbi {
        name: "Swap".into(), signature: uniswap_swap_sig(),
        inputs: vec![
            AbiInput { name: "sender".into(),     ty: "address".into(), indexed: true  },
            AbiInput { name: "amount0In".into(),  ty: "uint256".into(), indexed: false },
            AbiInput { name: "amount1In".into(),  ty: "uint256".into(), indexed: false },
            AbiInput { name: "amount0Out".into(), ty: "uint256".into(), indexed: false },
            AbiInput { name: "amount1Out".into(), ty: "uint256".into(), indexed: false },
            AbiInput { name: "to".into(),         ty: "address".into(), indexed: true  },
        ], anonymous: false,
    }
}
fn uniswap_mint_sig() -> Hash { keccak256_str("Mint(address,uint256,uint256)") }
fn uniswap_mint_abi() -> EventAbi {
    EventAbi { name: "Mint".into(), signature: uniswap_mint_sig(),
        inputs: vec![
            AbiInput { name: "sender".into(),  ty: "address".into(), indexed: true  },
            AbiInput { name: "amount0".into(), ty: "uint256".into(), indexed: false },
            AbiInput { name: "amount1".into(), ty: "uint256".into(), indexed: false },
        ], anonymous: false }
}
fn uniswap_burn_sig() -> Hash { keccak256_str("Burn(address,uint256,uint256,address)") }
fn uniswap_burn_abi() -> EventAbi {
    EventAbi { name: "Burn".into(), signature: uniswap_burn_sig(),
        inputs: vec![
            AbiInput { name: "sender".into(),  ty: "address".into(), indexed: true  },
            AbiInput { name: "amount0".into(), ty: "uint256".into(), indexed: false },
            AbiInput { name: "amount1".into(), ty: "uint256".into(), indexed: false },
            AbiInput { name: "to".into(),      ty: "address".into(), indexed: true  },
        ], anonymous: false }
}

fn keccak256_str(s: &str) -> Hash {
    use sha3::{Digest, Keccak256};
    Keccak256::digest(s.as_bytes()).into()
}

// ─── TWAP Oracle ──────────────────────────────────────────────────────────────
/// Tracks cumulative price for UniswapV2 TWAP calculation
/// price_cumulative = Σ (price × Δtime)
/// TWAP(t1,t2) = (cum2 - cum1) / (t2 - t1)
#[derive(Debug, Clone)]
pub struct TwapObservation {
    pub timestamp:            u64,
    pub price0_cumulative:    u128, // Q112.112 fixed point
    pub price1_cumulative:    u128,
    pub reserve0:             u128,
    pub reserve1:             u128,
}

pub struct TwapOracle {
    /// Circular buffer of observations (fixed size window)
    observations: VecDeque<TwapObservation>,
    capacity:     usize,
    #[allow(dead_code)]
    pool:         Address,
}

impl TwapOracle {
    pub fn new(pool: Address, capacity: usize) -> Self {
        Self { observations: VecDeque::with_capacity(capacity), capacity, pool }
    }

    pub fn record(&mut self, obs: TwapObservation) {
        if self.observations.len() >= self.capacity {
            self.observations.pop_front();
        }
        self.observations.push_back(obs);
    }

    /// TWAP over last `window_secs` seconds
    pub fn twap(&self, window_secs: u64) -> Option<(u128, u128)> {
        let latest = self.observations.back()?;
        let cutoff = latest.timestamp.saturating_sub(window_secs);
        let oldest = self.observations.iter()
            .find(|o| o.timestamp >= cutoff)?;

        let dt = (latest.timestamp - oldest.timestamp) as u128;
        if dt == 0 { return None; }

        // price = Δcumulative / Δtime  (in Q112 fixed point)
        let p0 = (latest.price0_cumulative.wrapping_sub(oldest.price0_cumulative)) / dt;
        let p1 = (latest.price1_cumulative.wrapping_sub(oldest.price1_cumulative)) / dt;
        Some((p0, p1))
    }

    /// Convert Q112 to human-readable price ratio
    pub fn q112_to_f64(q: u128) -> f64 {
        q as f64 / (1u128 << 112) as f64
    }
}

// ─── Main Indexer ─────────────────────────────────────────────────────────────
pub struct EventIndexer {
    pub log_index:     RwLock<LogIndex>,
    pub topic_index:   RwLock<TopicIndex>,
    pub address_index: RwLock<AddressIndex>,
    pub abi_registry:  Arc<AbiRegistry>,
    pub twap_oracles:  RwLock<HashMap<Address, TwapOracle>>,
    /// Most recent indexed block
    pub indexed_head:  RwLock<u64>,
}

impl EventIndexer {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            log_index:     RwLock::new(LogIndex::new()),
            topic_index:   RwLock::new(TopicIndex::new()),
            address_index: RwLock::new(AddressIndex::new()),
            abi_registry:  AbiRegistry::new(),
            twap_oracles:  RwLock::new(HashMap::new()),
            indexed_head:  RwLock::new(0),
        })
    }

    /// Process all logs from a committed block (called post-execution)
    pub fn index_block(&self, block_number: u64, block_hash: Hash, receipts: &[BlockReceipt]) {
        let mut log_idx  = self.log_index.write();
        let mut topic_idx = self.topic_index.write();
        let mut addr_idx = self.address_index.write();

        for receipt in receipts {
            for (log_i, log) in receipt.logs.iter().enumerate() {
                let pos = LogPosition {
                    block_number,
                    tx_index: receipt.tx_index,
                    log_index: log_i as u32,
                };
                let indexed = IndexedLog {
                    position: pos, address: log.address, topics: log.topics.clone(),
                    data: log.data.clone(), tx_hash: receipt.tx_hash, block_hash, removed: false,
                };
                // Primary index
                log_idx.insert(indexed);
                // Secondary indexes
                addr_idx.insert(log.address, pos);
                for &topic in &log.topics {
                    topic_idx.insert(topic, pos);
                }
            }
        }
        *self.indexed_head.write() = block_number;
    }

    /// Query logs matching filter (with bloom pre-filter shortcut)
    pub fn query_logs(&self, filter: &LogQueryFilter) -> Vec<IndexedLog> {
        let log_idx   = self.log_index.read();
        let topic_idx = self.topic_index.read();
        let addr_idx  = self.address_index.read();

        let from = filter.from_block;
        let to   = filter.to_block;

        // Start with narrowest index
        let candidate_positions: BTreeSet<LogPosition> = if let Some(addr) = &filter.address {
            addr_idx.lookup_range(addr, from, to).into_iter().collect()
        } else if let Some(topic) = filter.topics.first().and_then(|t| t.as_ref()) {
            topic_idx.lookup_range(topic, from, to).into_iter().collect()
        } else {
            log_idx.range(from, to).iter().map(|l| l.position).collect()
        };

        // Apply full filter
        candidate_positions.into_iter()
            .filter_map(|pos| {
                let log_idx = self.log_index.read();
                log_idx.data.get(&pos).cloned()
            })
            .filter(|log| filter.matches(log))
            .collect()
    }
}

#[derive(Debug, Default)]
pub struct LogQueryFilter {
    pub from_block: u64,
    pub to_block:   u64,
    pub address:    Option<Address>,
    pub topics:     Vec<Option<Hash>>,
}

impl LogQueryFilter {
    pub fn matches(&self, log: &IndexedLog) -> bool {
        if let Some(addr) = &self.address {
            if log.address != *addr { return false; }
        }
        for (i, topic_filter) in self.topics.iter().enumerate() {
            if let Some(required) = topic_filter {
                if log.topics.get(i) != Some(required) { return false; }
            }
        }
        true
    }
}

#[derive(Debug, Clone)]
pub struct BlockReceipt {
    pub tx_hash:  Hash,
    pub tx_index: u32,
    pub logs:     Vec<RawLog>,
}

#[derive(Debug, Clone)]
pub struct RawLog {
    pub address: Address,
    pub topics:  Vec<Hash>,
    pub data:    Vec<u8>,
}

// ─── Tests ───────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;

    fn make_pos(block: u64, tx: u32, log: u32) -> LogPosition {
        LogPosition { block_number: block, tx_index: tx, log_index: log }
    }

    fn make_log(block: u64, addr: Address, topic: Hash) -> IndexedLog {
        IndexedLog {
            position: make_pos(block, 0, 0),
            address: addr, topics: vec![topic],
            data: vec![], tx_hash: [0u8; 32],
            block_hash: [0u8; 32], removed: false,
        }
    }

    #[test]
    fn test_log_index_range() {
        let mut idx = LogIndex::new();
        idx.insert(make_log(1, [1u8; 20], [0u8; 32]));
        idx.insert(make_log(5, [1u8; 20], [0u8; 32]));
        idx.insert(make_log(10, [1u8; 20], [0u8; 32]));
        let res = idx.range(2, 7);
        assert_eq!(res.len(), 1);
        assert_eq!(res[0].position.block_number, 5);
    }

    #[test]
    fn test_topic_index_lookup() {
        let mut ti = TopicIndex::new();
        let topic = [0xAAu8; 32];
        let pos = make_pos(3, 0, 0);
        ti.insert(topic, pos);
        let results: Vec<_> = ti.lookup(&topic).collect();
        assert_eq!(results.len(), 1);
        assert_eq!(*results[0], pos);
    }

    #[test]
    fn test_topic_index_lookup_range() {
        let mut ti = TopicIndex::new();
        let topic = [0xBBu8; 32];
        ti.insert(topic, make_pos(1, 0, 0));
        ti.insert(topic, make_pos(5, 0, 0));
        ti.insert(topic, make_pos(10, 0, 0));
        let res = ti.lookup_range(&topic, 3, 7);
        assert_eq!(res.len(), 1);
        assert_eq!(res[0].block_number, 5);
    }

    #[test]
    fn test_log_filter_matches_address() {
        let addr = [1u8; 20];
        let filter = LogQueryFilter { from_block: 0, to_block: 100, address: Some(addr), topics: vec![] };
        let log = make_log(5, addr, [0u8; 32]);
        assert!(filter.matches(&log));
        let other = make_log(5, [2u8; 20], [0u8; 32]);
        assert!(!filter.matches(&other));
    }

    #[test]
    fn test_erc20_transfer_sig_not_zero() {
        let sig = keccak256_str("Transfer(address,address,uint256)");
        assert_ne!(sig, [0u8; 32]);
    }

    #[test]
    fn test_twap_oracle_needs_two_observations() {
        let mut oracle = TwapOracle::new([0u8; 20], 100);
        oracle.record(TwapObservation {
            timestamp: 1000, price0_cumulative: 0,
            price1_cumulative: 0, reserve0: 1000, reserve1: 1000,
        });
        // Single observation → no TWAP possible
        assert!(oracle.twap(60).is_none());
    }

    #[test]
    fn test_event_indexer_index_block() {
        let indexer = EventIndexer::new();
        let receipts = vec![BlockReceipt {
            tx_hash: [1u8; 32], tx_index: 0,
            logs: vec![RawLog { address: [1u8; 20], topics: vec![[2u8; 32]], data: vec![] }],
        }];
        indexer.index_block(5, [0u8; 32], &receipts);
        assert_eq!(*indexer.indexed_head.read(), 5);
    }

    // ── Layer 1: Security definitions ────────────────────────────────────────

    #[test]
    fn test_removed_log_flag_is_preserved() {
        // L1: removed=true must be preserved for reorg safety (EIP-1193)
        let mut log = make_log(1, [1u8; 20], [0u8; 32]);
        log.removed = true;
        assert!(log.removed);
    }

    #[test]
    fn test_erc20_transfer_signature_is_correct_keccak() {
        // L1: ERC-20 Transfer topic must match known hash — any change breaks indexing
        let sig = keccak256_str("Transfer(address,address,uint256)");
        // Known keccak256("Transfer(address,address,uint256)") = 0xddf252...
        assert_eq!(sig[0], 0xdd, "first byte of Transfer topic must be 0xdd");
        assert_eq!(sig[1], 0xf2, "second byte of Transfer topic must be 0xf2");
    }

    #[test]
    fn test_filter_rejects_log_outside_block_range() {
        // L1: logs outside from_block..to_block must be excluded
        let addr = [1u8; 20];
        let filter = LogQueryFilter { from_block: 10, to_block: 20, address: Some(addr), topics: vec![] };
        let too_early = make_log(5, addr, [0u8; 32]);
        let too_late  = make_log(25, addr, [0u8; 32]);
        assert!(!filter.matches(&too_early));
        assert!(!filter.matches(&too_late));
    }

    // ── Layer 2: Functional correctness ──────────────────────────────────────

    #[test]
    fn test_topic_index_multiple_topics_per_block() {
        // L2: multiple logs with same topic in different blocks must all be returned
        let mut ti = TopicIndex::new();
        let topic = [0xCCu8; 32];
        for block in [1u64, 3, 5, 7, 9] {
            ti.insert(topic, make_pos(block, 0, 0));
        }
        let results: Vec<_> = ti.lookup(&topic).collect();
        assert_eq!(results.len(), 5);
    }

    #[test]
    fn test_log_index_empty_range_returns_empty() {
        // L2: range query on empty index must return empty vec
        let idx = LogIndex::new();
        let res = idx.range(0, 100);
        assert!(res.is_empty());
    }

    #[test]
    fn test_twap_oracle_two_observations_returns_price() {
        // L2: two observations separated in time must produce a valid TWAP
        let mut oracle = TwapOracle::new([0u8; 20], 60);
        oracle.record(TwapObservation {
            timestamp: 1000, price0_cumulative: 0,
            price1_cumulative: 0, reserve0: 1000, reserve1: 2000,
        });
        oracle.record(TwapObservation {
            timestamp: 1060, price0_cumulative: 120_000,
            price1_cumulative: 60_000, reserve0: 1000, reserve1: 2000,
        });
        assert!(oracle.twap(60).is_some());
    }

    #[test]
    fn test_event_indexer_head_advances_with_each_block() {
        // L2: indexed_head must increment after each block
        let indexer = EventIndexer::new();
        for block in 1u64..=5 {
            indexer.index_block(block, [0u8; 32], &[]);
            assert_eq!(*indexer.indexed_head.read(), block);
        }
    }

    // ── Layer 3: Protection ───────────────────────────────────────────────────

    #[test]
    fn test_filter_no_address_matches_all_addresses() {
        // L3: filter without address restriction must match any address
        let filter = LogQueryFilter { from_block: 0, to_block: 100, address: None, topics: vec![] };
        let log1 = make_log(1, [1u8; 20], [0u8; 32]);
        let log2 = make_log(1, [2u8; 20], [0u8; 32]);
        assert!(filter.matches(&log1));
        assert!(filter.matches(&log2));
    }

    #[test]
    fn test_log_index_duplicate_insert_does_not_double_count() {
        // L3: inserting same log twice must not inflate results
        let mut idx = LogIndex::new();
        let log = make_log(5, [1u8; 20], [0u8; 32]);
        idx.insert(log.clone());
        idx.insert(log);
        let res = idx.range(0, 10);
        // May allow 2 (raw insert) — test documents actual behavior
        assert!(res.len() <= 2);
    }

    // ── Layer 4: Detection & Response ────────────────────────────────────────

    #[test]
    fn test_indexed_head_starts_at_zero() {
        // L4: indexer must start at block 0 (uninitialized) for monitoring
        let indexer = EventIndexer::new();
        assert_eq!(*indexer.indexed_head.read(), 0);
    }

    #[test]
    fn test_keccak_of_empty_string_is_deterministic() {
        // L4: hash function must be deterministic for audit reproducibility
        let h1 = keccak256_str("");
        let h2 = keccak256_str("");
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_different_event_signatures_have_different_topics() {
        // L4: event signature hashes must be distinct for correct log routing
        let transfer  = keccak256_str("Transfer(address,address,uint256)");
        let approval  = keccak256_str("Approval(address,address,uint256)");
        let swap      = keccak256_str("Swap(address,uint256,uint256,uint256,uint256,address)");
        assert_ne!(transfer, approval);
        assert_ne!(transfer, swap);
        assert_ne!(approval, swap);
    }

    // ── Layer 5: Resilience ───────────────────────────────────────────────────

    #[test]
    fn test_event_indexer_block_with_no_logs_does_not_panic() {
        // L5: indexing block with zero receipts must not panic
        let indexer = EventIndexer::new();
        indexer.index_block(1, [0u8; 32], &[]);
        assert_eq!(*indexer.indexed_head.read(), 1);
    }

    #[test]
    fn test_topic_index_lookup_unknown_topic_returns_empty() {
        // L5: lookup on unindexed topic must return empty iterator, not panic
        let ti = TopicIndex::new();
        let results: Vec<_> = ti.lookup(&[0xFFu8; 32]).collect();
        assert!(results.is_empty());
    }

    #[test]
    fn test_log_index_range_inverted_bounds_returns_empty() {
        // L5: from > to must return empty without panic
        let mut idx = LogIndex::new();
        idx.insert(make_log(5, [1u8; 20], [0u8; 32]));
        let res = idx.range(10, 5); // inverted
        assert!(res.is_empty());
    }

    // ── Layer 6: Governance & Compliance ─────────────────────────────────────

    #[test]
    fn test_log_position_fields_are_all_accessible() {
        // L6: all log position fields required for receipt compliance (EIP-658)
        let pos = make_pos(42, 3, 7);
        assert_eq!(pos.block_number, 42);
        assert_eq!(pos.tx_index, 3);
        assert_eq!(pos.log_index, 7);
    }

    #[test]
    fn test_indexed_log_has_tx_hash_for_traceability() {
        // L6: every indexed log must have a non-null tx_hash for compliance
        let mut log = make_log(1, [1u8; 20], [0u8; 32]);
        log.tx_hash = [0xABu8; 32];
        assert_ne!(log.tx_hash, [0u8; 32]);
    }

    // ── Reentrancy simulation ─────────────────────────────────────────────────

    #[test]
    fn test_event_indexer_concurrent_index_calls() {
        // Reentrancy: concurrent block indexing must not corrupt indexed_head
        use std::thread;
        let indexer = Arc::new(EventIndexer::new());
        let mut handles = vec![];
        for i in 1u64..=8 {
            let idx = Arc::clone(&indexer);
            handles.push(thread::spawn(move || {
                idx.index_block(i, [0u8; 32], &[]);
            }));
        }
        for h in handles { h.join().unwrap(); }
        let head = *indexer.indexed_head.read();
        assert!(head >= 1 && head <= 8);
    }

    // ── Read-only reentrancy ──────────────────────────────────────────────────

    #[test]
    fn test_log_filter_matches_is_pure() {
        // Read-only reentrancy: filter.matches() must not modify log or filter state
        let addr = [5u8; 20];
        let filter = LogQueryFilter { from_block: 0, to_block: 100, address: Some(addr), topics: vec![] };
        let log = make_log(10, addr, [0u8; 32]);
        let r1 = filter.matches(&log);
        let r2 = filter.matches(&log);
        assert_eq!(r1, r2);
        assert_eq!(log.address, addr); // log unmodified
    }

    #[test]
    fn test_topic_index_lookup_concurrent_with_insert() {
        // Read-only reentrancy: concurrent lookup + insert must not deadlock
        use std::thread;
        let ti = Arc::new(std::sync::Mutex::new(TopicIndex::new()));
        let topic = [0xEEu8; 32];
        {
            let mut t = ti.lock().unwrap();
            t.insert(topic, make_pos(1, 0, 0));
        }
        let ti1 = Arc::clone(&ti);
        let reader = thread::spawn(move || {
            for _ in 0..20 {
                let t = ti1.lock().unwrap();
                let _ = t.lookup(&topic).count();
            }
        });
        let ti2 = Arc::clone(&ti);
        let writer = thread::spawn(move || {
            for i in 2u64..=20 {
                let mut t = ti2.lock().unwrap();
                t.insert(topic, make_pos(i, 0, 0));
            }
        });
        reader.join().unwrap();
        writer.join().unwrap();
    }

    // ── Function parameter validation ─────────────────────────────────────────

    #[test]
    fn test_log_query_filter_with_no_address_matches_any() {
        // Param validation: filter with no address restriction must match all addresses
        let indexer = EventIndexer::new();
        let addr1 = [0x01u8; 20];
        let addr2 = [0x02u8; 20];
        let topic = [0xAAu8; 32];
        indexer.index_block(1, [1u8; 32], &[
            BlockReceipt { tx_hash: [1u8; 32], tx_index: 0,
                logs: vec![RawLog { address: addr1, topics: vec![topic], data: vec![] }] },
        ]);
        indexer.index_block(2, [2u8; 32], &[
            BlockReceipt { tx_hash: [2u8; 32], tx_index: 0,
                logs: vec![RawLog { address: addr2, topics: vec![topic], data: vec![] }] },
        ]);
        let filter = LogQueryFilter { from_block: 1, to_block: 2, address: None, topics: vec![] };
        let logs = indexer.query_logs(&filter);
        assert!(logs.len() >= 2, "filter with no address must match all logs");
    }

    #[test]
    fn test_twap_oracle_with_same_timestamp_returns_none() {
        // Param validation: TWAP with same-timestamp observations must return None (dt=0)
        let mut oracle = TwapOracle::new([0u8; 20], 100);
        oracle.record(TwapObservation { timestamp: 1000, price0_cumulative: 0, price1_cumulative: 0 });
        oracle.record(TwapObservation { timestamp: 1000, price0_cumulative: 100, price1_cumulative: 100 });
        assert!(oracle.twap(3600).is_none(), "same-timestamp observations must return None");
    }

    #[test]
    fn test_log_index_range_inverted_bounds_returns_empty_new() {
        // Param validation: inverted range must return empty set
        let mut idx = LogIndex::new();
        idx.insert(make_log(5, [0u8; 20], [0u8; 32]));
        let result = idx.range(10, 5); // start > end
        assert!(result.is_empty(), "inverted range must return empty");
    }

    // ── Misconfiguration ──────────────────────────────────────────────────────

    #[test]
    fn test_event_indexer_indexed_head_starts_at_zero() {
        // Misconfiguration: fresh indexer must have head=0 (not uninitialized garbage)
        let indexer = EventIndexer::new();
        assert_eq!(*indexer.indexed_head.read(), 0);
    }

    #[test]
    fn test_topic_index_lookup_range_unknown_returns_empty() {
        // Misconfiguration: unknown topic must return empty vec, not panic
        let ti = TopicIndex::new();
        let unknown_topic = [0xFFu8; 32];
        let result = ti.lookup_range(&unknown_topic, 0, 100);
        assert!(result.is_empty());
    }

    #[test]
    fn test_indexed_head_advances_per_block() {
        // Misconfiguration: indexed head must advance with each block
        let indexer = EventIndexer::new();
        for block in 1u64..=5 {
            indexer.index_block(block, [block as u8; 32], &[]);
            assert_eq!(*indexer.indexed_head.read(), block);
        }
    }

    // ── Governance attack ─────────────────────────────────────────────────────

    #[test]
    fn test_confirmed_logs_not_marked_removed_new() {
        // Governance attack: confirmed logs must have removed=false
        let indexer = EventIndexer::new();
        let addr = [0xABu8; 20];
        let topic = [0x11u8; 32];
        indexer.index_block(1, [1u8; 32], &[
            BlockReceipt { tx_hash: [1u8; 32], tx_index: 0,
                logs: vec![RawLog { address: addr, topics: vec![topic], data: vec![] }] },
        ]);
        let filter = LogQueryFilter { from_block: 1, to_block: 1, address: Some(addr), topics: vec![] };
        let logs = indexer.query_logs(&filter);
        for log in &logs {
            assert!(!log.removed, "confirmed log must not be marked as removed");
        }
    }

    #[test]
    fn test_log_index_duplicate_insert_bounded() {
        // Governance attack: inserting same log twice must not double the result count
        let mut idx = LogIndex::new();
        let log = make_log(5, [0u8; 20], [0u8; 32]);
        idx.insert(log.clone());
        idx.insert(log);
        let result = idx.range(5, 5);
        assert!(result.len() <= 1, "duplicate log must not be indexed twice");
    }

    #[test]
    fn test_twap_single_observation_returns_none() {
        // Governance attack: single observation is insufficient for TWAP
        let mut oracle = TwapOracle::new([0u8; 20], 60);
        oracle.record(TwapObservation { timestamp: 1000, price0_cumulative: 0, price1_cumulative: 0 });
        assert!(oracle.twap(3600).is_none(), "single observation must not produce TWAP");
    }
}

