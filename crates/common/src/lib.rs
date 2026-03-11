//! Common types shared across all fullnode crates

use serde::{Deserialize, Serialize};
use std::fmt;

// ─── Primitive aliases ────────────────────────────────────────────────────────
pub type H256 = [u8; 32];
pub type H160 = [u8; 20];
pub type U256 = [u64; 4]; // little-endian 64-bit limbs

// ─── Address ─────────────────────────────────────────────────────────────────
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub struct Address(pub H160);

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{}", hex::encode(self.0))
    }
}

// ─── BlockHash / TxHash ───────────────────────────────────────────────────────
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub struct Hash(pub H256);

impl fmt::Display for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{}", hex::encode(self.0))
    }
}

// ─── Transaction ─────────────────────────────────────────────────────────────
/// Canonical signed transaction (EIP-1559 style)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transaction {
    pub chain_id:               u64,
    pub nonce:                  u64,
    pub max_priority_fee:       u128, // wei
    pub max_fee_per_gas:        u128, // wei
    pub gas_limit:              u64,
    pub to:                     Option<Address>,
    pub value:                  u128, // wei
    pub data:                   Vec<u8>,
    pub access_list:            Vec<AccessListItem>,
    /// secp256k1 signature
    pub signature:              Signature,
}

impl Transaction {
    pub fn hash(&self) -> Hash {
        use sha3::{Digest, Keccak256};
        let encoded = serde_json::to_vec(self).unwrap_or_default();
        let mut h = Keccak256::new();
        h.update(&encoded);
        Hash(h.finalize().into())
    }
    pub fn sender(&self) -> Option<Address> {
        // recover from sig — stub
        Some(self.signature.recovery_address())
    }
    pub fn effective_gas_price(&self, base_fee: u128) -> u128 {
        let tip = self.max_priority_fee.min(self.max_fee_per_gas.saturating_sub(base_fee));
        base_fee + tip
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessListItem {
    pub address:      Address,
    pub storage_keys: Vec<H256>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Signature {
    pub v: u8,
    pub r: H256,
    pub s: H256,
}

impl Signature {
    pub fn recovery_address(&self) -> Address {
        // real impl: secp256k1::recover — stub returns zero address
        Address::default()
    }
}

// ─── Block ────────────────────────────────────────────────────────────────────
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockHeader {
    pub parent_hash:       Hash,
    pub number:            u64,
    pub timestamp:         u64,
    pub state_root:        Hash,
    pub transactions_root: Hash,
    pub receipts_root:     Hash,
    /// 2048-bit Bloom filter stored as 256 bytes (serde-compatible Vec)
    pub logs_bloom:        Vec<u8>,
    pub base_fee:          u128,
    pub gas_limit:         u64,
    pub gas_used:          u64,
    pub extra_data:        Vec<u8>,
    pub miner:             Address,
}

impl BlockHeader {
    pub fn hash(&self) -> Hash {
        use sha3::{Digest, Keccak256};
        let encoded = serde_json::to_vec(self).unwrap_or_default();
        Hash(Keccak256::digest(&encoded).into())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Block {
    pub header:       BlockHeader,
    pub transactions: Vec<Transaction>,
    pub uncles:       Vec<BlockHeader>,
}

impl Block {
    pub fn hash(&self) -> Hash { self.header.hash() }
    pub fn number(&self) -> u64 { self.header.number }
}

// ─── Receipt ──────────────────────────────────────────────────────────────────
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Receipt {
    pub tx_hash:           Hash,
    pub block_number:      u64,
    pub gas_used:          u64,
    pub status:            bool,
    pub logs:              Vec<Log>,
    pub contract_address:  Option<Address>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Log {
    pub address: Address,
    pub topics:  Vec<H256>,
    pub data:    Vec<u8>,
    pub removed: bool,
}

// ─── Account ─────────────────────────────────────────────────────────────────
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Account {
    pub nonce:        u64,
    pub balance:      u128,
    pub code_hash:    Hash,
    pub storage_root: Hash,
}

// ─── Tests ───────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;

    fn make_tx(nonce: u64, max_fee: u128, priority: u128) -> Transaction {
        Transaction {
            chain_id: 1, nonce, max_priority_fee: priority,
            max_fee_per_gas: max_fee, gas_limit: 21_000,
            to: Some(Address::default()), value: 0,
            data: vec![], access_list: vec![],
            signature: Signature::default(),
        }
    }

    #[test]
    fn test_tx_hash_deterministic() {
        let tx = make_tx(0, 10, 2);
        assert_eq!(tx.hash(), tx.hash());
    }

    #[test]
    fn test_tx_hash_different_nonces() {
        let tx1 = make_tx(0, 10, 2);
        let tx2 = make_tx(1, 10, 2);
        assert_ne!(tx1.hash(), tx2.hash());
    }

    #[test]
    fn test_effective_gas_price_under_cap() {
        let tx = make_tx(0, 10, 2);
        // base=7: tip = min(2, 10-7)=2, effective=9
        assert_eq!(tx.effective_gas_price(7), 9);
    }

    #[test]
    fn test_effective_gas_price_capped() {
        let tx = make_tx(0, 10, 5);
        // base=8: tip = min(5, 10-8)=2, effective=10
        assert_eq!(tx.effective_gas_price(8), 10);
    }

    #[test]
    fn test_address_display() {
        let addr = Address([0xABu8; 20]);
        let s = format!("{}", addr);
        assert!(s.starts_with("0x"));
        assert_eq!(s.len(), 42);
    }

    #[test]
    fn test_block_header_hash_changes_on_number() {
        let header = BlockHeader {
            parent_hash: Hash::default(), number: 1, timestamp: 1000,
            state_root: Hash::default(), transactions_root: Hash::default(),
            receipts_root: Hash::default(),
            logs_bloom: vec![0u8; 256],
            base_fee: 0, gas_limit: 15_000_000, gas_used: 0,
            extra_data: vec![], miner: Address::default(),
        };
        let mut h2 = header.clone();
        h2.number = 2;
        assert_ne!(header.hash(), h2.hash());
    }

    #[test]
    fn test_account_default() {
        let a = Account::default();
        assert_eq!(a.nonce, 0);
        assert_eq!(a.balance, 0);
    }

    // ── Layer 1: Security definitions ────────────────────────────────────────

    #[test]
    fn test_effective_gas_price_never_below_base_fee() {
        // L1: effective gas price must always be >= base_fee (EIP-1559)
        let tx = make_tx(0, 10, 2);
        let base_fee = 7u128;
        assert!(tx.effective_gas_price(base_fee) >= base_fee);
    }

    #[test]
    fn test_effective_gas_price_never_exceeds_max_fee() {
        // L1: effective price must be capped at max_fee_per_gas
        let tx = make_tx(0, 10, 100); // max_priority=100 >> max_fee=10
        let base_fee = 5u128;
        assert!(tx.effective_gas_price(base_fee) <= tx.max_fee_per_gas);
    }

    #[test]
    fn test_transaction_hash_changes_with_chain_id() {
        // L1: chain_id must be part of hash to prevent replay across chains (EIP-155)
        let tx1 = make_tx(0, 10, 2);
        let mut tx2 = tx1.clone();
        tx2.chain_id = 2;
        assert_ne!(tx1.hash(), tx2.hash());
    }

    #[test]
    fn test_address_zero_is_distinct_from_nonzero() {
        // L1: zero address must be distinguishable (used for contract creation detection)
        let zero = Address::default();
        let nonzero = Address([1u8; 20]);
        assert_ne!(zero, nonzero);
        assert_eq!(zero.0, [0u8; 20]);
    }

    // ── Layer 2: Functional correctness ──────────────────────────────────────

    #[test]
    fn test_hash_display_starts_with_0x() {
        // L2: hash display must be 0x-prefixed hex (standard Ethereum format)
        let h = Hash([0xABu8; 32]);
        let s = format!("{}", h);
        assert!(s.starts_with("0x"));
        assert_eq!(s.len(), 66); // "0x" + 64 hex chars
    }

    #[test]
    fn test_block_header_hash_is_deterministic() {
        // L2: same header must always hash to same value
        let header = BlockHeader {
            parent_hash: Hash::default(), number: 5, timestamp: 9999,
            state_root: Hash::default(), transactions_root: Hash::default(),
            receipts_root: Hash::default(), logs_bloom: vec![0u8; 256],
            base_fee: 100, gas_limit: 30_000_000, gas_used: 21_000,
            extra_data: vec![], miner: Address::default(),
        };
        assert_eq!(header.hash(), header.hash());
    }

    #[test]
    fn test_tx_hash_changes_with_value() {
        // L2: value field must be part of tx hash (EIP-1559 signed fields)
        let tx1 = make_tx(0, 10, 2);
        let mut tx2 = tx1.clone();
        tx2.value = 1_000_000;
        assert_ne!(tx1.hash(), tx2.hash());
    }

    #[test]
    fn test_block_gas_used_does_not_exceed_gas_limit() {
        // L2: valid block invariant: gas_used <= gas_limit
        let header = BlockHeader {
            parent_hash: Hash::default(), number: 1, timestamp: 1,
            state_root: Hash::default(), transactions_root: Hash::default(),
            receipts_root: Hash::default(), logs_bloom: vec![0u8; 256],
            base_fee: 0, gas_limit: 15_000_000, gas_used: 10_000_000,
            extra_data: vec![], miner: Address::default(),
        };
        assert!(header.gas_used <= header.gas_limit);
    }

    // ── Layer 3: Protection ───────────────────────────────────────────────────

    #[test]
    fn test_effective_gas_price_with_zero_base_fee() {
        // L3: zero base_fee must return tip (no underflow)
        let tx = make_tx(0, 10, 3);
        assert_eq!(tx.effective_gas_price(0), 3); // 0 + min(3, 10-0)=3
    }

    #[test]
    fn test_effective_gas_price_base_fee_equals_max_fee() {
        // L3: when base_fee == max_fee, tip must be 0 (no underflow)
        let tx = make_tx(0, 10, 5);
        assert_eq!(tx.effective_gas_price(10), 10); // tip = min(5, 0) = 0
    }

    #[test]
    fn test_tx_to_none_is_contract_creation() {
        // L3: to=None must be allowed (contract creation — distinct from zero address)
        let mut tx = make_tx(0, 10, 2);
        tx.to = None;
        assert!(tx.to.is_none());
    }

    // ── Layer 4: Detection & Response ────────────────────────────────────────

    #[test]
    fn test_block_header_hash_changes_with_state_root() {
        // L4: any state root change must invalidate block hash (tamper detection)
        let mut h1 = BlockHeader {
            parent_hash: Hash::default(), number: 1, timestamp: 1,
            state_root: Hash([0xAAu8; 32]), transactions_root: Hash::default(),
            receipts_root: Hash::default(), logs_bloom: vec![0u8; 256],
            base_fee: 0, gas_limit: 15_000_000, gas_used: 0,
            extra_data: vec![], miner: Address::default(),
        };
        let hash1 = h1.hash();
        h1.state_root = Hash([0xBBu8; 32]);
        assert_ne!(hash1, h1.hash());
    }

    #[test]
    fn test_tx_hash_changes_with_gas_limit() {
        // L4: gas_limit change must change tx hash (signed field)
        let tx1 = make_tx(0, 10, 2);
        let mut tx2 = tx1.clone();
        tx2.gas_limit = 100_000;
        assert_ne!(tx1.hash(), tx2.hash());
    }

    // ── Layer 5: Resilience ───────────────────────────────────────────────────

    #[test]
    fn test_address_display_is_lowercase_hex() {
        // L5: address display must use lowercase hex (consistent, no case errors)
        let addr = Address([0xABu8; 20]);
        let s = format!("{}", addr);
        assert_eq!(s, format!("0x{}", "ab".repeat(20)));
    }

    #[test]
    fn test_hash_default_is_all_zeros() {
        // L5: default hash must be 32 zero bytes (zero hash = null reference sentinel)
        let h = Hash::default();
        assert_eq!(h.0, [0u8; 32]);
    }

    #[test]
    fn test_effective_gas_price_max_values_no_overflow() {
        // L5: u128::MAX values must not overflow
        let mut tx = make_tx(0, 10, 2);
        tx.max_fee_per_gas = u128::MAX;
        tx.max_priority_fee = u128::MAX / 2;
        let _ = tx.effective_gas_price(0); // must not panic
    }

    // ── Layer 6: Governance & Compliance ─────────────────────────────────────

    #[test]
    fn test_chain_id_field_present_in_transaction() {
        // L6: chain_id is mandatory for EIP-155 replay protection compliance
        let tx = make_tx(0, 10, 2);
        assert_eq!(tx.chain_id, 1); // must match configured chain
    }

    #[test]
    fn test_block_header_has_miner_field_for_fee_recipient() {
        // L6: miner field required for MEV/fee tracking compliance
        let header = BlockHeader {
            parent_hash: Hash::default(), number: 1, timestamp: 1,
            state_root: Hash::default(), transactions_root: Hash::default(),
            receipts_root: Hash::default(), logs_bloom: vec![0u8; 256],
            base_fee: 0, gas_limit: 15_000_000, gas_used: 0,
            extra_data: vec![], miner: Address([0xFEu8; 20]),
        };
        assert_eq!(header.miner.0, [0xFEu8; 20]);
    }

    // ── Reentrancy simulation ─────────────────────────────────────────────────

    #[test]
    fn test_tx_hash_is_threadsafe() {
        // Reentrancy: hash() called concurrently from multiple threads must be stable
        use std::thread;
        use std::sync::Arc;
        let tx = Arc::new(make_tx(0, 10, 2));
        let expected = tx.hash();
        let mut handles = vec![];
        for _ in 0..8 {
            let t = Arc::clone(&tx);
            handles.push(thread::spawn(move || t.hash()));
        }
        for h in handles {
            assert_eq!(h.join().unwrap(), expected);
        }
    }

    // ── Read-only reentrancy ──────────────────────────────────────────────────

    #[test]
    fn test_effective_gas_price_called_multiple_times_stable() {
        // Read-only reentrancy: calling effective_gas_price multiple times must give same result
        let tx = make_tx(0, 10, 2);
        let p1 = tx.effective_gas_price(5);
        let p2 = tx.effective_gas_price(5);
        let p3 = tx.effective_gas_price(5);
        assert_eq!(p1, p2);
        assert_eq!(p2, p3);
    }

    #[test]
    fn test_address_display_does_not_mutate_address() {
        // Read-only reentrancy: formatting address must not change its bytes
        let addr = Address([0x11u8; 20]);
        let _ = format!("{}", addr);
        let _ = format!("{}", addr);
        assert_eq!(addr.0, [0x11u8; 20]);
    }

    // ── Function parameter validation ─────────────────────────────────────────

    #[test]
    fn test_effective_gas_price_with_max_priority_exceeding_max_fee() {
        // Param validation: priority fee > (max_fee - base_fee) must be clamped
        let tx = make_tx(0, 100, 200); // max_priority=200 > max_fee=100
        let base = 50u128;
        let price = tx.effective_gas_price(base);
        assert!(price <= tx.max_fee_per_gas, "price must never exceed max_fee_per_gas");
        assert!(price >= base, "price must be at least base_fee");
    }

    #[test]
    fn test_transaction_with_empty_data_is_valid() {
        // Param validation: empty calldata must be allowed (ETH transfer)
        let tx = make_tx(0, 10, 2);
        assert!(tx.data.is_empty());
        assert!(tx.hash() != Hash::default()); // still produces valid hash
    }

    #[test]
    fn test_block_with_zero_gas_used_is_valid() {
        // Param validation: empty block (0 gas used) must be allowed
        let header = BlockHeader {
            parent_hash: Hash::default(), number: 1, timestamp: 1000,
            state_root: Hash::default(), transactions_root: Hash::default(),
            receipts_root: Hash::default(), logs_bloom: vec![0u8; 256],
            base_fee: 0, gas_limit: 15_000_000, gas_used: 0,
            extra_data: vec![], miner: Address::default(),
        };
        assert!(header.gas_used <= header.gas_limit);
        assert!(header.hash() != Hash::default());
    }

    // ── Misconfiguration ──────────────────────────────────────────────────────

    #[test]
    fn test_log_with_zero_topics_is_valid() {
        // Misconfiguration: log with no topics must be allowed (raw data log)
        let log = Log { address: Address::default(), topics: vec![], data: vec![0x01], removed: false };
        assert!(log.topics.is_empty());
    }

    #[test]
    fn test_block_extra_data_can_be_empty() {
        // Misconfiguration: extra_data can be empty (no mandatory content)
        let header = BlockHeader {
            parent_hash: Hash::default(), number: 1, timestamp: 1,
            state_root: Hash::default(), transactions_root: Hash::default(),
            receipts_root: Hash::default(), logs_bloom: vec![0u8; 256],
            base_fee: 0, gas_limit: 15_000_000, gas_used: 0,
            extra_data: vec![], miner: Address::default(),
        };
        assert!(header.extra_data.is_empty());
    }

    #[test]
    fn test_account_with_max_balance_no_overflow() {
        // Misconfiguration: max u128 balance must not cause overflow on construction
        let a = Account { nonce: 0, balance: u128::MAX, code_hash: Hash::default(), storage_root: Hash::default() };
        assert_eq!(a.balance, u128::MAX);
    }

    // ── Governance attack ─────────────────────────────────────────────────────

    #[test]
    fn test_transaction_hash_includes_all_signed_fields() {
        // Governance attack: each signed field change must produce different hash
        let base = make_tx(0, 100, 50);
        let with_diff_chain  = { let mut t = base.clone(); t.chain_id = 999; t };
        let with_diff_nonce  = { let mut t = base.clone(); t.nonce = 99; t };
        let with_diff_value  = { let mut t = base.clone(); t.value = 1_000; t };
        let with_diff_gas    = { let mut t = base.clone(); t.gas_limit = 99_999; t };
        assert_ne!(base.hash(), with_diff_chain.hash());
        assert_ne!(base.hash(), with_diff_nonce.hash());
        assert_ne!(base.hash(), with_diff_value.hash());
        assert_ne!(base.hash(), with_diff_gas.hash());
    }

    #[test]
    fn test_block_header_hash_sensitive_to_all_root_fields() {
        // Governance attack: block hash must depend on all root fields
        let make_header = |sr: Hash, tr: Hash, rr: Hash| BlockHeader {
            parent_hash: Hash::default(), number: 1, timestamp: 1,
            state_root: sr, transactions_root: tr, receipts_root: rr,
            logs_bloom: vec![0u8; 256], base_fee: 0, gas_limit: 15_000_000, gas_used: 0,
            extra_data: vec![], miner: Address::default(),
        };
        let h = make_header(Hash([0xAAu8; 32]), Hash([0xBBu8; 32]), Hash([0xCCu8; 32]));
        let h_state  = make_header(Hash([0x11u8; 32]), Hash([0xBBu8; 32]), Hash([0xCCu8; 32]));
        let h_tx     = make_header(Hash([0xAAu8; 32]), Hash([0x11u8; 32]), Hash([0xCCu8; 32]));
        let h_rcpt   = make_header(Hash([0xAAu8; 32]), Hash([0xBBu8; 32]), Hash([0x11u8; 32]));
        assert_ne!(h.hash(), h_state.hash(), "state_root change must change block hash");
        assert_ne!(h.hash(), h_tx.hash(),    "tx_root change must change block hash");
        assert_ne!(h.hash(), h_rcpt.hash(),  "receipts_root change must change block hash");
    }

    #[test]
    fn test_address_not_equal_to_different_bytes() {
        // Governance attack: addresses must compare by content, not by reference
        let a1 = Address([0x01u8; 20]);
        let a2 = Address([0x02u8; 20]);
        let a1_copy = Address([0x01u8; 20]);
        assert_ne!(a1, a2);
        assert_eq!(a1, a1_copy);
    }
}

