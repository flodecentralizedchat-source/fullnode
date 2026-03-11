// ============================================================
// fullnode/crates/types/src/receipt.rs
// Transaction receipt types
// ============================================================

use serde::{Deserialize, Serialize};
use crate::{H256, H160, BlockNumber, GasAmount, Bloom};

/// Transaction execution receipt — included in block after execution.
/// Data structure: RLP list matching Ethereum Yellow Paper spec.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Receipt {
    /// EIP-658: 1 = success, 0 = failure (replaces old post-state root)
    pub status:           bool,
    /// Cumulative gas used in the block up to and including this tx
    pub cumulative_gas_used: GasAmount,
    /// Bloom filter of all logs emitted by this tx
    pub logs_bloom:       Bloom,
    /// All logs emitted during execution
    pub logs:             Vec<Log>,
    // ── Derived / indexed fields (not part of canonical RLP) ──
    pub tx_hash:          H256,
    pub tx_index:         u32,
    pub block_hash:       H256,
    pub block_number:     BlockNumber,
    pub gas_used:         GasAmount,
    /// Contract address created (None for calls)
    pub contract_address: Option<H160>,
}

impl Receipt {
    /// Build the 2048-bit Bloom filter from all logs (EIP-168).
    pub fn build_bloom(logs: &[Log]) -> Bloom {
        let mut bloom = Bloom::new();
        for log in logs {
            bloom.accrue(log.address.as_bytes());
            for topic in &log.topics {
                bloom.accrue(topic.as_bytes());
            }
        }
        bloom
    }
}

/// A single EVM log entry (event).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Log {
    /// The contract that emitted the log
    pub address: H160,
    /// Up to 4 indexed topics (topic[0] = event signature hash)
    pub topics:  Vec<H256>,
    /// ABI-encoded non-indexed parameters
    pub data:    Vec<u8>,
    /// Set to true for logs reverted by a chain reorganisation
    pub removed: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{H160, H256, Bloom};

    #[test]
    fn test_bloom_accrue_and_contains() {
        let mut bloom = Bloom::new();
        bloom.accrue(b"hello");
        assert!(bloom.contains(b"hello"));
        assert!(!bloom.contains(b"world"));
    }

    #[test]
    fn test_build_bloom_from_log() {
        let log = Log {
            address: H160::zero(),
            topics:  vec![H256::zero()],
            data:    vec![],
            removed: false,
        };
        let bloom = Receipt::build_bloom(&[log]);
        // Bloom must not be all zeros
        assert!(bloom.0.iter().any(|&b| b != 0));
    }
}
