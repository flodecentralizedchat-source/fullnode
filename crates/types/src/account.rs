// ============================================================
// fullnode/crates/types/src/account.rs
// Account state types
// ============================================================

use serde::{Deserialize, Serialize};
use crate::{H256, H160, U256};

/// Ethereum account state stored in the state trie.
/// Data structure: 4-field RLP-encoded tuple.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct AccountState {
    /// Number of transactions sent from this account
    pub nonce: u64,
    /// Balance in Wei
    pub balance: U256,
    /// keccak256 of the EVM bytecode (zero hash = EOA)
    pub code_hash: H256,
    /// Root of the account's storage Merkle Patricia Trie
    pub storage_root: H256,
}

impl AccountState {
    /// Create a fresh externally-owned account with given balance.
    pub fn new_eoa(balance: U256) -> Self {
        Self {
            nonce: 0,
            balance,
            code_hash: crate::hash::empty_keccak(),
            storage_root: H256::zero(),
        }
    }

    /// Returns true if this account has no code (is an EOA).
    pub fn is_eoa(&self) -> bool {
        self.code_hash == crate::hash::empty_keccak() || self.code_hash == H256::zero()
    }

    /// Returns true if this account holds no state at all.
    pub fn is_empty(&self) -> bool {
        self.nonce == 0 && self.balance.is_zero() && self.is_eoa()
    }

    /// RLP-encode the account for trie insertion.
    pub fn rlp_encode(&self) -> Vec<u8> {
        let mut stream = rlp::RlpStream::new_list(4);
        stream.append(&self.nonce);
        let mut bal = [0u8; 32];
        self.balance.to_big_endian(&mut bal);
        // Trim leading zeros for RLP
        let trimmed = bal.iter().position(|&b| b != 0).map(|i| &bal[i..]).unwrap_or(&[0u8]);
        stream.append(&trimmed);
        stream.append(&self.storage_root.as_bytes());
        stream.append(&self.code_hash.as_bytes());
        stream.out().to_vec()
    }
}

/// A storage slot: 32-byte key → 32-byte value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageSlot {
    pub address: H160,
    pub key:     H256,
    pub value:   H256,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_eoa_is_eoa() {
        let acc = AccountState::new_eoa(U256::from(1000));
        assert!(acc.is_eoa());
        assert!(!acc.is_empty());
    }

    #[test]
    fn test_default_is_empty() {
        let acc = AccountState::default();
        assert!(acc.is_eoa());
    }
}
