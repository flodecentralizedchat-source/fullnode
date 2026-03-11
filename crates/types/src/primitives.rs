// ============================================================
// fullnode/crates/types/src/primitives.rs
// Re-exports and primitive type aliases
// ============================================================

pub use primitive_types::{U256, H256, H160};
pub use bytes::Bytes;

/// A simple Merkle Patricia Trie placeholder used in block root computation.
/// Full implementation lives in fullnode-statedb.
pub struct MerklePatriciaTrie {
    entries: Vec<(Vec<u8>, Vec<u8>)>,
}

impl MerklePatriciaTrie {
    pub fn new() -> Self {
        Self { entries: Vec::new() }
    }

    pub fn insert(&mut self, key: Vec<u8>, value: Vec<u8>) {
        // Remove existing key if present
        self.entries.retain(|(k, _)| k != &key);
        self.entries.push((key, value));
    }

    /// Compute a deterministic root hash from the current entries.
    /// For production, this would be a proper MPT root; here we use
    /// keccak256 of the sorted, concatenated key-value pairs.
    pub fn root_hash(&self) -> crate::H256 {
        use sha3::{Digest, Keccak256};
        let mut sorted = self.entries.clone();
        sorted.sort_by_key(|(k, _)| k.clone());
        let mut hasher = Keccak256::new();
        for (k, v) in &sorted {
            hasher.update(k);
            hasher.update(v);
        }
        crate::H256::from_slice(&hasher.finalize())
    }
}
