// ============================================================
// fullnode/crates/types/src/hash.rs
// Hash type helpers
// ============================================================

use crate::H256;

/// Compute keccak256 of arbitrary bytes, returning H256.
pub fn keccak256(data: &[u8]) -> H256 {
    use sha3::{Digest, Keccak256};
    H256::from_slice(&Keccak256::digest(data))
}

/// Compute sha256 of arbitrary bytes, returning H256.
pub fn sha256(data: &[u8]) -> H256 {
    use sha2::{Digest, Sha256};
    H256::from_slice(&Sha256::digest(data))
}

/// Empty keccak256: keccak256(b"") — used as null code_hash for EOAs.
pub fn empty_keccak() -> H256 {
    keccak256(b"")
}

/// The RLP-encoded empty list hash — used as empty trie root.
pub fn empty_trie_hash() -> H256 {
    // keccak256(rlp(b"")) = 0x56e81f171...
    keccak256(&rlp::encode(&""))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keccak256_known_vector() {
        // keccak256(b"") is a well-known value
        let h = keccak256(b"");
        // 0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470
        assert_eq!(h.as_bytes()[0], 0xc5);
    }
}
