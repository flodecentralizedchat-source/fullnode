// ============================================================
// fullnode/crates/types/src/block.rs
// Block data structures
// ============================================================

use serde::{Deserialize, Serialize};
use crate::{U256, H256, H160, BlockNumber, GasAmount, Transaction, MerklePatriciaTrie};

/// Block header — authenticated summary of a block.
/// Algorithm: keccak256 of RLP-encoded header fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockHeader {
    /// Hash of parent block header
    pub parent_hash:        H256,
    /// Keccak-256 of the uncle block list
    pub uncles_hash:        H256,
    /// Block proposer / fee recipient
    pub coinbase:           H160,
    /// Root of the state Merkle Patricia Trie
    pub state_root:         H256,
    /// Root of the transaction Merkle Trie
    pub transactions_root:  H256,
    /// Root of the receipts Merkle Trie
    pub receipts_root:      H256,
    /// 2048-bit bloom filter of all logs in block
    pub logs_bloom:         Bloom,
    /// PoW difficulty / PoS committee weight
    pub difficulty:         U256,
    /// Block height
    pub number:             BlockNumber,
    /// Gas limit voted by miners/validators
    pub gas_limit:          GasAmount,
    /// Actual gas consumed in this block
    pub gas_used:           GasAmount,
    /// Unix timestamp
    pub timestamp:          u64,
    /// Arbitrary extra data (max 32 bytes)
    pub extra_data:         Vec<u8>,
    /// PoW mix hash (zero for PoS)
    pub mix_hash:           H256,
    /// PoW nonce (zero for PoS)
    pub nonce:              u64,
    /// EIP-1559 base fee per gas
    pub base_fee_per_gas:   Option<U256>,
    /// EIP-4895 withdrawals root
    pub withdrawals_root:   Option<H256>,
}

impl BlockHeader {
    /// Compute the keccak256 hash of the RLP-encoded header.
    /// We RLP-encode all canonical fields using RlpStream.
    pub fn hash(&self) -> H256 {
        use sha3::{Digest, Keccak256};
        let encoded = self.rlp_encode();
        H256::from_slice(&Keccak256::digest(&encoded))
    }

    /// Manually RLP-encode the header fields.
    pub fn rlp_encode(&self) -> Vec<u8> {
        let mut stream = rlp::RlpStream::new_list(15);
        stream.append(&self.parent_hash.as_bytes());
        stream.append(&self.uncles_hash.as_bytes());
        stream.append(&self.coinbase.as_bytes());
        stream.append(&self.state_root.as_bytes());
        stream.append(&self.transactions_root.as_bytes());
        stream.append(&self.receipts_root.as_bytes());
        stream.append(&self.logs_bloom.0.as_ref());
        let mut diff = [0u8; 32];
        self.difficulty.to_big_endian(&mut diff);
        let d_trim = diff.iter().position(|&b| b != 0).map(|i| &diff[i..]).unwrap_or(&[0u8]);
        stream.append(&d_trim);
        stream.append(&self.number);
        stream.append(&self.gas_limit);
        stream.append(&self.gas_used);
        stream.append(&self.timestamp);
        stream.append(&self.extra_data.as_slice());
        stream.append(&self.mix_hash.as_bytes());
        stream.append(&self.nonce);
        stream.out().to_vec()
    }

    /// Verify this header links correctly to parent.
    pub fn validate_chain_link(&self, parent: &BlockHeader) -> bool {
        self.parent_hash == parent.hash()
            && self.number == parent.number + 1
            && self.timestamp > parent.timestamp
    }
}

/// Full block = header + body
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Block {
    pub header:       BlockHeader,
    pub transactions: Vec<Transaction>,
    pub uncles:       Vec<BlockHeader>,
    pub withdrawals:  Option<Vec<Withdrawal>>,
}

impl Block {
    pub fn hash(&self) -> H256 {
        self.header.hash()
    }

    pub fn number(&self) -> BlockNumber {
        self.header.number
    }

    /// Build a Merkle Patricia Trie root from transactions.
    /// Algorithm: Insert (RLP(index) → RLP(tx_hash)) pairs into MPT.
    pub fn compute_transactions_root(&self) -> H256 {
        let mut trie = MerklePatriciaTrie::new();
        for (i, tx) in self.transactions.iter().enumerate() {
            let mut key_stream = rlp::RlpStream::new();
            key_stream.append(&i);
            let key = key_stream.out().to_vec();
            let value = tx.hash().as_bytes().to_vec();
            trie.insert(key, value);
        }
        trie.root_hash()
    }
}

/// 2048-bit Bloom filter for O(1) log presence checks.
/// Algorithm: keccak256(data)[0..1] mod 2048 sets 3 bits.
/// We use Vec<u8> internally so serde works on all platforms.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bloom(pub [u8; 256]);

impl serde::Serialize for Bloom {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(&self.0)
    }
}

impl<'de> serde::Deserialize<'de> for Bloom {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let v: Vec<u8> = serde::Deserialize::deserialize(d)?;
        if v.len() != 256 {
            return Err(serde::de::Error::custom("bloom must be 256 bytes"));
        }
        let mut arr = [0u8; 256];
        arr.copy_from_slice(&v);
        Ok(Bloom(arr))
    }
}

impl Bloom {
    pub fn new() -> Self {
        Bloom([0u8; 256])
    }

    /// Set bloom bits for an item (3 of the 6 keccak256 bytes select bit positions).
    pub fn accrue(&mut self, data: &[u8]) {
        use sha3::{Digest, Keccak256};
        let hash = Keccak256::digest(data);
        for i in 0..3 {
            let bit = (((hash[i * 2] as usize) << 8) | (hash[i * 2 + 1] as usize)) & 0x7FF;
            self.0[255 - bit / 8] |= 1 << (bit % 8);
        }
    }

    /// O(1) membership test (may have false positives).
    pub fn contains(&self, data: &[u8]) -> bool {
        use sha3::{Digest, Keccak256};
        let hash = Keccak256::digest(data);
        for i in 0..3 {
            let bit = (((hash[i * 2] as usize) << 8) | (hash[i * 2 + 1] as usize)) & 0x7FF;
            if self.0[255 - bit / 8] & (1 << (bit % 8)) == 0 {
                return false;
            }
        }
        true
    }

    /// Merge two bloom filters (OR operation).
    pub fn merge(&mut self, other: &Bloom) {
        for i in 0..256 {
            self.0[i] |= other.0[i];
        }
    }
}

impl Default for Bloom {
    fn default() -> Self { Self::new() }
}

/// EIP-4895 validator withdrawal
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Withdrawal {
    pub index:           u64,
    pub validator_index: u64,
    pub address:         H160,
    pub amount:          u64, // in Gwei
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_header() -> BlockHeader {
        BlockHeader {
            parent_hash: H256::zero(), uncles_hash: H256::zero(),
            coinbase: H160::zero(), state_root: H256::zero(),
            transactions_root: H256::zero(), receipts_root: H256::zero(),
            logs_bloom: Bloom::new(),
            difficulty: U256::zero(), number: 1,
            gas_limit: 15_000_000, gas_used: 0,
            timestamp: 1_700_000_001, extra_data: vec![],
            mix_hash: H256::zero(), nonce: 0,
            base_fee_per_gas: None, withdrawals_root: None,
        }
    }

    #[test]
    fn test_header_hash_is_deterministic() {
        let h = dummy_header();
        assert_eq!(h.hash(), h.hash());
    }

    #[test]
    fn test_header_hash_changes_with_number() {
        let h1 = dummy_header();
        let mut h2 = h1.clone();
        h2.number = 2;
        assert_ne!(h1.hash(), h2.hash());
    }

    #[test]
    fn test_bloom_set_and_check() {
        let mut b = Bloom::new();
        b.accrue(b"Transfer");
        assert!(b.contains(b"Transfer"));
        assert!(!b.contains(b"Approval"));
    }

    #[test]
    fn test_validate_chain_link() {
        let parent = dummy_header();
        let mut child = dummy_header();
        child.number = 2;
        child.parent_hash = parent.hash();
        child.timestamp = parent.timestamp + 12;
        assert!(child.validate_chain_link(&parent));
    }
}
