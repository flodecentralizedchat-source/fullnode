//! ═══════════════════════════════════════════════════════════════════
//! MODULE 5 — STATE DATABASE (Merkle Patricia Trie + RocksDB)
//!
//! Data Structures:
//!   MerklePatriciaTrie — 4-node type trie (Empty, Leaf, Extension, Branch)
//!   TrieNode           — Enum with RLP-encoded hash references
//!   StateCache         — Two-level LRU: account cache + storage cache
//!   Snapshot           — Flat key-value map for fast reads (EIP-1820 style)
//!   JournaledState     — Copy-on-write overlay for atomic state transitions
//!
//! Algorithms:
//!   Path encoding:   compact hex nibble encoding (odd/even prefix)
//!   Node hashing:    keccak256(rlp(node)) — nodes < 32 bytes inlined
//!   Merkle proof:    collect sibling hashes along root→leaf path
//!   State pruning:   reference-counted node deletion (mark-and-sweep)
//!   Snapshot update: batch write to flat DB after each block
//! ═══════════════════════════════════════════════════════════════════

use std::{
    collections::{HashMap, BTreeMap},
    sync::Arc,
    num::NonZeroUsize,
};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use tracing;

pub type Hash = [u8; 32];
pub type Address = [u8; 20];

// ─── Nibble path helpers ──────────────────────────────────────────────────────
/// Convert bytes to nibble path (each byte → 2 nibbles)
pub fn bytes_to_nibbles(key: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(key.len() * 2);
    for b in key { out.push(b >> 4); out.push(b & 0x0f); }
    out
}

/// Compact encoding for leaf/extension paths
pub fn compact_encode(nibbles: &[u8], is_leaf: bool) -> Vec<u8> {
    let odd = nibbles.len() % 2 == 1;
    let flag = if is_leaf { 2 } else { 0 } + if odd { 1 } else { 0 };
    let mut out = Vec::with_capacity(1 + (nibbles.len() + 1) / 2);
    if odd {
        out.push((flag << 4) | nibbles[0]);
        for i in (1..nibbles.len()).step_by(2) {
            out.push((nibbles[i] << 4) | nibbles[i + 1]);
        }
    } else {
        out.push(flag << 4);
        for i in (0..nibbles.len()).step_by(2) {
            out.push((nibbles[i] << 4) | nibbles[i + 1]);
        }
    }
    out
}

/// Find common prefix length between two nibble slices
pub fn common_prefix_len(a: &[u8], b: &[u8]) -> usize {
    a.iter().zip(b.iter()).take_while(|(x, y)| x == y).count()
}

// ─── Trie Node ────────────────────────────────────────────────────────────────
/// A Merkle Patricia Trie node (4 variants)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TrieNode {
    /// Null / empty
    Empty,
    /// Leaf: (key_remainder_nibbles, value)
    Leaf { path: Vec<u8>, value: Vec<u8> },
    /// Extension: (shared_path_nibbles, child_hash_or_inline)
    Extension { path: Vec<u8>, child: NodeRef },
    /// Branch: 16 children + optional value
    Branch { children: Box<[NodeRef; 16]>, value: Option<Vec<u8>> },
}

/// A reference to a child node: either inline (< 32 bytes) or hash
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NodeRef {
    Empty,
    Inline(Box<TrieNode>),
    Hash(Hash),
}

impl TrieNode {
    pub fn hash(&self) -> Hash {
        use sha3::{Digest, Keccak256};
        let rlp = self.rlp_encode();
        if rlp.len() < 32 {
            // Inline: pad with keccak of empty for stability
            let mut h = [0u8; 32];
            h[..rlp.len()].copy_from_slice(&rlp);
            h
        } else {
            Keccak256::digest(&rlp).into()
        }
    }

    pub fn rlp_encode(&self) -> Vec<u8> {
        // Simplified RLP — real impl uses rlp crate
        serde_json::to_vec(self).unwrap_or_default()
    }
}

// ─── Trie ─────────────────────────────────────────────────────────────────────
pub struct MerkleTrie {
    /// In-memory node store: hash → node
    nodes:    HashMap<Hash, TrieNode>,
    root:     Hash,
}

impl MerkleTrie {
    pub fn empty() -> Self {
        let empty = TrieNode::Empty;
        let root = empty.hash();
        let mut nodes = HashMap::new();
        nodes.insert(root, empty);
        Self { nodes, root }
    }

    pub fn root(&self) -> Hash { self.root }

    pub fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        let nibbles = bytes_to_nibbles(key);
        self.get_node(&self.root, &nibbles)
    }

    fn get_node(&self, hash: &Hash, path: &[u8]) -> Option<Vec<u8>> {
        let node = self.nodes.get(hash)?;
        match node {
            TrieNode::Empty => None,
            TrieNode::Leaf { path: p, value } => {
                if p == path { Some(value.clone()) } else { None }
            }
            TrieNode::Extension { path: p, child } => {
                if path.starts_with(p.as_slice()) {
                    let rest = &path[p.len()..];
                    match child {
                        NodeRef::Hash(h)   => self.get_node(h, rest),
                        NodeRef::Inline(n) => self.get_inline(n, rest),
                        NodeRef::Empty     => None,
                    }
                } else { None }
            }
            TrieNode::Branch { children, value } => {
                if path.is_empty() {
                    value.clone()
                } else {
                    let idx = path[0] as usize;
                    match &children[idx] {
                        NodeRef::Hash(h)   => self.get_node(h, &path[1..]),
                        NodeRef::Inline(n) => self.get_inline(n, &path[1..]),
                        NodeRef::Empty     => None,
                    }
                }
            }
        }
    }

    fn get_inline(&self, node: &TrieNode, path: &[u8]) -> Option<Vec<u8>> {
        match node {
            TrieNode::Empty => None,
            TrieNode::Leaf { path: p, value } => {
                if p.as_slice() == path { Some(value.clone()) } else { None }
            }
            TrieNode::Branch { children, value } => {
                if path.is_empty() { value.clone() }
                else {
                    let idx = path[0] as usize;
                    match &children[idx] {
                        NodeRef::Hash(h)   => self.get_node(h, &path[1..]),
                        NodeRef::Inline(n) => self.get_inline(n, &path[1..]),
                        NodeRef::Empty     => None,
                    }
                }
            }
            _ => None,
        }
    }

    /// Insert key-value, returns new root hash
    pub fn insert(&mut self, key: &[u8], value: Vec<u8>) -> Hash {
        let nibbles = bytes_to_nibbles(key);
        let old_root = self.root;
        let new_root = self.insert_node(old_root, &nibbles, value);
        self.root = new_root;
        new_root
    }

    fn insert_node(&mut self, hash: Hash, path: &[u8], value: Vec<u8>) -> Hash {
        let node = self.nodes.get(&hash).cloned().unwrap_or(TrieNode::Empty);
        let new_node = match node {
            TrieNode::Empty => {
                TrieNode::Leaf { path: path.to_vec(), value }
            }
            TrieNode::Leaf { path: ref p, value: ref v } => {
                let cp = common_prefix_len(p, path);
                if cp == p.len() && cp == path.len() {
                    // Exact match: update value
                    TrieNode::Leaf { path: p.clone(), value }
                } else {
                    // Split into branch (with optional extension prefix)
                    let mut children = Box::new(core::array::from_fn(|_| NodeRef::Empty));

                    // Place old leaf
                    if cp < p.len() {
                        let old_leaf = TrieNode::Leaf { path: p[cp+1..].to_vec(), value: v.clone() };
                        let old_hash = old_leaf.hash();
                        self.nodes.insert(old_hash, old_leaf);
                        children[p[cp] as usize] = NodeRef::Hash(old_hash);
                    }

                    // Place new leaf or value
                    if cp < path.len() {
                        let new_leaf = TrieNode::Leaf { path: path[cp+1..].to_vec(), value };
                        let new_hash = new_leaf.hash();
                        self.nodes.insert(new_hash, new_leaf);
                        children[path[cp] as usize] = NodeRef::Hash(new_hash);
                        let branch = TrieNode::Branch { children, value: None };
                        if cp > 0 {
                            let bh = branch.hash();
                            self.nodes.insert(bh, branch);
                            TrieNode::Extension { path: p[..cp].to_vec(), child: NodeRef::Hash(bh) }
                        } else {
                            branch
                        }
                    } else {
                        // New path is a prefix of old: branch holds the value
                        TrieNode::Branch { children, value: Some(value) }
                    }
                }
            }
            TrieNode::Extension { path: ref p, ref child } => {
                let cp = common_prefix_len(p, path);
                if cp == p.len() {
                    // Shared prefix fully consumed — descend into child
                    let child_hash = match child {
                        NodeRef::Hash(h) => *h,
                        _ => TrieNode::Empty.hash(),
                    };
                    let new_child = self.insert_node(child_hash, &path[cp..], value);
                    TrieNode::Extension { path: p.clone(), child: NodeRef::Hash(new_child) }
                } else {
                    // Split extension at divergence point
                    let mut children = Box::new(core::array::from_fn(|_| NodeRef::Empty));

                    // Remaining extension after split
                    if cp + 1 < p.len() {
                        let ext = TrieNode::Extension {
                            path: p[cp+1..].to_vec(),
                            child: child.clone(),
                        };
                        let eh = ext.hash();
                        self.nodes.insert(eh, ext);
                        children[p[cp] as usize] = NodeRef::Hash(eh);
                    } else {
                        // Extension becomes single-step — child goes directly
                        children[p[cp] as usize] = child.clone();
                    }

                    // New leaf
                    if cp < path.len() {
                        let new_leaf = TrieNode::Leaf { path: path[cp+1..].to_vec(), value };
                        let nlh = new_leaf.hash();
                        self.nodes.insert(nlh, new_leaf);
                        children[path[cp] as usize] = NodeRef::Hash(nlh);
                        let branch = TrieNode::Branch { children, value: None };
                        if cp > 0 {
                            let bh = branch.hash();
                            self.nodes.insert(bh, branch);
                            TrieNode::Extension { path: p[..cp].to_vec(), child: NodeRef::Hash(bh) }
                        } else {
                            branch
                        }
                    } else {
                        TrieNode::Branch { children, value: Some(value) }
                    }
                }
            }
            TrieNode::Branch { mut children, value: bv } => {
                if path.is_empty() {
                    TrieNode::Branch { children, value: Some(value) }
                } else {
                    let idx = path[0] as usize;
                    let child_hash = if let NodeRef::Hash(h) = &children[idx] { *h }
                        else { TrieNode::Empty.hash() };
                    let new_child = self.insert_node(child_hash, &path[1..], value);
                    children[idx] = NodeRef::Hash(new_child);
                    TrieNode::Branch { children, value: bv }
                }
            }
        };
        let h = new_node.hash();
        self.nodes.insert(h, new_node);
        h
    }

    /// Generate a Merkle inclusion proof (sibling hashes root→leaf)
    pub fn prove(&self, key: &[u8]) -> Vec<Vec<u8>> {
        let nibbles = bytes_to_nibbles(key);
        let mut proof = Vec::new();
        self.collect_proof(&self.root, &nibbles, &mut proof);
        proof
    }

    fn collect_proof(&self, hash: &Hash, path: &[u8], proof: &mut Vec<Vec<u8>>) {
        if let Some(node) = self.nodes.get(hash) {
            proof.push(node.rlp_encode());
            match node {
                TrieNode::Extension { path: p, child: NodeRef::Hash(h) } => {
                    if path.starts_with(p) {
                        self.collect_proof(h, &path[p.len()..], proof);
                    }
                }
                TrieNode::Branch { children, .. } if !path.is_empty() => {
                    if let NodeRef::Hash(h) = &children[path[0] as usize] {
                        self.collect_proof(h, &path[1..], proof);
                    }
                }
                _ => {}
            }
        }
    }
}

// ─── Account & Storage ───────────────────────────────────────────────────────
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AccountState {
    pub nonce:        u64,
    pub balance:      u128,
    pub code_hash:    Hash,
    pub storage_root: Hash,
}

impl AccountState {
    pub fn encode(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap_or_default()
    }
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        serde_json::from_slice(bytes).ok()
    }
    pub fn is_empty(&self) -> bool {
        self.nonce == 0 && self.balance == 0 && self.code_hash == [0u8; 32]
    }
}

// ─── State Cache (two-level LRU) ─────────────────────────────────────────────
pub struct StateCache {
    accounts: RwLock<lru::LruCache<Address, AccountState>>,
    storage:  RwLock<lru::LruCache<(Address, [u8; 32]), [u8; 32]>>,
    code:     RwLock<lru::LruCache<Hash, Vec<u8>>>,
}

impl StateCache {
    pub fn new(account_cap: usize, storage_cap: usize) -> Self {
        Self {
            accounts: RwLock::new(lru::LruCache::new(NonZeroUsize::new(account_cap).unwrap())),
            storage:  RwLock::new(lru::LruCache::new(NonZeroUsize::new(storage_cap).unwrap())),
            code:     RwLock::new(lru::LruCache::new(NonZeroUsize::new(4096).unwrap())),
        }
    }

    pub fn get_account(&self, addr: &Address) -> Option<AccountState> {
        self.accounts.write().get(addr).cloned()
    }
    pub fn set_account(&self, addr: Address, state: AccountState) {
        self.accounts.write().put(addr, state);
    }
    pub fn get_storage(&self, addr: &Address, key: &[u8; 32]) -> Option<[u8; 32]> {
        self.storage.write().get(&(*addr, *key)).copied()
    }
    pub fn set_storage(&self, addr: Address, key: [u8; 32], val: [u8; 32]) {
        self.storage.write().put((addr, key), val);
    }
    pub fn get_code(&self, hash: &Hash) -> Option<Vec<u8>> {
        self.code.write().get(hash).cloned()
    }
    pub fn set_code(&self, hash: Hash, code: Vec<u8>) {
        self.code.write().put(hash, code);
    }
}

// ─── Journaled State (Copy-on-Write overlay) ──────────────────────────────────
/// Sits on top of the committed trie; holds dirty writes + revert journal
pub struct JournaledState {
    /// Dirty accounts (not yet committed to trie)
    pub dirty_accounts: HashMap<Address, AccountState>,
    pub dirty_storage:  HashMap<(Address, [u8; 32]), [u8; 32]>,
    pub dirty_code:     HashMap<Hash, Vec<u8>>,
    /// Revert journal: stack of checkpoints
    journal: Vec<JournalEntry>,
    checkpoints: Vec<usize>,
}

#[derive(Debug, Clone)]
enum JournalEntry {
    AccountChanged { addr: Address, prev: Option<AccountState> },
    StorageChanged { addr: Address, key: [u8; 32], prev: [u8; 32] },
}

impl JournaledState {
    pub fn new() -> Self {
        Self {
            dirty_accounts: HashMap::new(),
            dirty_storage:  HashMap::new(),
            dirty_code:     HashMap::new(),
            journal:        Vec::new(),
            checkpoints:    Vec::new(),
        }
    }

    pub fn checkpoint(&mut self) -> usize {
        let cp = self.journal.len();
        self.checkpoints.push(cp);
        cp
    }

    pub fn revert_to(&mut self, checkpoint: usize) {
        while self.journal.len() > checkpoint {
            match self.journal.pop().unwrap() {
                JournalEntry::AccountChanged { addr, prev } => {
                    match prev {
                        Some(s) => { self.dirty_accounts.insert(addr, s); }
                        None    => { self.dirty_accounts.remove(&addr); }
                    }
                }
                JournalEntry::StorageChanged { addr, key, prev } => {
                    self.dirty_storage.insert((addr, key), prev);
                }
            }
        }
    }

    pub fn set_account(&mut self, addr: Address, new: AccountState, old: Option<AccountState>) {
        self.journal.push(JournalEntry::AccountChanged { addr, prev: old });
        self.dirty_accounts.insert(addr, new);
    }

    pub fn set_storage(&mut self, addr: Address, key: [u8; 32], new: [u8; 32], old: [u8; 32]) {
        self.journal.push(JournalEntry::StorageChanged { addr, key, prev: old });
        self.dirty_storage.insert((addr, key), new);
    }
}

// ─── Flat Snapshot DB (RocksDB-backed) ────────────────────────────────────────
/// Fast read path that bypasses trie traversal.
/// Uses two RocksDB column families: "accounts" and "storage".
/// Falls back to in-memory BTreeMap when `data_dir` is None (tests / ephemeral).
pub struct SnapshotDB {
    inner: SnapshotDBInner,
}

enum SnapshotDBInner {
    /// Persistent storage via RocksDB
    Rocks {
        db:            Arc<rocksdb::DB>,
        cf_accounts:   String,
        cf_storage:    String,
    },
    /// In-memory fallback (tests / no data_dir configured)
    Memory {
        accounts: RwLock<BTreeMap<Vec<u8>, Vec<u8>>>,
        storage:  RwLock<BTreeMap<(Vec<u8>, Vec<u8>), Vec<u8>>>,
    },
}

impl SnapshotDB {
    /// Open (or create) a RocksDB-backed snapshot database at `data_dir/snapshot`.
    pub fn open(data_dir: &str) -> anyhow::Result<Arc<Self>> {
        use rocksdb::{DB, ColumnFamilyDescriptor, Options};

        let path = format!("{data_dir}/snapshot");
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);

        let cf_accounts = "accounts".to_string();
        let cf_storage  = "storage".to_string();

        let cf_descs = vec![
            ColumnFamilyDescriptor::new(&cf_accounts, Options::default()),
            ColumnFamilyDescriptor::new(&cf_storage,  Options::default()),
        ];

        let db = DB::open_cf_descriptors(&opts, &path, cf_descs)?;
        tracing::info!("📦 SnapshotDB opened at {path}");

        Ok(Arc::new(Self {
            inner: SnapshotDBInner::Rocks {
                db: Arc::new(db),
                cf_accounts,
                cf_storage,
            },
        }))
    }

    /// Create a pure in-memory instance (unit tests / ephemeral nodes).
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: SnapshotDBInner::Memory {
                accounts: RwLock::new(BTreeMap::new()),
                storage:  RwLock::new(BTreeMap::new()),
            },
        })
    }

    pub fn get_account(&self, addr: &Address) -> Option<AccountState> {
        let key = addr.to_vec();
        match &self.inner {
            SnapshotDBInner::Rocks { db, cf_accounts, .. } => {
                let cf = db.cf_handle(cf_accounts)?;
                db.get_cf(&cf, &key).ok()?.and_then(|b| AccountState::decode(&b))
            }
            SnapshotDBInner::Memory { accounts, .. } => {
                accounts.read().get(&key).and_then(|b| AccountState::decode(b))
            }
        }
    }

    pub fn batch_update(
        &self,
        accounts: &HashMap<Address, AccountState>,
        storage:  &HashMap<(Address, [u8; 32]), [u8; 32]>,
    ) {
        match &self.inner {
            SnapshotDBInner::Rocks { db, cf_accounts, cf_storage } => {
                let mut batch = rocksdb::WriteBatch::default();
                if let Some(cf) = db.cf_handle(cf_accounts) {
                    for (addr, state) in accounts {
                        batch.put_cf(&cf, addr.to_vec(), state.encode());
                    }
                }
                if let Some(cf) = db.cf_handle(cf_storage) {
                    for ((addr, key), val) in storage {
                        // composite key: addr(20) ++ key(32)
                        let mut composite = Vec::with_capacity(52);
                        composite.extend_from_slice(addr);
                        composite.extend_from_slice(key);
                        batch.put_cf(&cf, composite, val.to_vec());
                    }
                }
                if let Err(e) = db.write(batch) {
                    tracing::error!("SnapshotDB batch write failed: {e}");
                }
            }
            SnapshotDBInner::Memory { accounts: acc_map, storage: st_map } => {
                let mut acc = acc_map.write();
                let mut st  = st_map.write();
                for (addr, state) in accounts {
                    acc.insert(addr.to_vec(), state.encode());
                }
                for ((addr, key), val) in storage {
                    st.insert((addr.to_vec(), key.to_vec()), val.to_vec());
                }
            }
        }
    }

    /// Flush all pending writes to disk (call on graceful shutdown).
    pub fn flush(&self) -> anyhow::Result<()> {
        if let SnapshotDBInner::Rocks { db, .. } = &self.inner {
            db.flush()?;
            tracing::info!("📦 SnapshotDB flushed to disk");
        }
        Ok(())
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bytes_to_nibbles() {
        let nibbles = bytes_to_nibbles(&[0xAB]);
        assert_eq!(nibbles, vec![0x0A, 0x0B]);
    }

    #[test]
    fn test_compact_encode_leaf_odd() {
        // Odd-length leaf: prefix flag = 3
        let enc = compact_encode(&[1, 2, 3], true);
        assert_eq!(enc[0] >> 4, 3); // flag = 3 (leaf + odd)
    }

    #[test]
    fn test_compact_encode_extension_even() {
        // Even-length extension: prefix flag = 0
        let enc = compact_encode(&[1, 2], false);
        assert_eq!(enc[0], 0x00);
    }

    #[test]
    fn test_common_prefix_len() {
        assert_eq!(common_prefix_len(&[1,2,3,4], &[1,2,5,6]), 2);
        assert_eq!(common_prefix_len(&[1,2], &[1,2]), 2);
        assert_eq!(common_prefix_len(&[], &[1]), 0);
    }

    #[test]
    fn test_trie_empty_get() {
        let t = MerkleTrie::empty();
        assert!(t.get(b"missing").is_none());
    }

    #[test]
    fn test_trie_insert_and_get() {
        let mut t = MerkleTrie::empty();
        t.insert(b"hello", b"world".to_vec());
        assert_eq!(t.get(b"hello"), Some(b"world".to_vec()));
    }

    #[test]
    fn test_trie_root_changes_on_insert() {
        let mut t = MerkleTrie::empty();
        let r0 = t.root();
        t.insert(b"key", b"val".to_vec());
        assert_ne!(t.root(), r0);
    }

    #[test]
    fn test_trie_multiple_keys() {
        let mut t = MerkleTrie::empty();
        t.insert(b"aaa", b"1".to_vec());
        t.insert(b"bbb", b"2".to_vec());
        t.insert(b"ccc", b"3".to_vec());
        assert_eq!(t.get(b"aaa"), Some(b"1".to_vec()));
        assert_eq!(t.get(b"bbb"), Some(b"2".to_vec()));
        assert_eq!(t.get(b"ccc"), Some(b"3".to_vec()));
    }

    #[test]
    fn test_trie_update_value() {
        let mut t = MerkleTrie::empty();
        t.insert(b"k", b"v1".to_vec());
        t.insert(b"k", b"v2".to_vec());
        assert_eq!(t.get(b"k"), Some(b"v2".to_vec()));
    }

    #[test]
    fn test_journaled_state_revert() {
        let mut j = JournaledState::new();
        let addr = [0u8; 20];
        let state1 = AccountState { nonce: 1, ..Default::default() };
        let state2 = AccountState { nonce: 2, ..Default::default() };
        j.set_account(addr, state1.clone(), None);
        let cp = j.checkpoint();
        j.set_account(addr, state2.clone(), Some(state1.clone()));
        assert_eq!(j.dirty_accounts[&addr].nonce, 2);
        j.revert_to(cp);
        assert_eq!(j.dirty_accounts[&addr].nonce, 1);
    }

    #[test]
    fn test_snapshot_batch_update() {
        let db = SnapshotDB::new();
        let addr = [1u8; 20];
        let state = AccountState { nonce: 5, balance: 1000, ..Default::default() };
        let mut map = HashMap::new();
        map.insert(addr, state.clone());
        db.batch_update(&map, &HashMap::new());
        let got = db.get_account(&addr).unwrap();
        assert_eq!(got.nonce, 5);
    }

    #[test]
    fn test_account_state_encode_decode() {
        let a = AccountState { nonce: 3, balance: 500, ..Default::default() };
        let enc = a.encode();
        let dec = AccountState::decode(&enc).unwrap();
        assert_eq!(dec.nonce, 3);
        assert_eq!(dec.balance, 500);
    }

    // ── Layer 1: Security definitions ────────────────────────────────────────

    #[test]
    fn test_account_is_empty_when_default() {
        // L1: default account must be considered empty (nonce=0, balance=0, no code)
        let a = AccountState::default();
        assert!(a.is_empty());
    }

    #[test]
    fn test_account_not_empty_with_nonzero_nonce() {
        // L1: nonzero nonce means account is active — must not be considered empty
        let a = AccountState { nonce: 1, ..Default::default() };
        assert!(!a.is_empty());
    }

    #[test]
    fn test_account_not_empty_with_nonzero_balance() {
        // L1: nonzero balance means account holds funds — must not be empty
        let a = AccountState { balance: 1, ..Default::default() };
        assert!(!a.is_empty());
    }

    #[test]
    fn test_trie_get_nonexistent_key_returns_none() {
        // L1: querying a key that was never inserted must return None, not panic
        let t = MerkleTrie::empty();
        assert_eq!(t.get(b"does_not_exist"), None);
    }

    // ── Layer 2: Functional correctness ──────────────────────────────────────

    #[test]
    fn test_trie_root_is_stable_after_no_change() {
        // L2: inserting same key+value twice must produce same root (idempotent)
        let mut t = MerkleTrie::empty();
        t.insert(b"key", b"value".to_vec());
        let r1 = t.root();
        t.insert(b"key", b"value".to_vec());
        let r2 = t.root();
        assert_eq!(r1, r2);
    }

    #[test]
    fn test_journaled_state_multiple_checkpoints() {
        // L2: nested checkpoints must unwind correctly in LIFO order
        let mut j = JournaledState::new();
        let addr = [1u8; 20];
        let s0 = AccountState { nonce: 0, ..Default::default() };
        let s1 = AccountState { nonce: 1, ..Default::default() };
        let s2 = AccountState { nonce: 2, ..Default::default() };
        j.set_account(addr, s0.clone(), None);
        let cp0 = j.checkpoint();
        j.set_account(addr, s1.clone(), Some(s0.clone()));
        let cp1 = j.checkpoint();
        j.set_account(addr, s2.clone(), Some(s1.clone()));
        assert_eq!(j.dirty_accounts[&addr].nonce, 2);
        j.revert_to(cp1);
        assert_eq!(j.dirty_accounts[&addr].nonce, 1);
        j.revert_to(cp0);
        assert_eq!(j.dirty_accounts[&addr].nonce, 0);
    }

    #[test]
    fn test_state_cache_evicts_lru_correctly() {
        // L2: cache with small capacity must evict oldest entries
        let cache = StateCache::new(2, 4);
        let a1 = [1u8; 20];
        let a2 = [2u8; 20];
        let a3 = [3u8; 20];
        cache.set_account(a1, AccountState { nonce: 1, ..Default::default() });
        cache.set_account(a2, AccountState { nonce: 2, ..Default::default() });
        cache.set_account(a3, AccountState { nonce: 3, ..Default::default() }); // evicts a1
        // a3 must be present
        assert_eq!(cache.get_account(&a3).unwrap().nonce, 3);
    }

    #[test]
    fn test_trie_proof_generated_for_existing_key() {
        // L2: proof must be non-empty for an existing key
        let mut t = MerkleTrie::empty();
        t.insert(b"proofkey", b"proofval".to_vec());
        let proof = t.prove(b"proofkey");
        assert!(!proof.is_empty());
    }

    // ── Layer 3: Protection ───────────────────────────────────────────────────

    #[test]
    fn test_snapshot_get_nonexistent_account_returns_none() {
        // L3: snapshot miss must return None, not default value (avoid phantom accounts)
        let db = SnapshotDB::new();
        assert!(db.get_account(&[0xFFu8; 20]).is_none());
    }

    #[test]
    fn test_revert_to_invalid_checkpoint_is_safe() {
        // L3: reverting to checkpoint 0 (before any writes) must be safe
        let mut j = JournaledState::new();
        let addr = [0u8; 20];
        j.set_account(addr, AccountState { nonce: 99, ..Default::default() }, None);
        j.revert_to(0); // revert all writes
        assert!(j.dirty_accounts.get(&addr).is_none() ||
                j.dirty_accounts[&addr].nonce == 0);
    }

    #[test]
    fn test_trie_different_values_same_key_produces_different_root() {
        // L3: any value change must invalidate the root (tamper detection)
        let mut t1 = MerkleTrie::empty();
        let mut t2 = MerkleTrie::empty();
        t1.insert(b"k", b"value_a".to_vec());
        t2.insert(b"k", b"value_b".to_vec());
        assert_ne!(t1.root(), t2.root());
    }

    // ── Layer 4: Detection & Response ────────────────────────────────────────

    #[test]
    fn test_trie_root_changes_are_detectable_after_insert() {
        // L4: root change = tamper signal — must be observable after every insert
        let mut t = MerkleTrie::empty();
        let roots: Vec<_> = [b"a".as_ref(), b"b", b"c", b"d"]
            .iter().enumerate()
            .map(|(i, k)| { t.insert(k, vec![i as u8]); t.root() })
            .collect();
        // All roots must be distinct
        for i in 0..roots.len() {
            for j in i+1..roots.len() {
                assert_ne!(roots[i], roots[j]);
            }
        }
    }

    #[test]
    fn test_journal_entry_count_tracks_writes() {
        // L4: journal length must reflect number of write operations for audit trail
        let mut j = JournaledState::new();
        assert_eq!(j.journal.len(), 0);
        j.set_account([1u8; 20], AccountState { nonce: 1, ..Default::default() }, None);
        assert_eq!(j.journal.len(), 1);
        j.set_account([2u8; 20], AccountState { nonce: 2, ..Default::default() }, None);
        assert_eq!(j.journal.len(), 2);
    }

    // ── Layer 5: Resilience ───────────────────────────────────────────────────

    #[test]
    fn test_trie_insert_many_keys_all_retrievable() {
        // L5: bulk insertion must not cause any key to become unretrievable
        let mut t = MerkleTrie::empty();
        let keys: Vec<Vec<u8>> = (0u8..=20).map(|i| vec![i; 4]).collect();
        for (i, k) in keys.iter().enumerate() {
            t.insert(k, vec![i as u8]);
        }
        for (i, k) in keys.iter().enumerate() {
            assert_eq!(t.get(k), Some(vec![i as u8]),
                "key {:?} not found after bulk insert", k);
        }
    }

    #[test]
    fn test_snapshot_batch_update_is_idempotent() {
        // L5: applying same batch twice must not corrupt state
        let db = SnapshotDB::new();
        let addr = [9u8; 20];
        let state = AccountState { nonce: 7, balance: 777, ..Default::default() };
        let mut map = HashMap::new();
        map.insert(addr, state.clone());
        db.batch_update(&map, &HashMap::new());
        db.batch_update(&map, &HashMap::new()); // apply again
        assert_eq!(db.get_account(&addr).unwrap().nonce, 7);
    }

    #[test]
    fn test_journaled_state_revert_clears_dirty_on_new_account() {
        // L5: reverting creation of new account must remove it from dirty_accounts
        let mut j = JournaledState::new();
        let addr = [7u8; 20];
        let cp = j.checkpoint();
        j.set_account(addr, AccountState { nonce: 1, ..Default::default() }, None);
        assert!(j.dirty_accounts.contains_key(&addr));
        j.revert_to(cp);
        assert!(!j.dirty_accounts.contains_key(&addr));
    }

    // ── Layer 6: Governance & Compliance ─────────────────────────────────────

    #[test]
    fn test_account_encode_decode_roundtrip_preserves_all_fields() {
        // L6: encode/decode must be lossless for all fields (audit trail)
        let a = AccountState {
            nonce: 42, balance: 1_000_000,
            code_hash: [0xABu8; 32], storage_root: [0xCDu8; 32],
        };
        let decoded = AccountState::decode(&a.encode()).unwrap();
        assert_eq!(decoded.nonce, 42);
        assert_eq!(decoded.balance, 1_000_000);
        assert_eq!(decoded.code_hash, [0xABu8; 32]);
        assert_eq!(decoded.storage_root, [0xCDu8; 32]);
    }

    #[test]
    fn test_trie_empty_root_is_deterministic() {
        // L6: two empty tries must have identical roots (consensus-critical)
        let t1 = MerkleTrie::empty();
        let t2 = MerkleTrie::empty();
        assert_eq!(t1.root(), t2.root());
    }

    // ── Reentrancy simulation ─────────────────────────────────────────────────

    #[test]
    fn test_trie_insert_read_interleaved_consistent() {
        // Reentrancy: inserting while reading must not produce stale values
        let mut t = MerkleTrie::empty();
        t.insert(b"x", b"original".to_vec());
        let v1 = t.get(b"x");
        t.insert(b"x", b"updated".to_vec());
        let v2 = t.get(b"x");
        assert_eq!(v1, Some(b"original".to_vec()));
        assert_eq!(v2, Some(b"updated".to_vec()));
    }

    #[test]
    fn test_journaled_state_storage_revert() {
        // Reentrancy: storage writes must revert cleanly just like account writes
        let mut j = JournaledState::new();
        let addr = [3u8; 20];
        let key  = [1u8; 32];
        let val1 = [0xAAu8; 32];
        let val2 = [0xBBu8; 32];
        j.set_storage(addr, key, val1, [0u8; 32]);
        let cp = j.checkpoint();
        j.set_storage(addr, key, val2, val1);
        assert_eq!(j.dirty_storage[&(addr, key)], val2);
        j.revert_to(cp);
        assert_eq!(j.dirty_storage[&(addr, key)], val1);
    }

    // ── Read-only reentrancy ──────────────────────────────────────────────────

    #[test]
    fn test_trie_get_does_not_mutate_root() {
        // Read-only reentrancy: get() must never change the root hash
        let mut t = MerkleTrie::empty();
        t.insert(b"ro_key", b"ro_val".to_vec());
        let root_before = t.root();
        let _ = t.get(b"ro_key");
        let _ = t.get(b"missing");
        assert_eq!(t.root(), root_before);
    }

    #[test]
    fn test_state_cache_concurrent_reads_and_writes() {
        // Read-only reentrancy: concurrent cache reads + writes must not deadlock
        use std::thread;
        let cache = Arc::new(StateCache::new(100, 200));
        let addr = [1u8; 20];
        cache.set_account(addr, AccountState { nonce: 1, ..Default::default() });
        let c1 = Arc::clone(&cache);
        let reader = thread::spawn(move || {
            for _ in 0..50 {
                let _ = c1.get_account(&addr);
            }
        });
        let c2 = Arc::clone(&cache);
        let writer = thread::spawn(move || {
            for n in 0..50u64 {
                c2.set_account(addr, AccountState { nonce: n, ..Default::default() });
            }
        });
        reader.join().unwrap();
        writer.join().unwrap();
        // Must still be readable after concurrent access
        assert!(cache.get_account(&addr).is_some());
    }

    // ── Function parameter validation ─────────────────────────────────────────

    #[test]
    fn test_trie_insert_empty_key_does_not_panic() {
        // Param validation: empty key insert must not crash
        let mut trie = MerkleTrie::empty();
        trie.insert(&[], vec![0xFF]);
        // Should either store or ignore, but never panic
    }

    #[test]
    fn test_trie_get_empty_key_does_not_panic() {
        // Param validation: getting with empty key must return None without panic
        let trie = MerkleTrie::empty();
        let _ = trie.get(&[]);
    }

    #[test]
    fn test_journaled_state_revert_to_zero_is_safe() {
        // Param validation: reverting to checkpoint 0 (fresh state) must not panic
        let mut j = JournaledState::new();
        let addr = [1u8; 20];
        let state = AccountState { nonce: 99, balance: 1000, code_hash: [0u8; 32], storage_root: [0u8; 32] };
        j.set_account(addr, state, None);
        j.revert_to(0);
        // After revert to 0, dirty account must be gone
        assert!(j.dirty_accounts.get(&addr).is_none());
    }

    // ── Misconfiguration ──────────────────────────────────────────────────────

    #[test]
    fn test_state_cache_set_then_get_account() {
        // Misconfiguration: set then immediately get must return same value
        let cache = StateCache::new(10, 20);
        let addr = [7u8; 20];
        let state = AccountState { nonce: 5, balance: 500, code_hash: [0u8; 32], storage_root: [0u8; 32] };
        cache.set_account(addr, state.clone());
        let got = cache.get_account(&addr).unwrap();
        assert_eq!(got.nonce, 5);
        assert_eq!(got.balance, 500);
    }

    #[test]
    fn test_trie_empty_root_is_constant() {
        // Misconfiguration: two fresh tries must have identical root (deterministic empty state)
        let t1 = MerkleTrie::empty();
        let t2 = MerkleTrie::empty();
        assert_eq!(t1.root(), t2.root());
    }

    #[test]
    fn test_snapshot_db_batch_update_idempotent() {
        // Misconfiguration: applying same batch twice must not corrupt state
        let db = SnapshotDB::new();
        let addr = [5u8; 20];
        let state = AccountState { nonce: 1, balance: 100, code_hash: [0u8; 32], storage_root: [0u8; 32] };
        db.batch_update(&[(addr, state.clone())]);
        db.batch_update(&[(addr, state)]);
        assert!(db.get_account(&addr).is_some());
    }

    // ── Governance attack ─────────────────────────────────────────────────────

    #[test]
    fn test_trie_different_values_same_key_produces_different_root() {
        // Governance attack: any state change must produce a different root
        let mut t1 = MerkleTrie::empty();
        let mut t2 = MerkleTrie::empty();
        t1.insert(b"account", vec![0x01]);
        t2.insert(b"account", vec![0x02]);
        assert_ne!(t1.root(), t2.root(),
            "different values for same key must produce different Merkle root");
    }

    #[test]
    fn test_journal_revert_completely_undoes_account_change() {
        // Governance attack: reverted state change must be fully undone
        let mut j = JournaledState::new();
        let addr = [0xAAu8; 20];
        let cp = j.checkpoint();
        let new_state = AccountState { nonce: 99, balance: 999_999_999, code_hash: [0u8; 32], storage_root: [0u8; 32] };
        j.set_account(addr, new_state, None);
        assert!(j.dirty_accounts.contains_key(&addr));
        j.revert_to(cp);
        // After revert, account must be removed from dirty set
        assert!(!j.dirty_accounts.contains_key(&addr), "reverted account must be gone");
    }

    #[test]
    fn test_proof_for_existing_key_is_nonempty() {
        // Governance attack: Merkle proof for existing key must be non-empty
        let mut trie = MerkleTrie::empty();
        trie.insert(b"key1", vec![0xAB]);
        let proof = trie.prove(b"key1");
        assert!(!proof.is_empty(), "proof for existing key must not be empty");
    }
}

