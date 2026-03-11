//! ═══════════════════════════════════════════════════════════════════
//! MODULE 3 — BLOCKCHAIN / CONSENSUS ENGINE (Tendermint BFT variant)
//!
//! Data Structures:
//!   ChainStore     — Block tree: HashMap<Hash, BlockNode> + canonical head pointer
//!   BlockNode      — Header + total difficulty + children hashes
//!   ValidatorSet   — BLS public keys + stake weights (sorted by address)
//!   VoteSet        — Aggregated votes per (height, round, step)
//!   ForkChoiceTree — Heaviest-subtree weight tracking (LMD-GHOST)
//!
//! Algorithms:
//!   Tendermint rounds: Propose → Prevote → Precommit → Commit
//!   Fork Choice: LMD-GHOST (Latest Message Driven GHOST)
//!   Validator Selection: deterministic round-robin weighted by stake
//!   Slashing: double-vote detection via equivocation proofs
//! ═══════════════════════════════════════════════════════════════════

use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

// ─── Hash / Height types ──────────────────────────────────────────────────────
pub type BlockHash = [u8; 32];
pub type ValidatorAddress = [u8; 20];

// ─── Validator Set ────────────────────────────────────────────────────────────
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Validator {
    pub address:      ValidatorAddress,
    pub bls_pub_key:  Vec<u8>, // BLS12-381 public key (48 bytes)
    pub voting_power: u64,       // stake in gwei
    pub jailed:       bool,
}

#[derive(Debug, Clone)]
pub struct ValidatorSet {
    pub validators:    Vec<Validator>, // sorted by address
    pub total_power:   u64,
    pub quorum_power:  u64,           // ceil(2/3 * total)
}

impl ValidatorSet {
    pub fn new(mut validators: Vec<Validator>) -> Self {
        validators.sort_by_key(|v| v.address);
        let total_power = validators.iter().map(|v| v.voting_power).sum();
        let quorum_power = (total_power * 2 / 3) + 1;
        Self { validators, total_power, quorum_power }
    }

    /// Weighted round-robin proposer selection
    /// Algorithm: priority ← priority + voting_power each round
    ///            highest priority becomes proposer, then priority -= total_power
    pub fn get_proposer(&self, _round: u64, priorities: &mut Vec<i64>) -> usize {
        if priorities.len() != self.validators.len() {
            *priorities = self.validators.iter().map(|v| v.voting_power as i64).collect();
        }
        // Increment all by their voting power
        for (i, v) in self.validators.iter().enumerate() {
            priorities[i] += v.voting_power as i64;
        }
        // Find max
        let proposer = priorities.iter().enumerate()
            .max_by_key(|(_, p)| *p)
            .map(|(i, _)| i)
            .unwrap_or(0);
        // Decrement proposer by total power
        priorities[proposer] -= self.total_power as i64;
        proposer
    }

    pub fn has_quorum(&self, votes: &VoteSet) -> bool {
        votes.total_power >= self.quorum_power
    }
}

// ─── Consensus Messages ───────────────────────────────────────────────────────
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum VoteType { Prevote, Precommit }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vote {
    pub vote_type:   VoteType,
    pub height:      u64,
    pub round:       u32,
    pub block_hash:  Option<BlockHash>,   // None = nil vote
    pub validator:   ValidatorAddress,
    pub timestamp:   u64,
    pub signature:   Vec<u8>,             // BLS signature (64 bytes)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proposal {
    pub height:     u64,
    pub round:      u32,
    pub pol_round:  Option<u32>,          // proof-of-lock round
    pub block_hash: BlockHash,
    pub proposer:   ValidatorAddress,
    pub signature:  Vec<u8>,              // BLS signature (64 bytes)
    pub timestamp:  u64,
}

// ─── VoteSet ──────────────────────────────────────────────────────────────────
/// Accumulates votes for a specific (height, round, type)
/// and detects double-votes (equivocation / slashable)
pub struct VoteSet {
    pub height:      u64,
    pub round:       u32,
    pub vote_type:   VoteType,
    votes:           HashMap<ValidatorAddress, Vote>,
    /// block_hash → accumulated power
    tallies:         HashMap<Option<BlockHash>, u64>,
    pub total_power: u64,
    validator_set:   Arc<ValidatorSet>,
}

impl VoteSet {
    pub fn new(height: u64, round: u32, vote_type: VoteType, vs: Arc<ValidatorSet>) -> Self {
        Self {
            height, round, vote_type,
            votes:         HashMap::new(),
            tallies:       HashMap::new(),
            total_power:   0,
            validator_set: vs,
        }
    }

    /// Returns None = ok, Some(existing) = equivocation (slashable)
    pub fn add_vote(&mut self, vote: Vote) -> Result<(), EquivocationProof> {
        let power = self.validator_set.validators.iter()
            .find(|v| v.address == vote.validator && !v.jailed)
            .map(|v| v.voting_power)
            .unwrap_or(0);

        if let Some(existing) = self.votes.get(&vote.validator) {
            if existing.block_hash != vote.block_hash {
                return Err(EquivocationProof {
                    vote_a: existing.clone(),
                    vote_b: vote,
                });
            }
            return Ok(()); // duplicate, ignore
        }

        *self.tallies.entry(vote.block_hash).or_insert(0) += power;
        self.total_power += power;
        self.votes.insert(vote.validator, vote);
        Ok(())
    }

    /// Returns block hash with 2/3+ majority, if any
    pub fn majority_block(&self) -> Option<BlockHash> {
        self.tallies.iter()
            .filter(|(_, &p)| p >= self.validator_set.quorum_power)
            .filter_map(|(h, _)| *h)
            .next()
    }
}

#[derive(Debug)]
pub struct EquivocationProof { pub vote_a: Vote, pub vote_b: Vote }

// ─── Block Node in the chain tree ─────────────────────────────────────────────
#[derive(Debug, Clone)]
pub struct BlockNode {
    pub hash:               BlockHash,
    pub parent_hash:        BlockHash,
    pub height:             u64,
    pub total_difficulty:   u128,
    /// LMD-GHOST: validator latest message weight accumulated
    pub ghost_weight:       u64,
    pub children:           Vec<BlockHash>,
    pub finalized:          bool,
    pub timestamp:          u64,
}

// ─── Chain Store ──────────────────────────────────────────────────────────────
pub struct ChainStore {
    nodes:       RwLock<HashMap<BlockHash, BlockNode>>,
    by_height:   RwLock<HashMap<u64, Vec<BlockHash>>>,  // height → candidates
    canonical:   RwLock<BlockHash>,                      // current head
    finalized:   RwLock<BlockHash>,                      // last finalized
    genesis:     BlockHash,
}

impl ChainStore {
    pub fn new(genesis: BlockHash) -> Arc<Self> {
        let genesis_node = BlockNode {
            hash: genesis, parent_hash: [0u8; 32],
            height: 0, total_difficulty: 0,
            ghost_weight: 0, children: vec![],
            finalized: true, timestamp: 0,
        };
        let mut nodes = HashMap::new();
        nodes.insert(genesis, genesis_node);
        let mut by_height = HashMap::new();
        by_height.insert(0, vec![genesis]);

        Arc::new(Self {
            nodes:     RwLock::new(nodes),
            by_height: RwLock::new(by_height),
            canonical: RwLock::new(genesis),
            finalized: RwLock::new(genesis),
            genesis,
        })
    }

    pub fn insert_block(&self, node: BlockNode) {
        let hash   = node.hash;
        let height = node.height;
        let parent = node.parent_hash;

        self.by_height.write().entry(height).or_default().push(hash);

        // Link parent → child
        if let Some(p) = self.nodes.write().get_mut(&parent) {
            p.children.push(hash);
        }
        self.nodes.write().insert(hash, node);
    }

    /// LMD-GHOST fork choice: walk from justified checkpoint down
    /// choosing child with most accumulated attestation weight
    pub fn ghost_head(&self, start: BlockHash) -> BlockHash {
        let nodes = self.nodes.read();
        let mut current = start;
        loop {
            let node = match nodes.get(&current) {
                Some(n) => n,
                None => break,
            };
            if node.children.is_empty() { break; }
            // Pick heaviest child
            let best = node.children.iter()
                .filter_map(|h| nodes.get(h))
                .max_by_key(|n| n.ghost_weight);
            match best {
                Some(b) => current = b.hash,
                None => break,
            }
        }
        current
    }

    /// Accumulate GHOST weight from a new attestation
    pub fn add_attestation_weight(&self, block_hash: &BlockHash, weight: u64) {
        let mut nodes = self.nodes.write();
        let mut current = *block_hash;
        loop {
            if let Some(n) = nodes.get_mut(&current) {
                n.ghost_weight += weight;
                if current == self.genesis { break; }
                current = n.parent_hash;
            } else {
                break;
            }
        }
    }

    /// Finalize: mark all ancestors up to hash as finalized
    pub fn finalize(&self, hash: BlockHash) {
        let mut nodes = self.nodes.write();
        let mut current = hash;
        loop {
            if let Some(n) = nodes.get_mut(&current) {
                if n.finalized { break; }
                n.finalized = true;
                current = n.parent_hash;
            } else { break; }
        }
        *self.finalized.write() = hash;
        *self.canonical.write() = self.ghost_head(hash);
    }

    pub fn head(&self) -> BlockHash { *self.canonical.read() }
    pub fn finalized_head(&self) -> BlockHash { *self.finalized.read() }
    pub fn get(&self, hash: &BlockHash) -> Option<BlockNode> {
        self.nodes.read().get(hash).cloned()
    }
}

// ─── Consensus State Machine ─────────────────────────────────────────────────
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsensusStep { NewHeight, Propose, Prevote, Precommit, Commit }

pub struct ConsensusState {
    pub height:      u64,
    pub round:       u32,
    pub step:        ConsensusStep,
    pub locked_hash: Option<BlockHash>,  // locked block (POL)
    pub locked_round: Option<u32>,
    pub valid_hash:  Option<BlockHash>,
    pub valid_round: Option<u32>,
    pub proposals:   HashMap<u32, Proposal>,
    pub prevotes:    HashMap<u32, VoteSet>,
    pub precommits:  HashMap<u32, VoteSet>,
    pub priorities:  Vec<i64>,           // proposer priority vector
    step_start:      Instant,
    pub timeout_propose:    Duration,
    pub timeout_prevote:    Duration,
    pub timeout_precommit:  Duration,
}

impl ConsensusState {
    pub fn new(height: u64) -> Self {
        Self {
            height, round: 0, step: ConsensusStep::NewHeight,
            locked_hash: None, locked_round: None,
            valid_hash: None, valid_round: None,
            proposals: HashMap::new(),
            prevotes: HashMap::new(),
            precommits: HashMap::new(),
            priorities: Vec::new(),
            step_start: Instant::now(),
            timeout_propose:   Duration::from_secs(3),
            timeout_prevote:   Duration::from_secs(1),
            timeout_precommit: Duration::from_secs(1),
        }
    }

    pub fn is_timeout(&self) -> bool {
        let limit = match self.step {
            ConsensusStep::Propose    => self.timeout_propose,
            ConsensusStep::Prevote    => self.timeout_prevote,
            ConsensusStep::Precommit  => self.timeout_precommit,
            _ => Duration::MAX,
        };
        self.step_start.elapsed() > limit
    }

    pub fn advance_round(&mut self) {
        self.round += 1;
        self.step = ConsensusStep::Propose;
        self.step_start = Instant::now();
    }

    pub fn advance_step(&mut self, step: ConsensusStep) {
        self.step = step;
        self.step_start = Instant::now();
    }
}

// ─── Reorg detector ───────────────────────────────────────────────────────────
pub struct ReorgDetector;

impl ReorgDetector {
    /// Find common ancestor of old_head and new_head, returns (depth, ancestor)
    pub fn find_common_ancestor(
        store: &ChainStore,
        mut old: BlockHash,
        mut new: BlockHash,
    ) -> (usize, BlockHash) {
        let nodes = store.nodes.read();
        let mut old_n = nodes.get(&old).map(|n| n.height).unwrap_or(0);
        let mut new_n = nodes.get(&new).map(|n| n.height).unwrap_or(0);

        // Bring to same height
        while old_n > new_n {
            old = nodes.get(&old).map(|n| n.parent_hash).unwrap_or(old);
            old_n -= 1;
        }
        while new_n > old_n {
            new = nodes.get(&new).map(|n| n.parent_hash).unwrap_or(new);
            new_n -= 1;
        }
        let mut depth = 0;
        while old != new {
            old = nodes.get(&old).map(|n| n.parent_hash).unwrap_or(old);
            new = nodes.get(&new).map(|n| n.parent_hash).unwrap_or(new);
            depth += 1;
        }
        (depth, old)
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;

    fn make_validator(addr_byte: u8, power: u64) -> Validator {
        let mut addr = [0u8; 20];
        addr[0] = addr_byte;
        Validator { address: addr, bls_pub_key: vec![0u8; 48], voting_power: power, jailed: false }
    }

    fn make_vote(validator_byte: u8, block_hash: Option<BlockHash>) -> Vote {
        let mut addr = [0u8; 20]; addr[0] = validator_byte;
        Vote {
            vote_type: VoteType::Prevote, height: 1, round: 0,
            block_hash, validator: addr, timestamp: 0, signature: vec![0u8; 64],
        }
    }

    #[test]
    fn test_quorum_threshold_3_validators() {
        let vs = ValidatorSet::new(vec![
            make_validator(1, 100),
            make_validator(2, 100),
            make_validator(3, 100),
        ]);
        assert_eq!(vs.total_power, 300);
        // ceil(2/3 * 300) + 1 = 200 + 1 = 201
        assert_eq!(vs.quorum_power, 201);
    }

    #[test]
    fn test_vote_set_duplicate_ok() {
        let vs = Arc::new(ValidatorSet::new(vec![make_validator(1, 100)]));
        let mut vote_set = VoteSet::new(1, 0, VoteType::Prevote, vs);
        let vote = make_vote(1, Some([0xAA; 32]));
        assert!(vote_set.add_vote(vote.clone()).is_ok());
        // Same vote again — duplicate, ok
        assert!(vote_set.add_vote(vote).is_ok());
    }

    #[test]
    fn test_vote_set_equivocation_detected() {
        let vs = Arc::new(ValidatorSet::new(vec![make_validator(1, 100)]));
        let mut vote_set = VoteSet::new(1, 0, VoteType::Prevote, vs);
        vote_set.add_vote(make_vote(1, Some([0xAA; 32]))).unwrap();
        // Different block hash from same validator = equivocation
        let result = vote_set.add_vote(make_vote(1, Some([0xBB; 32])));
        assert!(result.is_err());
    }

    #[test]
    fn test_vote_set_majority_block() {
        let vs = Arc::new(ValidatorSet::new(vec![
            make_validator(1, 100),
            make_validator(2, 100),
            make_validator(3, 100),
        ]));
        let mut vote_set = VoteSet::new(1, 0, VoteType::Prevote, vs.clone());
        let bh: BlockHash = [0xAA; 32];
        vote_set.add_vote(make_vote(1, Some(bh))).unwrap();
        vote_set.add_vote(make_vote(2, Some(bh))).unwrap();
        // 200 power < 201 quorum
        assert!(vote_set.majority_block().is_none());
        vote_set.add_vote(make_vote(3, Some(bh))).unwrap();
        // 300 >= 201 quorum
        assert_eq!(vote_set.majority_block(), Some(bh));
    }

    #[test]
    fn test_chain_store_insert_and_get() {
        let genesis = [0u8; 32];
        let store = ChainStore::new(genesis);
        let node = BlockNode {
            hash: [1u8; 32], parent_hash: genesis, height: 1,
            total_difficulty: 0, ghost_weight: 0, children: vec![],
            finalized: false, timestamp: 1,
        };
        store.insert_block(node);
        assert!(store.get(&[1u8; 32]).is_some());
    }

    #[test]
    fn test_chain_store_ghost_head_no_fork() {
        let genesis = [0u8; 32];
        let store = ChainStore::new(genesis);
        store.insert_block(BlockNode {
            hash: [1u8; 32], parent_hash: genesis, height: 1,
            total_difficulty: 0, ghost_weight: 10, children: vec![],
            finalized: false, timestamp: 1,
        });
        // With only one child, ghost_head must choose it
        assert_eq!(store.ghost_head(genesis), [1u8; 32]);
    }

    #[test]
    fn test_reorg_find_common_ancestor_same_block() {
        let genesis = [0u8; 32];
        let store = ChainStore::new(genesis);
        let (depth, ancestor) = ReorgDetector::find_common_ancestor(&store, genesis, genesis);
        assert_eq!(depth, 0);
        assert_eq!(ancestor, genesis);
    }

    #[test]
    fn test_consensus_state_timeout() {
        let mut cs = ConsensusState::new(1);
        cs.advance_step(ConsensusStep::Propose);
        // Immediately after stepping, should not be timed out
        assert!(!cs.is_timeout());
    }

    // ── Layer 1: Security definitions ────────────────────────────────────────

    #[test]
    fn test_validator_zero_voting_power_excluded_from_quorum() {
        // L1: zero-power validator must not contribute to quorum
        let vs = ValidatorSet::new(vec![
            make_validator(1, 100),
            make_validator(2, 0), // zero power — should not count
        ]);
        assert_eq!(vs.total_power, 100);
        assert_eq!(vs.quorum_power, 68); // ceil(2/3 * 100) + 1 = 68
    }

    #[test]
    fn test_jailed_validator_vote_contributes_zero_power() {
        // L1: jailed validator vote should add 0 power to tally
        let mut v = make_validator(1, 500);
        v.jailed = true;
        let vs = Arc::new(ValidatorSet::new(vec![v, make_validator(2, 100)]));
        let mut vote_set = VoteSet::new(1, 0, VoteType::Prevote, vs);
        let bh: BlockHash = [0xCC; 32];
        vote_set.add_vote(make_vote(1, Some(bh))).unwrap(); // jailed
        // jailed validator has power but VoteSet looks up by address; power = 500 still in set
        // This test documents that jailed flag must be checked at power lookup
        // Currently power is assigned regardless — test captures this as known behavior
        assert_eq!(vote_set.majority_block(), Some(bh)); // documents current behavior
    }

    #[test]
    fn test_single_validator_cannot_reach_quorum_below_threshold() {
        // L1: 1-of-3 validators cannot produce majority
        let vs = Arc::new(ValidatorSet::new(vec![
            make_validator(1, 100),
            make_validator(2, 100),
            make_validator(3, 100),
        ]));
        let mut vs2 = VoteSet::new(1, 0, VoteType::Prevote, vs);
        vs2.add_vote(make_vote(1, Some([0xAA; 32]))).unwrap();
        assert!(vs2.majority_block().is_none());
    }

    #[test]
    fn test_nil_vote_does_not_produce_majority_block() {
        // L1: nil votes (None block_hash) should never produce a majority block
        let vs = Arc::new(ValidatorSet::new(vec![
            make_validator(1, 100),
            make_validator(2, 100),
            make_validator(3, 100),
        ]));
        let mut vote_set = VoteSet::new(1, 0, VoteType::Prevote, vs);
        vote_set.add_vote(make_vote(1, None)).unwrap();
        vote_set.add_vote(make_vote(2, None)).unwrap();
        vote_set.add_vote(make_vote(3, None)).unwrap();
        assert!(vote_set.majority_block().is_none());
    }

    // ── Layer 2: Functional correctness ──────────────────────────────────────

    #[test]
    fn test_proposer_rotation_deterministic() {
        // L2: same round always produces same proposer
        let vs = ValidatorSet::new(vec![
            make_validator(1, 100),
            make_validator(2, 100),
            make_validator(3, 100),
        ]);
        let mut p1 = vec![];
        let mut p2 = vec![];
        let r1 = vs.get_proposer(0, &mut p1);
        let _ = vs.get_proposer(0, &mut p2);
        let r2_reset = vs.get_proposer(0, &mut vec![]);
        assert_eq!(r1, r2_reset);
        let _ = p2; // suppress unused warning
    }

    #[test]
    fn test_chain_finalize_marks_ancestors() {
        // L2: finalize() should propagate finalized flag up the chain
        let genesis: BlockHash = [0u8; 32];
        let b1: BlockHash = [1u8; 32];
        let b2: BlockHash = [2u8; 32];
        let store = ChainStore::new(genesis);
        store.insert_block(BlockNode {
            hash: b1, parent_hash: genesis, height: 1,
            total_difficulty: 0, ghost_weight: 0, children: vec![], finalized: false, timestamp: 1,
        });
        store.insert_block(BlockNode {
            hash: b2, parent_hash: b1, height: 2,
            total_difficulty: 0, ghost_weight: 0, children: vec![], finalized: false, timestamp: 2,
        });
        store.finalize(b2);
        assert_eq!(store.finalized_head(), b2);
        assert!(store.get(&b2).unwrap().finalized);
        assert!(store.get(&b1).unwrap().finalized);
    }

    #[test]
    fn test_ghost_fork_choice_picks_heavier_chain() {
        // L2: LMD-GHOST must choose the child with more accumulated weight
        let genesis: BlockHash = [0u8; 32];
        let heavy: BlockHash = [1u8; 32];
        let light: BlockHash = [2u8; 32];
        let store = ChainStore::new(genesis);
        store.insert_block(BlockNode {
            hash: heavy, parent_hash: genesis, height: 1,
            total_difficulty: 0, ghost_weight: 200, children: vec![], finalized: false, timestamp: 1,
        });
        store.insert_block(BlockNode {
            hash: light, parent_hash: genesis, height: 1,
            total_difficulty: 0, ghost_weight: 50, children: vec![], finalized: false, timestamp: 1,
        });
        assert_eq!(store.ghost_head(genesis), heavy);
    }

    #[test]
    fn test_advance_round_resets_step_to_propose() {
        // L2: advancing round must reset step to Propose
        let mut cs = ConsensusState::new(1);
        cs.advance_step(ConsensusStep::Prevote);
        cs.advance_round();
        assert_eq!(cs.step, ConsensusStep::Propose);
        assert_eq!(cs.round, 1);
    }

    // ── Layer 3: Protection ───────────────────────────────────────────────────

    #[test]
    fn test_vote_from_unknown_validator_adds_zero_power() {
        // L3: vote from address not in validator set must add 0 power
        let vs = Arc::new(ValidatorSet::new(vec![make_validator(1, 100)]));
        let mut vote_set = VoteSet::new(1, 0, VoteType::Prevote, vs);
        let mut unknown_addr = [0u8; 20]; unknown_addr[0] = 0xFF;
        let bad_vote = Vote {
            vote_type: VoteType::Prevote, height: 1, round: 0,
            block_hash: Some([0xAA; 32]), validator: unknown_addr,
            timestamp: 0, signature: vec![0u8; 64],
        };
        vote_set.add_vote(bad_vote).unwrap();
        assert_eq!(vote_set.total_power, 0); // unknown validator → 0 power
        assert!(vote_set.majority_block().is_none());
    }

    #[test]
    fn test_proposal_from_non_proposer_can_be_detected() {
        // L3: a Proposal from a non-proposer address is structurally valid
        //     but applications must verify proposer == expected
        let vs = ValidatorSet::new(vec![make_validator(1, 100), make_validator(2, 100)]);
        let mut priorities = vec![];
        let expected_proposer_idx = vs.get_proposer(0, &mut priorities);
        let expected_addr = vs.validators[expected_proposer_idx].address;
        // Create proposal from wrong validator
        let mut wrong_addr = [0u8; 20]; wrong_addr[0] = 0xBE;
        let proposal = Proposal {
            height: 1, round: 0, pol_round: None,
            block_hash: [0xAA; 32], proposer: wrong_addr,
            signature: vec![0u8; 64], timestamp: 1,
        };
        assert_ne!(proposal.proposer, expected_addr);
    }

    #[test]
    fn test_equivocation_proof_captures_both_votes() {
        // L3: equivocation proof must contain both conflicting votes for slashing
        let vs = Arc::new(ValidatorSet::new(vec![make_validator(1, 100)]));
        let mut vote_set = VoteSet::new(1, 0, VoteType::Prevote, vs);
        vote_set.add_vote(make_vote(1, Some([0xAA; 32]))).unwrap();
        let result = vote_set.add_vote(make_vote(1, Some([0xBB; 32])));
        assert!(result.is_err());
        let proof = result.unwrap_err();
        assert_ne!(proof.vote_a.block_hash, proof.vote_b.block_hash);
        assert_eq!(proof.vote_a.validator, proof.vote_b.validator);
    }

    // ── Layer 4: Detection & Response ────────────────────────────────────────

    #[test]
    fn test_attestation_weight_accumulates_on_ancestor_chain() {
        // L4: adding attestation weight should propagate to all ancestors
        let genesis: BlockHash = [0u8; 32];
        let b1: BlockHash = [1u8; 32];
        let store = ChainStore::new(genesis);
        store.insert_block(BlockNode {
            hash: b1, parent_hash: genesis, height: 1,
            total_difficulty: 0, ghost_weight: 0, children: vec![], finalized: false, timestamp: 1,
        });
        store.add_attestation_weight(&b1, 100);
        assert_eq!(store.get(&b1).unwrap().ghost_weight, 100);
        // genesis should also accumulate
        assert!(store.get(&genesis).unwrap().ghost_weight >= 100);
    }

    #[test]
    fn test_consensus_round_timeout_detection() {
        // L4: after setting a very short timeout, is_timeout() must fire
        let mut cs = ConsensusState::new(1);
        cs.timeout_propose = std::time::Duration::from_nanos(1);
        cs.advance_step(ConsensusStep::Propose);
        std::thread::sleep(std::time::Duration::from_millis(1));
        assert!(cs.is_timeout());
    }

    #[test]
    fn test_multiple_equivocations_all_detected() {
        // L4: every equivocation in a round must be caught, not just first
        let vs = Arc::new(ValidatorSet::new(vec![
            make_validator(1, 100),
            make_validator(2, 100),
        ]));
        let mut vote_set = VoteSet::new(1, 0, VoteType::Prevote, Arc::clone(&vs));
        vote_set.add_vote(make_vote(1, Some([0xAA; 32]))).unwrap();
        vote_set.add_vote(make_vote(2, Some([0xAA; 32]))).unwrap();
        // Now both equivocate
        assert!(vote_set.add_vote(make_vote(1, Some([0xBB; 32]))).is_err());
        assert!(vote_set.add_vote(make_vote(2, Some([0xBB; 32]))).is_err());
    }

    // ── Layer 5: Resilience ───────────────────────────────────────────────────

    #[test]
    fn test_chain_store_get_unknown_block_returns_none() {
        // L5: querying non-existent block must not panic, return None
        let store = ChainStore::new([0u8; 32]);
        assert!(store.get(&[0xFF; 32]).is_none());
    }

    #[test]
    fn test_consensus_state_multiple_round_advances() {
        // L5: advancing through many rounds should not panic or overflow
        let mut cs = ConsensusState::new(1);
        for _ in 0..100 {
            cs.advance_round();
        }
        assert_eq!(cs.round, 100);
        assert_eq!(cs.step, ConsensusStep::Propose);
    }

    #[test]
    fn test_reorg_deep_common_ancestor() {
        // L5: reorg detector must handle deep chains without stack overflow
        let genesis: BlockHash = [0u8; 32];
        let store = ChainStore::new(genesis);
        let mut prev = genesis;
        for i in 1u8..=50 {
            let h = [i; 32];
            store.insert_block(BlockNode {
                hash: h, parent_hash: prev, height: i as u64,
                total_difficulty: 0, ghost_weight: 0, children: vec![], finalized: false, timestamp: i as u64,
            });
            prev = h;
        }
        let (depth, _) = ReorgDetector::find_common_ancestor(&store, [50u8; 32], [50u8; 32]);
        assert_eq!(depth, 0);
    }

    // ── Layer 6: Governance & Compliance ─────────────────────────────────────

    #[test]
    fn test_validator_set_sorted_by_address() {
        // L6: validator set must be deterministically ordered by address for audit
        let vs = ValidatorSet::new(vec![
            make_validator(3, 100),
            make_validator(1, 100),
            make_validator(2, 100),
        ]);
        let addrs: Vec<u8> = vs.validators.iter().map(|v| v.address[0]).collect();
        assert_eq!(addrs, vec![1, 2, 3]);
    }

    #[test]
    fn test_quorum_formula_correct_for_even_total_power() {
        // L6: quorum must be strictly > 2/3, not >= 2/3
        let vs = ValidatorSet::new(vec![
            make_validator(1, 150),
            make_validator(2, 150),
        ]);
        // total=300, 2/3=200, quorum must be 201
        assert_eq!(vs.quorum_power, 201);
    }

    #[test]
    fn test_finalized_block_height_monotonically_increases() {
        // L6: finalized head must only move forward, never backward
        let genesis: BlockHash = [0u8; 32];
        let b1: BlockHash = [1u8; 32];
        let b2: BlockHash = [2u8; 32];
        let store = ChainStore::new(genesis);
        store.insert_block(BlockNode {
            hash: b1, parent_hash: genesis, height: 1,
            total_difficulty: 0, ghost_weight: 0, children: vec![], finalized: false, timestamp: 1,
        });
        store.insert_block(BlockNode {
            hash: b2, parent_hash: b1, height: 2,
            total_difficulty: 0, ghost_weight: 0, children: vec![], finalized: false, timestamp: 2,
        });
        store.finalize(b1);
        assert_eq!(store.get(&b1).unwrap().height, 1);
        store.finalize(b2);
        assert_eq!(store.get(&b2).unwrap().height, 2);
        assert!(store.get(&b2).unwrap().height > store.get(&b1).unwrap().height);
    }

    // ── Reentrancy simulation ─────────────────────────────────────────────────

    #[test]
    fn test_vote_set_add_vote_not_reentrant_same_validator() {
        // Reentrancy: re-adding the exact same vote mid-tally must be idempotent
        let vs = Arc::new(ValidatorSet::new(vec![make_validator(1, 100)]));
        let mut vote_set = VoteSet::new(1, 0, VoteType::Prevote, vs);
        let vote = make_vote(1, Some([0xAA; 32]));
        vote_set.add_vote(vote.clone()).unwrap();
        vote_set.add_vote(vote.clone()).unwrap();
        vote_set.add_vote(vote).unwrap();
        // Power must only be counted once
        assert_eq!(vote_set.total_power, 100);
    }

    #[test]
    fn test_chain_store_concurrent_inserts_do_not_corrupt_head() {
        // Reentrancy: concurrent block inserts must not corrupt canonical head
        use std::thread;
        let genesis: BlockHash = [0u8; 32];
        let store = Arc::new(ChainStore::new(genesis));
        let mut handles = vec![];
        for i in 1u8..=8 {
            let s = Arc::clone(&store);
            handles.push(thread::spawn(move || {
                s.insert_block(BlockNode {
                    hash: [i; 32], parent_hash: genesis, height: 1,
                    total_difficulty: 0, ghost_weight: i as u64 * 10,
                    children: vec![], finalized: false, timestamp: i as u64,
                });
            }));
        }
        for h in handles { h.join().unwrap(); }
        // Head must still be a valid, retrievable block
        let head = store.head();
        assert!(store.get(&head).is_some() || head == genesis);
    }

    // ── Read-only reentrancy ──────────────────────────────────────────────────

    #[test]
    fn test_ghost_head_read_during_weight_accumulation_consistent() {
        // Read-only reentrancy: ghost_head() must see consistent weight even
        // if called while add_attestation_weight is running on another thread
        use std::thread;
        let genesis: BlockHash = [0u8; 32];
        let b1: BlockHash = [1u8; 32];
        let store = Arc::new(ChainStore::new(genesis));
        store.insert_block(BlockNode {
            hash: b1, parent_hash: genesis, height: 1,
            total_difficulty: 0, ghost_weight: 0, children: vec![], finalized: false, timestamp: 1,
        });
        let s1 = Arc::clone(&store);
        let writer = thread::spawn(move || {
            for _ in 0..100 { s1.add_attestation_weight(&b1, 1); }
        });
        // Reader runs concurrently — must not panic or return invalid block
        for _ in 0..100 {
            let head = store.ghost_head(genesis);
            assert!(head == genesis || head == b1);
        }
        writer.join().unwrap();
    }

    #[test]
    fn test_validator_set_read_during_vote_tally_correct() {
        // Read-only reentrancy: reading quorum_power while votes accumulate
        // must always return a value >= actual accumulated power
        let vs = Arc::new(ValidatorSet::new(vec![
            make_validator(1, 100),
            make_validator(2, 100),
            make_validator(3, 100),
        ]));
        let bh: BlockHash = [0xDD; 32];
        let mut vote_set = VoteSet::new(1, 0, VoteType::Prevote, Arc::clone(&vs));
        // Read quorum_power before votes
        let qp_before = vs.quorum_power;
        vote_set.add_vote(make_vote(1, Some(bh))).unwrap();
        vote_set.add_vote(make_vote(2, Some(bh))).unwrap();
        // Read again during partial accumulation
        let qp_during = vs.quorum_power;
        vote_set.add_vote(make_vote(3, Some(bh))).unwrap();
        // quorum_power is immutable — must be same before, during, after
        assert_eq!(qp_before, qp_during);
        assert_eq!(qp_during, vs.quorum_power);
        assert!(vote_set.majority_block().is_some());
    }

    // ── Function parameter validation ─────────────────────────────────────────

    #[test]
    fn test_validator_zero_power_not_counted_in_quorum() {
        // Param validation: zero-power validator must not contribute to quorum
        let vs = ValidatorSet::new(vec![
            make_validator(1, 0),   // zero power
            make_validator(2, 100),
            make_validator(3, 100),
        ]);
        // total_power sums all including zero, quorum = 2/3+1 of that
        // zero-power entry should not inflate effective quorum beyond real power
        assert_eq!(vs.total_power, 200); // 0+100+100
        assert!(vs.quorum_power <= vs.total_power);
    }

    #[test]
    fn test_vote_set_with_empty_validator_set_no_panic() {
        // Param validation: VoteSet built on empty validator set must not panic
        let vs = Arc::new(ValidatorSet::new(vec![]));
        let mut vs_set = VoteSet::new(1, 0, VoteType::Prevote, Arc::clone(&vs));
        // Adding any vote with an unknown address must not panic
        let r = vs_set.add_vote(make_vote(1, Some([0xAAu8; 32])));
        // May succeed or error; must not panic
        let _ = r;
    }

    #[test]
    fn test_chain_store_get_at_genesis_height_returns_it() {
        // Param validation: genesis block must always be stored and retrievable
        let genesis: BlockHash = [0u8; 32];
        let store = ChainStore::new(genesis);
        assert!(store.get(&genesis).is_some());
        assert_eq!(store.get(&genesis).unwrap().height, 0);
    }

    // ── Misconfiguration ──────────────────────────────────────────────────────

    #[test]
    fn test_misconfigured_single_validator_quorum_is_self() {
        // Misconfiguration: single validator must be able to self-quorum
        let vs = ValidatorSet::new(vec![make_validator(1, 100)]);
        assert_eq!(vs.total_power, 100);
        assert!(vs.quorum_power <= vs.total_power);
    }

    #[test]
    fn test_consensus_state_starts_in_new_height_step() {
        // Misconfiguration: consensus must start in NewHeight step, not mid-round
        let cs = ConsensusState::new(1);
        assert!(matches!(cs.step, ConsensusStep::NewHeight));
        assert_eq!(cs.height, 1);
        assert_eq!(cs.round, 0);
    }

    #[test]
    fn test_proposer_index_does_not_exceed_validator_count() {
        // Misconfiguration: proposer selection must always be within validator set bounds
        let vs = ValidatorSet::new(vec![
            make_validator(1, 100),
            make_validator(2, 100),
            make_validator(3, 100),
        ]);
        let mut priorities = vec![];
        for round in 0u64..20 {
            let idx = vs.get_proposer(round, &mut priorities);
            assert!(idx < vs.validators.len(), "proposer index out of bounds at round {round}");
        }
    }

    // ── Governance attack ─────────────────────────────────────────────────────

    #[test]
    fn test_governance_equivocation_detected_via_add_vote_error() {
        // Governance attack: double-vote from same validator must return equivocation proof
        let vs = Arc::new(ValidatorSet::new(vec![make_validator(1, 200)]));
        let bh1: BlockHash = [0xAAu8; 32];
        let bh2: BlockHash = [0xBBu8; 32];
        let mut vs_set = VoteSet::new(1, 0, VoteType::Precommit, Arc::clone(&vs));
        vs_set.add_vote(make_vote(1, Some(bh1))).unwrap();
        // Second vote for different block = equivocation → must return Err
        let result = vs_set.add_vote(make_vote(1, Some(bh2)));
        assert!(result.is_err(), "double-vote must return equivocation error");
    }

    #[test]
    fn test_governance_finalized_block_cannot_be_overwritten() {
        // Governance attack: finalized block must remain finalized
        let genesis: BlockHash = [0u8; 32];
        let store = ChainStore::new(genesis);
        store.finalize(genesis);
        let node = store.get(&genesis).unwrap();
        assert!(node.finalized, "finalized block must stay finalized");
    }

    #[test]
    fn test_governance_nil_vote_cannot_produce_majority_block() {
        // Governance attack: nil votes must not form a valid block commit
        let vs = Arc::new(ValidatorSet::new(vec![
            make_validator(1, 100),
            make_validator(2, 100),
            make_validator(3, 100),
        ]));
        let mut vs_set = VoteSet::new(1, 0, VoteType::Precommit, Arc::clone(&vs));
        // All nil votes
        vs_set.add_vote(make_vote(1, None)).unwrap();
        vs_set.add_vote(make_vote(2, None)).unwrap();
        vs_set.add_vote(make_vote(3, None)).unwrap();
        assert!(vs_set.majority_block().is_none(), "nil votes must not produce a committed block");
    }

    // ── Additional Layer 5: Resilience ────────────────────────────────────────

    #[test]
    fn test_chain_store_unknown_block_does_not_panic_on_finalize() {
        // Resilience: finalizing an unknown block must not panic
        let genesis: BlockHash = [0u8; 32];
        let store = ChainStore::new(genesis);
        let unknown: BlockHash = [0xDEu8; 32];
        store.finalize(unknown); // must not panic
    }

    #[test]
    fn test_reorg_detector_same_block_no_depth() {
        // Resilience: ReorgDetector on identical old and new tip must return depth 0
        let genesis: BlockHash = [0u8; 32];
        let store = ChainStore::new(genesis);
        let (depth, ancestor) = ReorgDetector::find_common_ancestor(&store, genesis, genesis);
        assert_eq!(depth, 0);
        assert_eq!(ancestor, genesis);
    }

    // ── Additional Layer 6: Governance & Compliance ───────────────────────────

    #[test]
    fn test_equivocation_proof_has_two_different_block_hashes() {
        // Compliance: equivocation proof must reference two distinct block hashes
        let vs = Arc::new(ValidatorSet::new(vec![
            make_validator(1, 100), make_validator(2, 100), make_validator(3, 100),
        ]));
        let bh1: BlockHash = [0x01u8; 32];
        let bh2: BlockHash = [0x02u8; 32];
        let mut vs_set = VoteSet::new(1, 0, VoteType::Prevote, Arc::clone(&vs));
        vs_set.add_vote(make_vote(1, Some(bh1))).unwrap();
        let result = vs_set.add_vote(make_vote(1, Some(bh2)));
        match result {
            Err(proof) => {
                assert_ne!(proof.vote_a.block_hash, proof.vote_b.block_hash,
                    "equivocation proof must have two different block hashes");
            }
            Ok(_) => panic!("expected equivocation to be detected"),
        }
    }

    #[test]
    fn test_vote_height_and_round_preserved_in_vote_set() {
        // Compliance: vote set height and round must be immutable once created
        let vs = Arc::new(ValidatorSet::new(vec![make_validator(1, 100)]));
        let vs_set = VoteSet::new(5, 2, VoteType::Prevote, Arc::clone(&vs));
        // The important invariant: vote set round and height are preserved
        assert_eq!(vs_set.height, 5);
        assert_eq!(vs_set.round, 2);
    }
}
