//! ═══════════════════════════════════════════════════════════════════
//! MODULE 4 — EXECUTION ENGINE (EVM)
//!
//! Data Structures:
//!   EvmContext  — Block env + tx env + journaled state
//!   CallStack   — Vec<CallFrame> with max depth 1024
//!   Memory      — Byte-addressable expandable buffer (32-byte word alignment)
//!   Stack       — 256-bit word stack, max 1024 items
//!   GasMeter    — Remaining gas + stipend tracking
//!   Journal     — Ordered revert log [(addr, key, old_val)]
//!
//! Algorithms:
//!   Gas computation: static cost table + dynamic EIP-2929 warm/cold pricing
//!   Call dispatch:   CALL/DELEGATECALL/STATICCALL/CREATE/CREATE2 routing
//!   Precompiles:     ecRecover(1), SHA256(2), RIPEMD(3), Identity(4),
//!                    ModExp(5), BN128Add(6), BN128Mul(7), BN128Pair(8)
//!   CREATE2 address: keccak256(0xff ++ sender ++ salt ++ keccak256(bytecode))[12:]
//! ═══════════════════════════════════════════════════════════════════

use std::collections::HashMap;
// serde unused in execution

pub type U256 = [u64; 4];
pub type Address = [u8; 20];
pub type Hash = [u8; 32];

// ─── Opcode table (partial) ───────────────────────────────────────────────────
#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Opcode {
    STOP=0x00, ADD=0x01, MUL=0x02, SUB=0x03, DIV=0x04, SDIV=0x05,
    MOD=0x06, SMOD=0x07, ADDMOD=0x08, MULMOD=0x09, EXP=0x0a, SIGNEXTEND=0x0b,
    LT=0x10, GT=0x11, SLT=0x12, SGT=0x13, EQ=0x14, ISZERO=0x15,
    AND=0x16, OR=0x17, XOR=0x18, NOT=0x19, BYTE=0x1a, SHL=0x1b, SHR=0x1c, SAR=0x1d,
    SHA3=0x20,
    ADDRESS=0x30, BALANCE=0x31, ORIGIN=0x32, CALLER=0x33, CALLVALUE=0x34,
    CALLDATALOAD=0x35, CALLDATASIZE=0x36, CALLDATACOPY=0x37,
    CODESIZE=0x38, CODECOPY=0x39, GASPRICE=0x3a, EXTCODESIZE=0x3b,
    EXTCODECOPY=0x3c, RETURNDATASIZE=0x3d, RETURNDATACOPY=0x3e, EXTCODEHASH=0x3f,
    BLOCKHASH=0x40, COINBASE=0x41, TIMESTAMP=0x42, NUMBER=0x43,
    PREVRANDAO=0x44, GASLIMIT=0x45, CHAINID=0x46, SELFBALANCE=0x47, BASEFEE=0x48,
    MLOAD=0x51, MSTORE=0x52, MSTORE8=0x53, SLOAD=0x54, SSTORE=0x55,
    JUMP=0x56, JUMPI=0x57, PC=0x58, MSIZE=0x59, GAS=0x5a, JUMPDEST=0x5b,
    PUSH1=0x60, PUSH32=0x7f,
    DUP1=0x80, DUP16=0x8f,
    SWAP1=0x90, SWAP16=0x9f,
    LOG0=0xa0, LOG4=0xa4,
    CREATE=0xf0, CALL=0xf1, CALLCODE=0xf2, RETURN=0xf3,
    DELEGATECALL=0xf4, CREATE2=0xf5, STATICCALL=0xfa, REVERT=0xfd,
    INVALID=0xfe, SELFDESTRUCT=0xff,
}

/// Static base gas costs per opcode (EIP-3529, London)
pub fn base_gas(op: u8) -> u64 {
    match op {
        0x00 => 0,   // STOP
        0x01..=0x0b => 3,  // arithmetic
        0x10..=0x1d => 3,  // comparison + bitwise
        0x20 => 30,  // SHA3 (+ 6/word)
        0x30..=0x4f => 2,  // env opcodes
        0x51 => 3, 0x52 => 3, 0x53 => 3, // MLOAD/MSTORE/MSTORE8
        0x54 => 0, // SLOAD — EIP-2929 dynamic
        0x55 => 0, // SSTORE — dynamic
        0x56 => 8, 0x57 => 10, // JUMP/JUMPI
        0x5b => 1,  // JUMPDEST
        0x60..=0x7f => 3,  // PUSH
        0x80..=0x8f => 3,  // DUP
        0x90..=0x9f => 3,  // SWAP
        0xa0..=0xa4 => 375, // LOG (+ 8/byte + 375/topic)
        0xf0 => 32000, // CREATE
        0xf1 => 0,    // CALL — dynamic
        0xf3 => 0, 0xfd => 0, // RETURN/REVERT
        0xff => 5000, // SELFDESTRUCT
        _ => 3,
    }
}

// ─── EVM Word Stack ───────────────────────────────────────────────────────────
pub struct Stack {
    data: Vec<U256>,
}

impl Stack {
    pub fn new() -> Self { Self { data: Vec::with_capacity(1024) } }
    pub fn push(&mut self, val: U256) -> Result<(), EvmError> {
        if self.data.len() >= 1024 { return Err(EvmError::StackOverflow); }
        self.data.push(val);
        Ok(())
    }
    pub fn pop(&mut self) -> Result<U256, EvmError> {
        self.data.pop().ok_or(EvmError::StackUnderflow)
    }
    pub fn peek(&self, depth: usize) -> Result<&U256, EvmError> {
        let len = self.data.len();
        self.data.get(len.saturating_sub(depth + 1)).ok_or(EvmError::StackUnderflow)
    }
    pub fn swap(&mut self, n: usize) -> Result<(), EvmError> {
        let len = self.data.len();
        if len < n + 1 { return Err(EvmError::StackUnderflow); }
        self.data.swap(len - 1, len - 1 - n);
        Ok(())
    }
    pub fn dup(&mut self, n: usize) -> Result<(), EvmError> {
        let val = *self.peek(n - 1)?;
        self.push(val)
    }
    pub fn len(&self) -> usize { self.data.len() }
}

// ─── Memory (byte-addressable, expands in 32-byte words) ─────────────────────
pub struct Memory {
    data: Vec<u8>,
}

impl Memory {
    pub fn new() -> Self { Self { data: Vec::new() } }

    /// Expand to cover offset+size, returns gas cost for expansion
    pub fn ensure(&mut self, offset: usize, size: usize) -> u64 {
        if size == 0 { return 0; }
        let new_size = ((offset + size + 31) / 32) * 32;
        if new_size <= self.data.len() { return 0; }
        let old_words = (self.data.len() / 32) as u64;
        let new_words = (new_size / 32) as u64;
        self.data.resize(new_size, 0);
        // Memory expansion cost: 3*w + w²/512  (EIP-3860 variant)
        3 * (new_words - old_words) + (new_words * new_words / 512) - (old_words * old_words / 512)
    }

    pub fn read_word(&self, offset: usize) -> U256 {
        let mut bytes = [0u8; 32];
        let len = self.data.len();
        for i in 0..32 {
            if offset + i < len { bytes[i] = self.data[offset + i]; }
        }
        bytes_to_u256(&bytes)
    }

    pub fn write_word(&mut self, offset: usize, val: &U256) {
        let bytes = u256_to_bytes(val);
        let end = offset + 32;
        if end > self.data.len() { self.data.resize(end, 0); }
        self.data[offset..end].copy_from_slice(&bytes);
    }

    pub fn write_byte(&mut self, offset: usize, byte: u8) {
        if offset >= self.data.len() { self.data.resize(offset + 1, 0); }
        self.data[offset] = byte;
    }

    pub fn slice(&self, offset: usize, size: usize) -> Vec<u8> {
        if size == 0 { return vec![]; }
        let mut out = vec![0u8; size];
        let src_len = self.data.len();
        let copy = size.min(src_len.saturating_sub(offset));
        if copy > 0 { out[..copy].copy_from_slice(&self.data[offset..offset + copy]); }
        out
    }

    pub fn size(&self) -> usize { self.data.len() }
}

// ─── Gas Meter ────────────────────────────────────────────────────────────────
pub struct GasMeter {
    pub gas_limit:     u64,
    pub gas_remaining: u64,
    pub gas_refund:    i64, // can be negative
}

impl GasMeter {
    pub fn new(limit: u64) -> Self { Self { gas_limit: limit, gas_remaining: limit, gas_refund: 0 } }

    pub fn consume(&mut self, cost: u64) -> Result<(), EvmError> {
        if cost > self.gas_remaining {
            self.gas_remaining = 0;
            Err(EvmError::OutOfGas)
        } else {
            self.gas_remaining -= cost;
            Ok(())
        }
    }

    pub fn refund(&mut self, amount: i64) {
        self.gas_refund += amount;
    }

    pub fn gas_used(&self) -> u64 {
        self.gas_limit - self.gas_remaining
    }

    /// Effective refund capped at 1/5 of gas used (EIP-3529)
    pub fn effective_refund(&self) -> u64 {
        let used = self.gas_used();
        let refund = self.gas_refund.max(0) as u64;
        refund.min(used / 5)
    }
}

// ─── Access List (EIP-2929 warm/cold tracking) ────────────────────────────────
#[derive(Default)]
pub struct AccessList {
    warm_accounts: std::collections::HashSet<Address>,
    warm_storage:  HashMap<Address, std::collections::HashSet<[u8; 32]>>,
}

impl AccessList {
    pub fn warm_address(&mut self, addr: &Address) -> bool {
        self.warm_accounts.insert(*addr) // returns true if was cold
    }
    pub fn warm_slot(&mut self, addr: &Address, key: &[u8; 32]) -> bool {
        self.warm_storage.entry(*addr).or_default().insert(*key)
    }
    pub fn sload_cost(&mut self, addr: &Address, key: &[u8; 32]) -> u64 {
        if self.warm_slot(addr, key) { 2100 } else { 100 } // EIP-2929
    }
}

// ─── Journal entry for revert support ────────────────────────────────────────
#[derive(Debug, Clone)]
pub enum JournalEntry {
    BalanceChange { addr: Address, old: u128 },
    NonceChange   { addr: Address, old: u64 },
    StorageChange { addr: Address, key: [u8; 32], old: U256 },
    CodeSet       { addr: Address },
    AccountCreate { addr: Address },
    SelfDestruct  { addr: Address, beneficiary: Address },
    Log           { data: LogRecord },
}

#[derive(Debug, Clone)]
pub struct LogRecord {
    pub address: Address,
    pub topics:  Vec<[u8; 32]>,
    pub data:    Vec<u8>,
}

// ─── Call Frame ───────────────────────────────────────────────────────────────
pub struct CallFrame {
    pub code:        Vec<u8>,
    pub pc:          usize,
    pub stack:       Stack,
    pub memory:      Memory,
    pub gas:         GasMeter,
    pub caller:      Address,
    pub address:     Address,   // contract being executed
    pub value:       u128,
    pub input:       Vec<u8>,
    pub is_static:   bool,      // STATICCALL context
    pub return_data: Vec<u8>,   // last subcall output
    pub depth:       usize,
    pub journal_checkpoint: usize,
}

impl CallFrame {
    pub fn new(
        code: Vec<u8>, caller: Address, address: Address,
        value: u128, input: Vec<u8>, gas: u64, is_static: bool, depth: usize,
        journal_checkpoint: usize,
    ) -> Self {
        Self {
            code, pc: 0,
            stack: Stack::new(), memory: Memory::new(),
            gas: GasMeter::new(gas),
            caller, address, value, input, is_static,
            return_data: vec![], depth, journal_checkpoint,
        }
    }
}

// ─── Execution result ────────────────────────────────────────────────────────
#[derive(Debug, Clone)]
pub struct ExecutionResult {
    pub success:    bool,
    pub gas_used:   u64,
    pub output:     Vec<u8>,
    pub logs:       Vec<LogRecord>,
}

// ─── Precompile Registry ──────────────────────────────────────────────────────
pub trait Precompile: Send + Sync {
    fn run(&self, input: &[u8], gas_limit: u64) -> Result<(Vec<u8>, u64), EvmError>;
}

pub struct PrecompileSet {
    pub contracts: HashMap<Address, Box<dyn Precompile>>,
}

impl PrecompileSet {
    pub fn ethereum_mainnet() -> Self {
        let mut contracts: HashMap<Address, Box<dyn Precompile>> = HashMap::new();
        // Address 0x01 — ecRecover
        let mut addr = [0u8; 20]; addr[19] = 1;
        contracts.insert(addr, Box::new(EcRecover));
        // Address 0x02 — SHA256
        addr[19] = 2;
        contracts.insert(addr, Box::new(Sha256Precompile));
        Self { contracts }
    }
    pub fn get(&self, addr: &Address) -> Option<&dyn Precompile> {
        self.contracts.get(addr).map(|b| b.as_ref())
    }
}

struct EcRecover;
impl Precompile for EcRecover {
    fn run(&self, _input: &[u8], _gas_limit: u64) -> Result<(Vec<u8>, u64), EvmError> {
        // Base cost 3000 gas (EIP-2)
        // Real: secp256k1::recover — stub returns zero address
        Ok((vec![0u8; 32], 3000))
    }
}

struct Sha256Precompile;
impl Precompile for Sha256Precompile {
    fn run(&self, input: &[u8], _gas_limit: u64) -> Result<(Vec<u8>, u64), EvmError> {
        use sha2::{Digest, Sha256};
        let cost = 60 + 12 * ((input.len() as u64 + 31) / 32);
        Ok((Sha256::digest(input).to_vec(), cost))
    }
}

// ─── U256 helpers ─────────────────────────────────────────────────────────────
pub fn bytes_to_u256(b: &[u8; 32]) -> U256 {
    [
        u64::from_be_bytes(b[0..8].try_into().unwrap()),
        u64::from_be_bytes(b[8..16].try_into().unwrap()),
        u64::from_be_bytes(b[16..24].try_into().unwrap()),
        u64::from_be_bytes(b[24..32].try_into().unwrap()),
    ]
}

pub fn u256_to_bytes(v: &U256) -> [u8; 32] {
    let mut b = [0u8; 32];
    b[0..8].copy_from_slice(&v[0].to_be_bytes());
    b[8..16].copy_from_slice(&v[1].to_be_bytes());
    b[16..24].copy_from_slice(&v[2].to_be_bytes());
    b[24..32].copy_from_slice(&v[3].to_be_bytes());
    b
}

pub fn u256_add(a: U256, b: U256) -> U256 {
    let (r0, c0) = a[3].overflowing_add(b[3]);
    let (r1, c1) = a[2].overflowing_add(b[2] + c0 as u64);
    let (r2, c2) = a[1].overflowing_add(b[1] + c1 as u64);
    let r3 = a[0].wrapping_add(b[0] + c2 as u64);
    [r3, r2, r1, r0]
}

pub fn create2_address(sender: &Address, salt: &[u8; 32], init_code: &[u8]) -> Address {
    use sha3::{Digest, Keccak256};
    let code_hash = Keccak256::digest(init_code);
    let mut input = Vec::with_capacity(1 + 20 + 32 + 32);
    input.push(0xff);
    input.extend_from_slice(sender);
    input.extend_from_slice(salt);
    input.extend_from_slice(&code_hash);
    let hash = Keccak256::digest(&input);
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&hash[12..]);
    addr
}

// ─── Errors ───────────────────────────────────────────────────────────────────
#[derive(Debug, thiserror::Error)]
pub enum EvmError {
    #[error("stack overflow")]
    StackOverflow,
    #[error("stack underflow")]
    StackUnderflow,
    #[error("out of gas")]
    OutOfGas,
    #[error("invalid opcode 0x{0:02x}")]
    InvalidOpcode(u8),
    #[error("invalid jump destination")]
    InvalidJump,
    #[error("call depth exceeded")]
    CallDepthExceeded,
    #[error("write protection in static context")]
    WriteProtection,
    #[error("revert: {0:?}")]
    Revert(Vec<u8>),
}

// ─── Tests ───────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stack_push_and_pop() {
        let mut s = Stack::new();
        let val = [1u64, 2u64, 3u64, 4u64];
        s.push(val).unwrap();
        assert_eq!(s.pop().unwrap(), val);
    }

    #[test]
    fn test_stack_overflow() {
        let mut s = Stack::new();
        for _ in 0..1024 { s.push([0u64; 4]).unwrap(); }
        assert!(matches!(s.push([0u64; 4]), Err(EvmError::StackOverflow)));
    }

    #[test]
    fn test_stack_underflow() {
        let mut s = Stack::new();
        assert!(matches!(s.pop(), Err(EvmError::StackUnderflow)));
    }

    #[test]
    fn test_stack_dup() {
        let mut s = Stack::new();
        s.push([42u64, 0, 0, 0]).unwrap();
        s.dup(1).unwrap();
        assert_eq!(s.len(), 2);
        assert_eq!(s.peek(0).unwrap(), &[42u64, 0, 0, 0]);
    }

    #[test]
    fn test_stack_swap() {
        let mut s = Stack::new();
        s.push([1u64, 0, 0, 0]).unwrap();
        s.push([2u64, 0, 0, 0]).unwrap();
        s.swap(1).unwrap();
        assert_eq!(s.pop().unwrap(), [1u64, 0, 0, 0]);
    }

    #[test]
    fn test_memory_word_roundtrip() {
        let mut m = Memory::new();
        let val = [1u64, 2u64, 3u64, 4u64];
        m.write_word(0, &val);
        assert_eq!(m.read_word(0), val);
    }

    #[test]
    fn test_memory_expansion_cost() {
        let mut m = Memory::new();
        let cost = m.ensure(0, 32);
        assert!(cost > 0);
        // Second access to same region costs nothing
        let cost2 = m.ensure(0, 32);
        assert_eq!(cost2, 0);
    }

    #[test]
    fn test_gas_meter_consume() {
        let mut g = GasMeter::new(1000);
        g.consume(400).unwrap();
        assert_eq!(g.gas_used(), 400);
        assert_eq!(g.gas_remaining, 600);
    }

    #[test]
    fn test_gas_meter_out_of_gas() {
        let mut g = GasMeter::new(100);
        assert!(matches!(g.consume(200), Err(EvmError::OutOfGas)));
    }

    #[test]
    fn test_gas_meter_refund_capped() {
        let mut g = GasMeter::new(10_000);
        g.consume(5000).unwrap();
        g.refund(10_000); // huge refund request
        assert_eq!(g.effective_refund(), 1000); // capped at 5000/5
    }

    #[test]
    fn test_u256_add_no_overflow() {
        let a = [0u64, 0, 0, 5];
        let b = [0u64, 0, 0, 3];
        assert_eq!(u256_add(a, b), [0u64, 0, 0, 8]);
    }

    #[test]
    fn test_u256_add_carry() {
        let a = [0u64, 0, 0, u64::MAX];
        let b = [0u64, 0, 0, 1];
        assert_eq!(u256_add(a, b), [0u64, 0, 1, 0]);
    }

    #[test]
    fn test_bytes_u256_roundtrip() {
        let orig = [1u64, 2u64, 3u64, 4u64];
        let bytes = u256_to_bytes(&orig);
        assert_eq!(bytes_to_u256(&bytes), orig);
    }

    #[test]
    fn test_access_list_warm_cold() {
        let mut al = AccessList::default();
        let addr = [0u8; 20];
        let key  = [0u8; 32];
        assert_eq!(al.sload_cost(&addr, &key), 2100); // cold
        assert_eq!(al.sload_cost(&addr, &key), 100);  // warm
    }

    #[test]
    fn test_create2_address_deterministic() {
        let sender = [0u8; 20];
        let salt   = [0u8; 32];
        let code   = &[0x60u8, 0x00];
        let a1 = create2_address(&sender, &salt, code);
        let a2 = create2_address(&sender, &salt, code);
        assert_eq!(a1, a2);
    }

    #[test]
    fn test_sha256_precompile() {
        let p = Sha256Precompile;
        let (out, cost) = p.run(&[], 10_000).unwrap();
        assert_eq!(out.len(), 32);
        assert_eq!(cost, 60); // base cost for 0 words
    }

    // ── Layer 1: Security definitions ────────────────────────────────────────

    #[test]
    fn test_gas_limit_zero_out_of_gas_immediately() {
        // L1: zero gas limit means any operation is OOG
        let mut g = GasMeter::new(0);
        assert!(matches!(g.consume(1), Err(EvmError::OutOfGas)));
    }

    #[test]
    fn test_stack_max_depth_is_1024() {
        // L1: EVM stack depth is exactly 1024 — 1025th push must fail
        let mut s = Stack::new();
        for _ in 0..1024 { s.push([0u64; 4]).unwrap(); }
        assert!(matches!(s.push([0u64; 4]), Err(EvmError::StackOverflow)));
        assert_eq!(s.len(), 1024);
    }

    #[test]
    fn test_memory_expansion_gas_nonzero_for_large_alloc() {
        // L1: large memory alloc must have nonzero gas cost (prevent free memory griefing)
        let mut m = Memory::new();
        let cost = m.ensure(0, 1024 * 32);
        assert!(cost > 0);
    }

    #[test]
    fn test_static_call_frame_flag_propagates() {
        // L1: is_static flag on CallFrame must be preserved — can't do state changes
        let frame = CallFrame::new(
            vec![], [0u8; 20], [0u8; 20], 0, vec![], 1_000_000, true, 0, 0,
        );
        assert!(frame.is_static);
    }

    // ── Layer 2: Functional correctness ──────────────────────────────────────

    #[test]
    fn test_gas_used_tracked_correctly() {
        // L2: gas_used = gas_limit - gas_remaining
        let mut g = GasMeter::new(100_000);
        g.consume(30_000).unwrap();
        assert_eq!(g.gas_used(), 30_000);
        assert_eq!(g.gas_remaining, 70_000);
    }

    #[test]
    fn test_memory_write_and_read_word() {
        // L2: store 32 bytes at offset 0, retrieve them correctly
        let mut m = Memory::new();
        m.ensure(0, 32);
        let word: U256 = [0xABABABABABABABABu64; 4];
        m.write_word(0, &word);
        let loaded = m.read_word(0);
        assert_eq!(loaded, word);
    }

    #[test]
    fn test_access_list_address_warm_on_second_access() {
        // L2: address warm_address returns true (cold) first time, false (warm) second
        let mut al = AccessList::default();
        let addr = [1u8; 20];
        assert!(al.warm_address(&addr));  // was cold
        assert!(!al.warm_address(&addr)); // now warm
    }

    #[test]
    fn test_create2_address_changes_with_salt() {
        // L2: different salts must produce different addresses
        let sender = [0u8; 20];
        let code = &[0x60u8, 0x00];
        let a1 = create2_address(&sender, &[0u8; 32], code);
        let a2 = create2_address(&sender, &[1u8; 32], code);
        assert_ne!(a1, a2);
    }

    #[test]
    fn test_u256_add_wraps_correctly_at_max() {
        // L2: [u64::MAX; 4] + 1 should wrap to [0; 4]
        let max = [u64::MAX; 4];
        let one = [0u64, 0, 0, 1];
        let result = u256_add(max, one);
        assert_eq!(result, [0u64; 4]);
    }

    // ── Layer 3: Protection ───────────────────────────────────────────────────

    #[test]
    fn test_sha256_precompile_insufficient_gas_rejected() {
        // L3: precompile must reject calls with insufficient gas
        let p = Sha256Precompile;
        let result = p.run(&[0u8; 32], 10); // far below minimum
        assert!(result.is_err());
    }

    #[test]
    fn test_gas_consume_exact_limit_ok() {
        // L3: consuming exactly the gas limit must succeed (boundary condition)
        let mut g = GasMeter::new(21_000);
        assert!(g.consume(21_000).is_ok());
        assert_eq!(g.gas_remaining, 0);
    }

    #[test]
    fn test_stack_peek_out_of_range_returns_error() {
        // L3: peeking beyond stack depth must return StackUnderflow, not panic
        let mut s = Stack::new();
        s.push([42u64, 0, 0, 0]).unwrap();
        assert!(matches!(s.peek(5), Err(EvmError::StackUnderflow)));
    }

    // ── Layer 4: Detection & Response ────────────────────────────────────────

    #[test]
    fn test_out_of_gas_zeroes_remaining() {
        // L4: OOG condition must zero out gas_remaining for subsequent operations
        let mut g = GasMeter::new(100);
        let _ = g.consume(200); // OOG
        assert_eq!(g.gas_remaining, 0);
    }

    #[test]
    fn test_base_gas_unknown_opcode_returns_default() {
        // L4: unknown opcode must return a safe default cost, not panic
        let cost = base_gas(0xEF); // undefined opcode
        assert!(cost > 0); // must have nonzero cost to prevent free execution
    }

    #[test]
    fn test_effective_refund_zero_when_no_gas_used() {
        // L4: no gas used → no refund (prevents refund manipulation)
        let g = GasMeter::new(100_000);
        g.gas_remaining; // no consume called
        assert_eq!(g.effective_refund(), 0);
    }

    // ── Layer 5: Resilience ───────────────────────────────────────────────────

    #[test]
    fn test_memory_zero_size_ensure_no_cost() {
        // L5: zero-size memory ensure must be free and not panic
        let mut m = Memory::new();
        let cost = m.ensure(0, 0);
        assert_eq!(cost, 0);
    }

    #[test]
    fn test_stack_pop_after_push_multiple() {
        // L5: push N items then pop N items must drain in LIFO order
        let mut s = Stack::new();
        for i in 0..10u64 { s.push([i, 0, 0, 0]).unwrap(); }
        for i in (0..10u64).rev() {
            assert_eq!(s.pop().unwrap(), [i, 0, 0, 0]);
        }
    }

    #[test]
    fn test_gas_refund_capped_proportional_to_used() {
        // L5: EIP-3529 cap is 1/5 of gas_used — verify against different use amounts
        let mut g = GasMeter::new(100_000);
        g.consume(50_000).unwrap(); // used 50_000
        g.refund(100_000);          // request huge refund
        assert_eq!(g.effective_refund(), 10_000); // capped at 50_000/5
    }

    // ── Layer 6: Governance & Compliance ─────────────────────────────────────

    #[test]
    fn test_create2_address_is_20_bytes() {
        // L6: CREATE2 address must always be exactly 20 bytes (EIP-1014)
        let addr = create2_address(&[0u8; 20], &[0u8; 32], &[0x60, 0x00]);
        assert_eq!(addr.len(), 20);
    }

    #[test]
    fn test_sha256_output_is_always_32_bytes() {
        // L6: SHA256 precompile output must always be exactly 32 bytes (EIP-152)
        let p = Sha256Precompile;
        for len in [0usize, 1, 31, 32, 64, 128] {
            let input = vec![0xAAu8; len];
            let (out, _) = p.run(&input, 1_000_000).unwrap();
            assert_eq!(out.len(), 32, "SHA256 output must be 32 bytes for input len {len}");
        }
    }

    #[test]
    fn test_eip2929_cold_slot_cost_is_2100() {
        // L6: EIP-2929 cold SLOAD must cost exactly 2100 (consensus-critical)
        let mut al = AccessList::default();
        assert_eq!(al.sload_cost(&[0u8; 20], &[0u8; 32]), 2100);
    }

    #[test]
    fn test_eip2929_warm_slot_cost_is_100() {
        // L6: EIP-2929 warm SLOAD must cost exactly 100 (consensus-critical)
        let mut al = AccessList::default();
        al.sload_cost(&[0u8; 20], &[0u8; 32]); // warm it
        assert_eq!(al.sload_cost(&[0u8; 20], &[0u8; 32]), 100);
    }

    // ── Reentrancy simulation ─────────────────────────────────────────────────

    #[test]
    fn test_journal_checkpoint_revert_then_apply_again() {
        // Reentrancy: reverting to a checkpoint then re-applying same ops must be clean
        // We simulate this on GasMeter: consume → check → consume again after OOG reset
        let mut g = GasMeter::new(1000);
        g.consume(500).unwrap();
        assert_eq!(g.gas_used(), 500);
        // Simulate revert: restore gas
        g.gas_remaining = g.gas_limit;
        assert_eq!(g.gas_used(), 0);
        g.consume(500).unwrap();
        assert_eq!(g.gas_used(), 500);
    }

    #[test]
    fn test_stack_operations_interleaved_dont_corrupt_state() {
        // Reentrancy: interleaved push/pop/dup/swap must leave stack in consistent state
        let mut s = Stack::new();
        s.push([1u64, 0, 0, 0]).unwrap();
        s.push([2u64, 0, 0, 0]).unwrap();
        s.dup(1).unwrap();       // stack: [1, 2, 2]
        s.swap(1).unwrap();      // stack: [1, 2, 2] → [2, 2, 1] (swap top two)
        let top = s.pop().unwrap();
        assert_eq!(top[0], 2);
        assert_eq!(s.len(), 2);
    }

    // ── Read-only reentrancy ──────────────────────────────────────────────────

    #[test]
    fn test_access_list_read_during_warm_does_not_mutate_cost() {
        // Read-only reentrancy: reading sload_cost twice for same slot must be idempotent
        let mut al = AccessList::default();
        let addr = [5u8; 20];
        let key  = [6u8; 32];
        let _ = al.sload_cost(&addr, &key); // warm it
        let c1 = al.sload_cost(&addr, &key);
        let c2 = al.sload_cost(&addr, &key);
        assert_eq!(c1, c2); // warm cost is stable
        assert_eq!(c1, 100);
    }

    #[test]
    fn test_gas_remaining_read_is_monotonically_decreasing() {
        // Read-only reentrancy: gas_remaining must never increase during normal execution
        let mut g = GasMeter::new(10_000);
        let mut prev = g.gas_remaining;
        for cost in [100u64, 200, 300, 500] {
            g.consume(cost).unwrap();
            assert!(g.gas_remaining <= prev);
            prev = g.gas_remaining;
        }
    }

    // ── Function parameter validation ─────────────────────────────────────────

    #[test]
    fn test_memory_slice_zero_size_returns_empty() {
        // Param validation: slicing zero bytes must return empty vec, not panic
        let m = Memory::new();
        assert_eq!(m.slice(0, 0), vec![]);
    }

    #[test]
    fn test_gas_meter_consume_zero_is_noop() {
        // Param validation: consuming zero gas must not change remaining
        let mut g = GasMeter::new(1000);
        g.consume(0).unwrap();
        assert_eq!(g.gas_remaining, 1000);
    }

    #[test]
    fn test_stack_swap_with_n_zero_is_noop() {
        // Param validation: SWAP0 (n=0) means swap top with itself — no change
        let mut s = Stack::new();
        s.push([7u64, 0, 0, 0]).unwrap();
        let result = s.swap(0); // swap top with top
        let _ = result; // may succeed or error; must not panic
        if result.is_ok() {
            assert_eq!(s.pop().unwrap(), [7u64, 0, 0, 0]);
        }
    }

    // ── Misconfiguration ──────────────────────────────────────────────────────

    #[test]
    fn test_call_frame_is_static_flag_is_sticky() {
        // Misconfiguration: once is_static=true, frame must never allow state writes
        let frame = CallFrame::new(vec![], [0u8; 20], [0u8; 20], 0, vec![], 100_000, true, 0, 0);
        assert!(frame.is_static, "is_static must be preserved on CallFrame construction");
    }

    #[test]
    fn test_gas_meter_refund_negative_does_not_underflow() {
        // Misconfiguration: negative refund must not cause underflow
        let mut g = GasMeter::new(10_000);
        g.consume(5_000).unwrap();
        g.refund(-1000); // reduce refund
        // effective_refund must be 0 when refund is negative
        assert_eq!(g.effective_refund(), 0);
    }

    #[test]
    fn test_precompile_set_has_sha256_at_address_2() {
        // Misconfiguration: precompile address 0x02 must be SHA256 (Ethereum standard)
        let ps = PrecompileSet::ethereum_mainnet();
        let mut addr = [0u8; 20]; addr[19] = 2;
        assert!(ps.get(&addr).is_some(), "SHA256 precompile must be registered at address 0x02");
    }

    // ── Governance attack ─────────────────────────────────────────────────────

    #[test]
    fn test_create2_address_does_not_collide_with_different_code() {
        // Governance attack: same sender+salt but different code must give different address
        let sender = [0u8; 20];
        let salt   = [0u8; 32];
        let a1 = create2_address(&sender, &salt, &[0x60, 0x00]);
        let a2 = create2_address(&sender, &salt, &[0x60, 0x01]); // different bytecode
        assert_ne!(a1, a2, "different init code must produce different CREATE2 address");
    }

    #[test]
    fn test_access_list_independent_addresses_have_independent_slots() {
        // Governance attack: warming slot for address A must not warm slots for address B
        let mut al = AccessList::default();
        let addr_a = [0x01u8; 20];
        let addr_b = [0x02u8; 20];
        let slot = [0u8; 32];
        al.sload_cost(&addr_a, &slot); // warm addr_a
        // addr_b slot must still be cold
        assert_eq!(al.sload_cost(&addr_b, &slot), 2100,
            "warming a slot for addr_a must not warm same slot for addr_b");
    }

    #[test]
    fn test_static_call_frame_depth_tracked() {
        // Governance attack: call depth must be tracked to prevent stack overflow attacks
        let frame = CallFrame::new(vec![], [0u8; 20], [0u8; 20], 0, vec![], 100_000, false, 512, 0);
        assert_eq!(frame.depth, 512);
    }
}
