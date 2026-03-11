// ============================================================
// fullnode/crates/types/src/lib.rs
// Core data structures shared across all subsystems
// ============================================================

pub mod block;
pub mod transaction;
pub mod account;
pub mod receipt;
pub mod hash;
pub mod address;
pub mod primitives;

pub use block::*;
pub use transaction::*;
pub use account::*;
pub use receipt::*;
pub use hash::*;
pub use address::*;
pub use primitives::*;

// ─── Primitive Aliases ────────────────────────────────────────────────────────
pub type U256         = primitive_types::U256;
pub type H256         = primitive_types::H256;
pub type H160         = primitive_types::H160;
pub type Bytes        = bytes::Bytes;
pub type BlockNumber  = u64;
pub type Nonce        = u64;
pub type GasAmount    = u64;
