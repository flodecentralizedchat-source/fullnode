// ============================================================
// fullnode/crates/types/src/transaction.rs
// Transaction data structures — EIP-155, EIP-1559, EIP-2930
// ============================================================

use serde::{Deserialize, Serialize};
use crate::{U256, H256, H160, Nonce, GasAmount};

/// Transaction type discriminant (EIP-2718 typed transactions)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum TxType {
    Legacy     = 0x00,
    AccessList = 0x01, // EIP-2930
    DynamicFee = 0x02, // EIP-1559
    Blob       = 0x03, // EIP-4844
}

/// Unified transaction envelope (EIP-2718 tagged union)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transaction {
    pub tx_type:   TxType,
    pub inner:     TxInner,
    /// Recoverable ECDSA signature
    pub signature: Signature,
    /// Cached hash — computed lazily via hash()
    #[serde(skip)]
    cached_hash: std::sync::OnceLock<H256>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxInner {
    pub chain_id:                  Option<u64>,
    pub nonce:                     Nonce,
    /// For legacy/EIP-2930: gas_price. For EIP-1559: ignored (use max_fee).
    pub gas_price:                 Option<U256>,
    /// EIP-1559 priority fee tip (max amount above base fee)
    pub max_priority_fee_per_gas:  Option<U256>,
    /// EIP-1559 total fee cap (base fee + tip)
    pub max_fee_per_gas:           Option<U256>,
    pub gas_limit:                 GasAmount,
    /// None = contract creation
    pub to:                        Option<H160>,
    pub value:                     U256,
    pub data:                      Vec<u8>,
    /// EIP-2930 access list (pre-warm storage slots)
    pub access_list:               Vec<AccessListItem>,
    /// EIP-4844 blob versioned hashes
    pub blob_versioned_hashes:     Vec<H256>,
    pub max_fee_per_blob_gas:      Option<U256>,
}

/// EIP-2930 access list entry — pre-warm storage slots (SLOAD: 2100 → 100)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessListItem {
    pub address:      H160,
    pub storage_keys: Vec<H256>,
}

/// ECDSA secp256k1 signature (recoverable).
/// v encodes both parity and optional chain_id (EIP-155).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Signature {
    pub v: u64,
    pub r: U256,
    pub s: U256,
}

impl Transaction {
    /// Compute transaction hash: keccak256(type_byte || rlp(fields))
    pub fn hash(&self) -> H256 {
        *self.cached_hash.get_or_init(|| {
            use sha3::{Digest, Keccak256};
            let mut hasher = Keccak256::new();
            let rlp_data = self.signing_rlp();
            match self.tx_type {
                TxType::Legacy => {
                    hasher.update(&rlp_data);
                }
                t => {
                    hasher.update(&[t as u8]);
                    hasher.update(&rlp_data);
                }
            }
            H256::from_slice(&hasher.finalize())
        })
    }

    /// Recover sender address from ECDSA signature.
    /// Algorithm: given (r, s, v) + signing hash → recover pubkey → derive address.
    pub fn recover_sender(&self) -> Result<H160, TxError> {
        use k256::ecdsa::{RecoveryId, Signature as K256Sig, VerifyingKey};

        let sig_hash  = self.signing_hash();
        let rec_parity = self.recovery_parity()?;

        let mut r_bytes = [0u8; 32];
        let mut s_bytes = [0u8; 32];
        self.signature.r.to_big_endian(&mut r_bytes);
        self.signature.s.to_big_endian(&mut s_bytes);

        let mut sig_bytes = [0u8; 64];
        sig_bytes[..32].copy_from_slice(&r_bytes);
        sig_bytes[32..].copy_from_slice(&s_bytes);

        let k256_sig = K256Sig::from_bytes(&sig_bytes.into())
            .map_err(|_| TxError::InvalidSignature)?;
        let rec_id = RecoveryId::new(rec_parity == 1, false);

        let vk = VerifyingKey::recover_from_prehash(sig_hash.as_bytes(), &k256_sig, rec_id)
            .map_err(|_| TxError::RecoveryFailed)?;

        let point = vk.to_encoded_point(false);
        let pubkey = &point.as_bytes()[1..]; // strip 0x04 prefix

        use sha3::{Digest, Keccak256};
        let hash = Keccak256::digest(pubkey);
        Ok(H160::from_slice(&hash[12..]))
    }

    /// Effective gas price: min(max_fee, base_fee + priority_tip)
    pub fn effective_gas_price(&self, base_fee: U256) -> U256 {
        match self.tx_type {
            TxType::DynamicFee | TxType::Blob => {
                let max_fee  = self.inner.max_fee_per_gas.unwrap_or_default();
                let priority = self.inner.max_priority_fee_per_gas.unwrap_or_default();
                std::cmp::min(max_fee, base_fee + priority)
            }
            _ => self.inner.gas_price.unwrap_or_default(),
        }
    }

    /// RLP-encode the signing payload (type-specific field list).
    fn signing_rlp(&self) -> Vec<u8> {
        let mut s = rlp::RlpStream::new();
        match self.tx_type {
            TxType::Legacy => {
                s.begin_list(6);
                s.append(&self.inner.nonce);
                let gp = self.inner.gas_price.unwrap_or_default();
                let mut gp_bytes = [0u8; 32];
                gp.to_big_endian(&mut gp_bytes);
                let gp_trim = gp_bytes.iter().position(|&b| b != 0).map(|i| &gp_bytes[i..]).unwrap_or(&[0u8]);
                s.append(&gp_trim);
                s.append(&self.inner.gas_limit);
                match &self.inner.to {
                    Some(addr) => s.append(&addr.as_bytes()),
                    None       => s.append_empty_data(),
                };
                let mut val = [0u8; 32];
                self.inner.value.to_big_endian(&mut val);
                let val_trim = val.iter().position(|&b| b != 0).map(|i| &val[i..]).unwrap_or(&[0u8]);
                s.append(&val_trim);
                s.append(&self.inner.data.as_slice());
            }
            TxType::DynamicFee => {
                s.begin_list(9);
                s.append(&self.inner.chain_id.unwrap_or(1u64));
                s.append(&self.inner.nonce);
                let mf = self.inner.max_priority_fee_per_gas.unwrap_or_default();
                let mut mf_b = [0u8; 32]; mf.to_big_endian(&mut mf_b);
                let mf_t = mf_b.iter().position(|&b| b != 0).map(|i| &mf_b[i..]).unwrap_or(&[0u8]);
                s.append(&mf_t);
                let mfg = self.inner.max_fee_per_gas.unwrap_or_default();
                let mut mfg_b = [0u8; 32]; mfg.to_big_endian(&mut mfg_b);
                let mfg_t = mfg_b.iter().position(|&b| b != 0).map(|i| &mfg_b[i..]).unwrap_or(&[0u8]);
                s.append(&mfg_t);
                s.append(&self.inner.gas_limit);
                match &self.inner.to {
                    Some(addr) => s.append(&addr.as_bytes()),
                    None       => s.append_empty_data(),
                };
                let mut val = [0u8; 32]; self.inner.value.to_big_endian(&mut val);
                let val_t = val.iter().position(|&b| b != 0).map(|i| &val[i..]).unwrap_or(&[0u8]);
                s.append(&val_t);
                s.append(&self.inner.data.as_slice());
                s.begin_list(self.inner.access_list.len());
                for item in &self.inner.access_list {
                    s.begin_list(2);
                    s.append(&item.address.as_bytes());
                    s.begin_list(item.storage_keys.len());
                    for k in &item.storage_keys { s.append(&k.as_bytes()); }
                }
            }
            _ => {
                // Fallback: encode minimal fields
                s.begin_list(3);
                s.append(&self.inner.nonce);
                s.append(&self.inner.gas_limit);
                s.append(&self.inner.data.as_slice());
            }
        }
        s.out().to_vec()
    }

    fn signing_hash(&self) -> H256 {
        use sha3::{Digest, Keccak256};
        let rlp = self.signing_rlp();
        H256::from_slice(&Keccak256::digest(&rlp))
    }

    /// Extract the recovery parity bit (0 or 1) from v.
    fn recovery_parity(&self) -> Result<u8, TxError> {
        let v = self.signature.v;
        Ok(match self.tx_type {
            TxType::Legacy => {
                if v == 27 || v == 28 {
                    (v - 27) as u8
                } else if v >= 35 {
                    ((v - 35) % 2) as u8
                } else {
                    return Err(TxError::InvalidV(v));
                }
            }
            _ => (v & 1) as u8,
        })
    }
}

/// Pending transaction with ordering metadata for the mempool.
#[derive(Debug, Clone)]
pub struct PendingTx {
    pub tx:           Transaction,
    pub sender:       H160,
    /// Effective priority fee (tip above base fee)
    pub priority_fee: U256,
    /// Arrival time for FIFO ordering among equal-fee txns
    pub received_at:  std::time::Instant,
    /// Byte length for pool capacity management
    pub encoded_len:  usize,
}

impl PartialEq for PendingTx {
    fn eq(&self, other: &Self) -> bool { self.tx.hash() == other.tx.hash() }
}
impl Eq for PendingTx {}
impl PartialOrd for PendingTx {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> { Some(self.cmp(other)) }
}
/// Higher fee → higher priority; among ties, older arrival wins.
impl Ord for PendingTx {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.priority_fee
            .cmp(&other.priority_fee)
            .then_with(|| other.received_at.cmp(&self.received_at))
    }
}

// ─── Errors ──────────────────────────────────────────────────────────────────
#[derive(Debug, thiserror::Error)]
pub enum TxError {
    #[error("invalid signature")]
    InvalidSignature,
    #[error("signature recovery failed")]
    RecoveryFailed,
    #[error("invalid v value: {0}")]
    InvalidV(u64),
    #[error("nonce too low: got {got}, expected {expected}")]
    NonceTooLow { got: u64, expected: u64 },
    #[error("insufficient balance: have {have}, need {need}")]
    InsufficientBalance { have: U256, need: U256 },
    #[error("gas limit exceeds block limit")]
    GasLimitExceeded,
    #[error("intrinsic gas too low")]
    IntrinsicGasTooLow,
}

// ─── Tests ───────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;

    fn make_legacy_tx(nonce: u64, gas_price: u64, value: u64) -> Transaction {
        Transaction {
            tx_type: TxType::Legacy,
            inner: TxInner {
                chain_id: Some(1),
                nonce,
                gas_price: Some(U256::from(gas_price)),
                max_priority_fee_per_gas: None,
                max_fee_per_gas: None,
                gas_limit: 21_000,
                to: Some(H160::zero()),
                value: U256::from(value),
                data: vec![],
                access_list: vec![],
                blob_versioned_hashes: vec![],
                max_fee_per_blob_gas: None,
            },
            signature: Signature::default(),
            cached_hash: std::sync::OnceLock::new(),
        }
    }

    #[test]
    fn test_hash_is_deterministic() {
        let tx = make_legacy_tx(0, 1_000_000_000, 0);
        assert_eq!(tx.hash(), tx.hash());
    }

    #[test]
    fn test_different_nonce_different_hash() {
        let tx1 = make_legacy_tx(0, 1_000_000_000, 0);
        let tx2 = make_legacy_tx(1, 1_000_000_000, 0);
        assert_ne!(tx1.hash(), tx2.hash());
    }

    #[test]
    fn test_effective_gas_price_eip1559() {
        let mut tx = make_legacy_tx(0, 0, 0);
        tx.tx_type = TxType::DynamicFee;
        tx.inner.gas_price = None;
        tx.inner.max_fee_per_gas = Some(U256::from(10u64));
        tx.inner.max_priority_fee_per_gas = Some(U256::from(2u64));

        // base_fee=7: effective = min(10, 7+2) = 9
        assert_eq!(tx.effective_gas_price(U256::from(7u64)), U256::from(9u64));
        // base_fee=9: effective = min(10, 9+2=11) = 10
        assert_eq!(tx.effective_gas_price(U256::from(9u64)), U256::from(10u64));
    }

    #[test]
    fn test_recovery_parity_legacy_27() {
        let mut tx = make_legacy_tx(0, 0, 0);
        tx.signature.v = 27;
        assert_eq!(tx.recovery_parity().unwrap(), 0);
    }

    #[test]
    fn test_recovery_parity_legacy_28() {
        let mut tx = make_legacy_tx(0, 0, 0);
        tx.signature.v = 28;
        assert_eq!(tx.recovery_parity().unwrap(), 1);
    }

    #[test]
    fn test_recovery_parity_eip155() {
        let mut tx = make_legacy_tx(0, 0, 0);
        // v = chain_id*2 + 35 → parity = 0
        tx.signature.v = 1 * 2 + 35; // = 37
        assert_eq!(tx.recovery_parity().unwrap(), 0);
        // v = chain_id*2 + 36 → parity = 1
        tx.signature.v = 1 * 2 + 36; // = 38
        assert_eq!(tx.recovery_parity().unwrap(), 1);
    }
}
