// ============================================================
// fullnode/crates/types/src/address.rs
// Address helpers and constants
// ============================================================

use crate::H160;

/// The zero address: 0x0000...0000
pub fn zero_address() -> H160 {
    H160::zero()
}

/// Derive an Ethereum address from an uncompressed secp256k1 public key (65 bytes).
/// address = keccak256(pubkey[1..])[12..]
pub fn address_from_pubkey(pubkey: &[u8]) -> H160 {
    use sha3::{Digest, Keccak256};
    assert!(pubkey.len() >= 65, "pubkey must be 65 bytes (uncompressed)");
    let hash = Keccak256::digest(&pubkey[1..]);
    H160::from_slice(&hash[12..])
}

/// EIP-55 checksum encode an address as a hex string.
pub fn checksum_encode(addr: &H160) -> String {
    use sha3::{Digest, Keccak256};
    let hex = hex::encode(addr.as_bytes());
    let hash = Keccak256::digest(hex.as_bytes());
    let mut out = String::with_capacity(42);
    out.push_str("0x");
    for (i, c) in hex.chars().enumerate() {
        let nibble = (hash[i / 2] >> (if i % 2 == 0 { 4 } else { 0 })) & 0xf;
        if nibble >= 8 {
            out.push(c.to_ascii_uppercase());
        } else {
            out.push(c);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zero_address_is_zero() {
        assert_eq!(zero_address(), H160::zero());
    }

    #[test]
    fn test_checksum_encode_length() {
        let addr = H160::zero();
        let s = checksum_encode(&addr);
        assert_eq!(s.len(), 42);
        assert!(s.starts_with("0x"));
    }
}
