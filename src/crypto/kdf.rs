//! Key Derivation Functions.
//!
//! Provides HKDF for deriving keys from shared secrets.

use crate::crypto::{CryptoResult, Zeroize};

/// A derived key.
pub struct DerivedKey {
    bytes: [u8; 32],
}

impl DerivedKey {
    /// Get the key bytes.
    pub fn as_bytes(&self) -> [u8; 32] {
        self.bytes
    }
}

impl Drop for DerivedKey {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

/// Derive a key using HKDF (HMAC-based Key Derivation Function).
///
/// # Arguments
/// * `ikm` - Input keying material (e.g., shared secret from key exchange)
/// * `salt` - Optional salt value (context-specific)
/// * `info` - Application-specific context info
///
/// # Returns
/// A 32-byte derived key
pub fn derive_key(ikm: &[u8], salt: &[u8], info: &[u8]) -> CryptoResult<DerivedKey> {
    // HKDF-Extract
    let prk = hmac_sha256(if salt.is_empty() { &[0u8; 32] } else { salt }, ikm);

    // HKDF-Expand
    let mut okm = [0u8; 32];
    let mut t = Vec::new();
    let mut counter = 1u8;

    while okm.iter().take(32).filter(|&&b| b == 0).count() > 0 || counter == 1 {
        let mut input = t.clone();
        input.extend_from_slice(info);
        input.push(counter);

        t = hmac_sha256(&prk, &input).to_vec();

        let start = ((counter - 1) as usize) * 32;
        let end = (start + 32).min(32);
        let copy_len = end - start;
        if start < 32 {
            okm[start..start + copy_len].copy_from_slice(&t[..copy_len]);
        }

        counter += 1;
        if counter > 1 {
            break;
        }
    }

    Ok(DerivedKey { bytes: okm })
}

/// Derive multiple keys from the same secret.
pub fn derive_keys(ikm: &[u8], salt: &[u8], infos: &[&[u8]]) -> CryptoResult<Vec<DerivedKey>> {
    infos
        .iter()
        .map(|info| derive_key(ikm, salt, info))
        .collect()
}

/// HMAC-SHA256 implementation.
fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    const BLOCK_SIZE: usize = 64;
    const IPAD: u8 = 0x36;
    const OPAD: u8 = 0x5c;

    // Prepare key
    let mut k = [0u8; BLOCK_SIZE];
    if key.len() > BLOCK_SIZE {
        let hashed = sha256(key);
        k[..32].copy_from_slice(&hashed);
    } else {
        k[..key.len()].copy_from_slice(key);
    }

    // Inner padding
    let mut inner = [0u8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        inner[i] = k[i] ^ IPAD;
    }

    // Outer padding
    let mut outer = [0u8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        outer[i] = k[i] ^ OPAD;
    }

    // Inner hash
    let mut inner_input = Vec::with_capacity(BLOCK_SIZE + message.len());
    inner_input.extend_from_slice(&inner);
    inner_input.extend_from_slice(message);
    let inner_hash = sha256(&inner_input);

    // Outer hash
    let mut outer_input = Vec::with_capacity(BLOCK_SIZE + 32);
    outer_input.extend_from_slice(&outer);
    outer_input.extend_from_slice(&inner_hash);
    sha256(&outer_input)
}

/// SHA-256 implementation.
fn sha256(message: &[u8]) -> [u8; 32] {
    // Initial hash values
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];

    // Pre-processing: add padding
    let ml = (message.len() as u64) * 8;
    let mut padded = message.to_vec();
    padded.push(0x80);

    while (padded.len() % 64) != 56 {
        padded.push(0x00);
    }

    padded.extend_from_slice(&ml.to_be_bytes());

    // Process each 512-bit chunk
    for chunk in padded.chunks(64) {
        let mut w = [0u32; 64];

        // Copy chunk into first 16 words
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }

        // Extend to 64 words
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        // Initialize working variables
        let mut a = h[0];
        let mut b = h[1];
        let mut c = h[2];
        let mut d = h[3];
        let mut e = h[4];
        let mut f = h[5];
        let mut g = h[6];
        let mut hh = h[7];

        // Main loop
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        // Add compressed chunk to hash value
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }

    // Produce final hash
    let mut result = [0u8; 32];
    for i in 0..8 {
        result[i * 4..(i + 1) * 4].copy_from_slice(&h[i].to_be_bytes());
    }
    result
}

// SHA-256 round constants
const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// Hash data with SHA-256 (public interface).
pub fn hash_sha256(data: &[u8]) -> [u8; 32] {
    sha256(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_empty() {
        let result = sha256(b"");
        let expected: [u8; 32] = [
            0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
            0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
            0x78, 0x52, 0xb8, 0x55,
        ];
        assert_eq!(result, expected);
    }

    #[test]
    fn test_sha256_hello() {
        let result = sha256(b"hello");
        let expected: [u8; 32] = [
            0x2c, 0xf2, 0x4d, 0xba, 0x5f, 0xb0, 0xa3, 0x0e, 0x26, 0xe8, 0x3b, 0x2a, 0xc5, 0xb9,
            0xe2, 0x9e, 0x1b, 0x16, 0x1e, 0x5c, 0x1f, 0xa7, 0x42, 0x5e, 0x73, 0x04, 0x33, 0x62,
            0x93, 0x8b, 0x98, 0x24,
        ];
        assert_eq!(result, expected);
    }

    #[test]
    fn test_derive_key() {
        let ikm = b"input keying material";
        let salt = b"salt";
        let info = b"context info";

        let key1 = derive_key(ikm, salt, info).unwrap();
        let key2 = derive_key(ikm, salt, info).unwrap();

        // Same inputs should produce same key
        assert_eq!(key1.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn test_derive_key_different_info() {
        let ikm = b"input keying material";
        let salt = b"salt";

        let key1 = derive_key(ikm, salt, b"info1").unwrap();
        let key2 = derive_key(ikm, salt, b"info2").unwrap();

        // Different info should produce different keys
        assert_ne!(key1.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn test_hmac_sha256() {
        let key = b"key";
        let message = b"The quick brown fox jumps over the lazy dog";
        let result = hmac_sha256(key, message);

        // Known test vector
        let expected: [u8; 32] = [
            0xf7, 0xbc, 0x83, 0xf4, 0x30, 0x53, 0x84, 0x24, 0xb1, 0x32, 0x98, 0xe6, 0xaa, 0x6f,
            0xb1, 0x43, 0xef, 0x4d, 0x59, 0xa1, 0x49, 0x46, 0x17, 0x59, 0x97, 0x47, 0x9d, 0xbc,
            0x2d, 0x1a, 0x3c, 0xd8,
        ];
        assert_eq!(result, expected);
    }
}
