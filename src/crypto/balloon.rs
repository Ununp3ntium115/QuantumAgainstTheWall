//! Balloon Hashing - Provably Space-Hard Function
//!
//! Implements Balloon hashing from Stanford's Applied Crypto Group.
//! Unlike Argon2, Balloon has *provable* security guarantees in the
//! random oracle model.
//!
//! Key properties:
//! - Proven memory-hardness (not just heuristic)
//! - Data-independent memory access (side-channel resistant)
//! - Built from any standard hash function (SHA-256, SHA-3, etc.)
//!
//! Reference: https://crypto.stanford.edu/balloon/

use crate::crypto::kdf::hash_sha256;
use crate::crypto::{CryptoResult, Zeroize};

/// Balloon hashing parameters
#[derive(Debug, Clone)]
pub struct BalloonParams {
    /// Space cost: number of 32-byte blocks in buffer
    /// Total memory = space_cost * 32 bytes
    pub space_cost: usize,
    /// Time cost: number of rounds
    pub time_cost: usize,
    /// Delta: number of dependencies per block (typically 3-5)
    pub delta: usize,
    /// Output length in bytes
    pub output_len: usize,
}

impl Default for BalloonParams {
    fn default() -> Self {
        Self {
            space_cost: 65536, // 2 MB (65536 * 32 bytes)
            time_cost: 3,      // 3 rounds
            delta: 4,          // 4 dependencies
            output_len: 32,    // 256-bit output
        }
    }
}

impl BalloonParams {
    /// Maximum quantum pain (1 GB memory)
    pub fn quantum_fortress() -> Self {
        Self {
            space_cost: 33554432, // 1 GB (33554432 * 32 bytes)
            time_cost: 4,
            delta: 5,
            output_len: 32,
        }
    }

    /// High security (256 MB)
    pub fn high_security() -> Self {
        Self {
            space_cost: 8388608, // 256 MB
            time_cost: 3,
            delta: 4,
            output_len: 32,
        }
    }

    /// Moderate security (64 MB)
    pub fn moderate() -> Self {
        Self {
            space_cost: 2097152, // 64 MB
            time_cost: 3,
            delta: 4,
            output_len: 32,
        }
    }

    /// Interactive (16 MB)
    pub fn interactive() -> Self {
        Self {
            space_cost: 524288, // 16 MB
            time_cost: 2,
            delta: 3,
            output_len: 32,
        }
    }

    /// Memory usage in bytes
    pub fn memory_usage(&self) -> usize {
        self.space_cost * 32
    }
}

/// Hash counter with block index
fn hash_counter(cnt: u64, buf: &[u8], salt: &[u8]) -> [u8; 32] {
    let mut input = Vec::with_capacity(8 + buf.len() + salt.len());
    input.extend_from_slice(&cnt.to_le_bytes());
    input.extend_from_slice(buf);
    input.extend_from_slice(salt);
    hash_sha256(&input)
}

/// Hash with multiple inputs
fn hash_multi(inputs: &[&[u8]]) -> [u8; 32] {
    let total_len: usize = inputs.iter().map(|i| i.len()).sum();
    let mut combined = Vec::with_capacity(total_len);
    for input in inputs {
        combined.extend_from_slice(input);
    }
    hash_sha256(&combined)
}

/// Integer to bytes
fn int_to_bytes(v: u64) -> [u8; 8] {
    v.to_le_bytes()
}

/// Balloon hash function
///
/// Based on the algorithm from:
/// "Balloon Hashing: A Memory-Hard Function Providing Provable Protection
///  Against Sequential Attacks" - Boneh, Corrigan-Gibbs, Schechter
pub fn balloon_hash(password: &[u8], salt: &[u8], params: &BalloonParams) -> CryptoResult<Vec<u8>> {
    let s = params.space_cost;
    let t = params.time_cost;
    let delta = params.delta;

    // Allocate buffer
    let mut buf: Vec<[u8; 32]> = vec![[0u8; 32]; s];

    // Step 1: Expand input into buffer
    // buf[0] = H(0 || password || salt)
    buf[0] = hash_counter(0, password, salt);

    // buf[i] = H(i || buf[i-1] || salt) for i = 1..s
    for i in 1..s {
        buf[i] = hash_counter(i as u64, &buf[i - 1], salt);
    }

    // Step 2: Mix buffer contents
    let mut cnt: u64 = s as u64;

    for t_round in 0..t {
        for m in 0..s {
            // Hash previous block
            let prev = if m == 0 { s - 1 } else { m - 1 };

            // Compute new value: H(cnt || buf[prev] || buf[m])
            let new_val = hash_multi(&[&int_to_bytes(cnt), &buf[prev], &buf[m]]);
            buf[m] = new_val;
            cnt += 1;

            // Mix in delta pseudo-random blocks
            for i in 0..delta {
                // idx_block = H(t || m || i || salt)
                let idx_input = hash_multi(&[
                    &int_to_bytes(t_round as u64),
                    &int_to_bytes(m as u64),
                    &int_to_bytes(i as u64),
                    salt,
                ]);

                // Convert hash to index (first 8 bytes as u64, mod s)
                let mut idx_bytes = [0u8; 8];
                idx_bytes.copy_from_slice(&idx_input[0..8]);
                let other = (u64::from_le_bytes(idx_bytes) as usize) % s;

                // buf[m] = H(cnt || buf[m] || buf[other])
                let mixed = hash_multi(&[&int_to_bytes(cnt), &buf[m], &buf[other]]);
                buf[m] = mixed;
                cnt += 1;
            }
        }
    }

    // Step 3: Extract output
    // Output = H(cnt || buf[s-1])
    let output = hash_multi(&[&int_to_bytes(cnt), &buf[s - 1]]);

    // Clear buffer
    for block in &mut buf {
        block.zeroize();
    }

    Ok(output[..params.output_len].to_vec())
}

/// Balloon M (memory-hard with extra mixing)
///
/// Enhanced version with additional mixing rounds
pub fn balloon_m_hash(
    password: &[u8],
    salt: &[u8],
    params: &BalloonParams,
) -> CryptoResult<Vec<u8>> {
    let s = params.space_cost;
    let t = params.time_cost;
    let delta = params.delta;

    let mut buf: Vec<[u8; 32]> = vec![[0u8; 32]; s];

    // Initialize
    buf[0] = hash_counter(0, password, salt);
    for i in 1..s {
        buf[i] = hash_counter(i as u64, &buf[i - 1], salt);
    }

    let mut cnt: u64 = s as u64;

    // Enhanced mixing with bidirectional dependencies
    for t_round in 0..t {
        // Forward pass
        for m in 0..s {
            let prev = if m == 0 { s - 1 } else { m - 1 };
            let next = if m == s - 1 { 0 } else { m + 1 };

            buf[m] = hash_multi(&[&int_to_bytes(cnt), &buf[prev], &buf[m], &buf[next]]);
            cnt += 1;

            for i in 0..delta {
                let idx_input = hash_multi(&[
                    &int_to_bytes(t_round as u64),
                    &int_to_bytes(m as u64),
                    &int_to_bytes(i as u64),
                    salt,
                ]);
                let mut idx_bytes = [0u8; 8];
                idx_bytes.copy_from_slice(&idx_input[0..8]);
                let other = (u64::from_le_bytes(idx_bytes) as usize) % s;

                buf[m] = hash_multi(&[&int_to_bytes(cnt), &buf[m], &buf[other]]);
                cnt += 1;
            }
        }

        // Backward pass (extra security)
        for m in (0..s).rev() {
            let prev = if m == 0 { s - 1 } else { m - 1 };

            buf[m] = hash_multi(&[&int_to_bytes(cnt), &buf[prev], &buf[m]]);
            cnt += 1;
        }
    }

    let output = hash_multi(&[&int_to_bytes(cnt), &buf[s - 1]]);

    for block in &mut buf {
        block.zeroize();
    }

    Ok(output[..params.output_len].to_vec())
}

/// Balloon key with automatic zeroization
pub struct BalloonKey {
    key: Vec<u8>,
}

impl BalloonKey {
    pub fn derive(password: &[u8], salt: &[u8], params: &BalloonParams) -> CryptoResult<Self> {
        let key = balloon_hash(password, salt, params)?;
        Ok(Self { key })
    }

    pub fn derive_enhanced(
        password: &[u8],
        salt: &[u8],
        params: &BalloonParams,
    ) -> CryptoResult<Self> {
        let key = balloon_m_hash(password, salt, params)?;
        Ok(Self { key })
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.key
    }
}

impl Drop for BalloonKey {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_balloon_basic() {
        let password = b"password";
        let salt = b"somesalt";
        let params = BalloonParams {
            space_cost: 1024, // Small for testing
            time_cost: 1,
            delta: 3,
            output_len: 32,
        };

        let hash = balloon_hash(password, salt, &params).unwrap();
        assert_eq!(hash.len(), 32);

        // Deterministic
        let hash2 = balloon_hash(password, salt, &params).unwrap();
        assert_eq!(hash, hash2);
    }

    #[test]
    fn test_balloon_different_inputs() {
        let params = BalloonParams {
            space_cost: 1024,
            time_cost: 1,
            delta: 3,
            output_len: 32,
        };

        let hash1 = balloon_hash(b"password1", b"salt1234", &params).unwrap();
        let hash2 = balloon_hash(b"password2", b"salt1234", &params).unwrap();
        let hash3 = balloon_hash(b"password1", b"salt5678", &params).unwrap();

        assert_ne!(hash1, hash2);
        assert_ne!(hash1, hash3);
        assert_ne!(hash2, hash3);
    }

    #[test]
    fn test_balloon_m() {
        let password = b"test";
        let salt = b"saltval8";
        let params = BalloonParams {
            space_cost: 512,
            time_cost: 1,
            delta: 3,
            output_len: 32,
        };

        let hash = balloon_m_hash(password, salt, &params).unwrap();
        assert_eq!(hash.len(), 32);

        // Should differ from standard balloon
        let hash_std = balloon_hash(password, salt, &params).unwrap();
        assert_ne!(hash, hash_std);
    }

    #[test]
    fn test_balloon_key() {
        let params = BalloonParams {
            space_cost: 1024,
            time_cost: 1,
            delta: 3,
            output_len: 32,
        };

        let key = BalloonKey::derive(b"password", b"saltsalt", &params).unwrap();
        assert_eq!(key.as_bytes().len(), 32);
    }
}
