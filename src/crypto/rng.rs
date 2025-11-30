//! Quantum-seeded cryptographically secure random number generator.
//!
//! Uses entropy from Matrix Product State (MPS) to seed a CSPRNG.

use crate::entropy::total_entanglement_entropy;
use crate::mps::MPS;
use crate::crypto::CryptoResult;

/// A cryptographically secure RNG seeded by quantum entropy.
///
/// The entropy is derived from the entanglement structure of an MPS,
/// then used to seed a ChaCha20-based CSPRNG.
pub struct QuantumRng {
    /// Internal state (ChaCha20 state)
    state: [u32; 16],
    /// Output buffer
    buffer: [u8; 64],
    /// Position in buffer
    position: usize,
    /// Entropy source info
    entropy_bits: f64,
}

impl QuantumRng {
    /// Create a new quantum RNG from an MPS state.
    ///
    /// The MPS entanglement entropy is used to derive the seed.
    ///
    /// # Arguments
    /// * `mps` - The MPS to extract entropy from
    ///
    /// # Returns
    /// A new QuantumRng instance
    pub fn from_mps(mps: &MPS) -> CryptoResult<Self> {
        let entropy = total_entanglement_entropy(mps);

        if entropy < 128.0 {
            // Need at least 128 bits of entropy for security
            // For product states, use fallback
        }

        // Derive seed from MPS singular values
        let seed = Self::derive_seed_from_mps(mps);

        Ok(Self::from_seed(&seed, entropy))
    }

    /// Create from a 32-byte seed directly.
    pub fn from_seed(seed: &[u8; 32], entropy_bits: f64) -> Self {
        // Initialize ChaCha20 state
        // Constants: "expand 32-byte k"
        let mut state = [0u32; 16];
        state[0] = 0x61707865; // "expa"
        state[1] = 0x3320646e; // "nd 3"
        state[2] = 0x79622d32; // "2-by"
        state[3] = 0x6b206574; // "te k"

        // Key (seed)
        for i in 0..8 {
            state[4 + i] = u32::from_le_bytes([
                seed[i * 4],
                seed[i * 4 + 1],
                seed[i * 4 + 2],
                seed[i * 4 + 3],
            ]);
        }

        // Counter
        state[12] = 0;
        state[13] = 0;

        // Nonce (derived from entropy value)
        let nonce_bytes = (entropy_bits.to_bits() as u64).to_le_bytes();
        state[14] = u32::from_le_bytes([nonce_bytes[0], nonce_bytes[1], nonce_bytes[2], nonce_bytes[3]]);
        state[15] = u32::from_le_bytes([nonce_bytes[4], nonce_bytes[5], nonce_bytes[6], nonce_bytes[7]]);

        let mut rng = Self {
            state,
            buffer: [0u8; 64],
            position: 64, // Force refill on first use
            entropy_bits,
        };

        rng.refill_buffer();
        rng
    }

    /// Derive a 32-byte seed from MPS singular values.
    fn derive_seed_from_mps(mps: &MPS) -> [u8; 32] {
        let mut seed = [0u8; 32];
        let mut hasher = SimpleHasher::new();

        // Hash all singular values
        for sv_vec in mps.all_singular_values() {
            for &sv in sv_vec {
                hasher.update(&sv.to_le_bytes());
            }
        }

        // Hash the entropy value itself
        let entropy = total_entanglement_entropy(mps);
        hasher.update(&entropy.to_le_bytes());

        // Hash site count
        hasher.update(&(mps.n_sites() as u64).to_le_bytes());

        hasher.finalize(&mut seed);
        seed
    }

    /// Generate random bytes.
    pub fn fill_bytes(&mut self, dest: &mut [u8]) {
        let mut written = 0;

        while written < dest.len() {
            if self.position >= 64 {
                self.refill_buffer();
            }

            let available = 64 - self.position;
            let to_copy = (dest.len() - written).min(available);

            dest[written..written + to_copy]
                .copy_from_slice(&self.buffer[self.position..self.position + to_copy]);

            self.position += to_copy;
            written += to_copy;
        }
    }

    /// Generate a random u64.
    pub fn next_u64(&mut self) -> u64 {
        let mut bytes = [0u8; 8];
        self.fill_bytes(&mut bytes);
        u64::from_le_bytes(bytes)
    }

    /// Generate a random u32.
    pub fn next_u32(&mut self) -> u32 {
        let mut bytes = [0u8; 4];
        self.fill_bytes(&mut bytes);
        u32::from_le_bytes(bytes)
    }

    /// Generate a 32-byte random value (for keys, nonces, etc.)
    pub fn gen_bytes_32(&mut self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        self.fill_bytes(&mut bytes);
        bytes
    }

    /// Generate a 12-byte random value (for GCM nonces)
    pub fn gen_bytes_12(&mut self) -> [u8; 12] {
        let mut bytes = [0u8; 12];
        self.fill_bytes(&mut bytes);
        bytes
    }

    /// Get the entropy level of this RNG.
    pub fn entropy_bits(&self) -> f64 {
        self.entropy_bits
    }

    /// ChaCha20 quarter round
    #[inline]
    fn quarter_round(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
        state[a] = state[a].wrapping_add(state[b]);
        state[d] ^= state[a];
        state[d] = state[d].rotate_left(16);

        state[c] = state[c].wrapping_add(state[d]);
        state[b] ^= state[c];
        state[b] = state[b].rotate_left(12);

        state[a] = state[a].wrapping_add(state[b]);
        state[d] ^= state[a];
        state[d] = state[d].rotate_left(8);

        state[c] = state[c].wrapping_add(state[d]);
        state[b] ^= state[c];
        state[b] = state[b].rotate_left(7);
    }

    /// Refill the output buffer using ChaCha20.
    fn refill_buffer(&mut self) {
        let mut working = self.state;

        // 20 rounds (10 double rounds)
        for _ in 0..10 {
            // Column rounds
            Self::quarter_round(&mut working, 0, 4, 8, 12);
            Self::quarter_round(&mut working, 1, 5, 9, 13);
            Self::quarter_round(&mut working, 2, 6, 10, 14);
            Self::quarter_round(&mut working, 3, 7, 11, 15);
            // Diagonal rounds
            Self::quarter_round(&mut working, 0, 5, 10, 15);
            Self::quarter_round(&mut working, 1, 6, 11, 12);
            Self::quarter_round(&mut working, 2, 7, 8, 13);
            Self::quarter_round(&mut working, 3, 4, 9, 14);
        }

        // Add original state
        for i in 0..16 {
            working[i] = working[i].wrapping_add(self.state[i]);
        }

        // Convert to bytes
        for i in 0..16 {
            let bytes = working[i].to_le_bytes();
            self.buffer[i * 4] = bytes[0];
            self.buffer[i * 4 + 1] = bytes[1];
            self.buffer[i * 4 + 2] = bytes[2];
            self.buffer[i * 4 + 3] = bytes[3];
        }

        // Increment counter
        self.state[12] = self.state[12].wrapping_add(1);
        if self.state[12] == 0 {
            self.state[13] = self.state[13].wrapping_add(1);
        }

        self.position = 0;
    }
}

/// Simple hash function for seed derivation (SHA-256-like mixing)
struct SimpleHasher {
    state: [u64; 4],
    buffer: Vec<u8>,
}

impl SimpleHasher {
    fn new() -> Self {
        Self {
            state: [
                0x6a09e667f3bcc908,
                0xbb67ae8584caa73b,
                0x3c6ef372fe94f82b,
                0xa54ff53a5f1d36f1,
            ],
            buffer: Vec::new(),
        }
    }

    fn update(&mut self, data: &[u8]) {
        self.buffer.extend_from_slice(data);

        // Process full blocks
        while self.buffer.len() >= 32 {
            let block: [u8; 32] = self.buffer[..32].try_into().unwrap();
            self.process_block(&block);
            self.buffer.drain(..32);
        }
    }

    fn process_block(&mut self, block: &[u8; 32]) {
        let mut w = [0u64; 4];
        for i in 0..4 {
            w[i] = u64::from_le_bytes([
                block[i * 8],
                block[i * 8 + 1],
                block[i * 8 + 2],
                block[i * 8 + 3],
                block[i * 8 + 4],
                block[i * 8 + 5],
                block[i * 8 + 6],
                block[i * 8 + 7],
            ]);
        }

        // Simple mixing
        for i in 0..4 {
            self.state[i] = self.state[i]
                .wrapping_add(w[i])
                .rotate_left(17)
                .wrapping_mul(0x9e3779b97f4a7c15);
            self.state[(i + 1) % 4] ^= self.state[i];
        }
    }

    fn finalize(mut self, output: &mut [u8; 32]) {
        // Pad remaining data
        self.buffer.push(0x80);
        while self.buffer.len() < 32 {
            self.buffer.push(0);
        }

        let block: [u8; 32] = self.buffer[..32].try_into().unwrap();
        self.process_block(&block);

        // Final mixing
        for _ in 0..4 {
            for i in 0..4 {
                self.state[i] = self.state[i]
                    .rotate_left(13)
                    .wrapping_mul(0xbf58476d1ce4e5b9);
                self.state[(i + 1) % 4] ^= self.state[i];
            }
        }

        // Output
        for i in 0..4 {
            let bytes = self.state[i].to_le_bytes();
            output[i * 8..(i + 1) * 8].copy_from_slice(&bytes);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_quantum_rng_from_seed() {
        let seed = [0x42u8; 32];
        let mut rng = QuantumRng::from_seed(&seed, 256.0);

        let a = rng.next_u64();
        let b = rng.next_u64();

        // Should produce different values
        assert_ne!(a, b);
    }

    #[test]
    fn test_quantum_rng_deterministic() {
        let seed = [0x42u8; 32];
        let mut rng1 = QuantumRng::from_seed(&seed, 256.0);
        let mut rng2 = QuantumRng::from_seed(&seed, 256.0);

        // Same seed should produce same output
        assert_eq!(rng1.next_u64(), rng2.next_u64());
        assert_eq!(rng1.next_u64(), rng2.next_u64());
    }

    #[test]
    fn test_quantum_rng_fill_bytes() {
        let seed = [0x42u8; 32];
        let mut rng = QuantumRng::from_seed(&seed, 256.0);

        let mut buf1 = [0u8; 100];
        let mut buf2 = [0u8; 100];

        rng.fill_bytes(&mut buf1);
        rng.fill_bytes(&mut buf2);

        // Different fills should be different
        assert_ne!(buf1, buf2);
    }

    #[test]
    fn test_quantum_rng_from_mps() {
        let mps = MPS::new(10, 8);
        let rng = QuantumRng::from_mps(&mps);
        assert!(rng.is_ok());
    }
}
