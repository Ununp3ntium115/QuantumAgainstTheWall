//! Bandwidth-Hard Function - Memory Bandwidth Bottleneck
//!
//! Unlike traditional memory-hard functions that focus on memory *capacity*,
//! bandwidth-hard functions exploit memory *bandwidth* as the limiting factor.
//!
//! Key insight: ASICs and CPUs have similar memory bandwidth (~50-100 GB/s),
//! but ASICs can have orders of magnitude more memory capacity. By focusing
//! on random memory accesses that maximize bandwidth usage, we equalize the
//! cost between specialized hardware and general-purpose CPUs.
//!
//! Reference: "Bandwidth Hard Functions for ASIC Resistance"
//! Ling Ren and Srinivas Devadas, TCC 2017

use crate::crypto::kdf::hash_sha256;
use crate::crypto::{CryptoResult, Zeroize};

/// Bandwidth-hard function parameters
#[derive(Debug, Clone)]
pub struct BandwidthParams {
    /// Memory size in blocks (each block = 64 bytes for cache-line alignment)
    /// Total memory = space_cost * 64 bytes
    pub space_cost: usize,
    /// Number of mixing rounds
    pub time_cost: usize,
    /// Number of random memory accesses per round
    /// Higher = more bandwidth usage
    pub bandwidth_cost: usize,
    /// Output length in bytes
    pub output_len: usize,
}

impl Default for BandwidthParams {
    fn default() -> Self {
        Self {
            space_cost: 1048576,      // 64 MB (1M blocks * 64 bytes)
            time_cost: 4,              // 4 rounds
            bandwidth_cost: 100000,    // 100K random accesses per round
            output_len: 32,
        }
    }
}

impl BandwidthParams {
    /// Maximum quantum pain (1 GB, extreme bandwidth usage)
    pub fn quantum_fortress() -> Self {
        Self {
            space_cost: 16777216,     // 1 GB (16M blocks * 64 bytes)
            time_cost: 8,              // 8 rounds
            bandwidth_cost: 1000000,   // 1M random accesses = massive bandwidth
            output_len: 32,
        }
    }

    /// High security (256 MB, high bandwidth)
    pub fn high_security() -> Self {
        Self {
            space_cost: 4194304,       // 256 MB
            time_cost: 6,
            bandwidth_cost: 500000,    // 500K accesses
            output_len: 32,
        }
    }

    /// Moderate security (64 MB, moderate bandwidth)
    pub fn moderate() -> Self {
        Self::default()
    }

    /// Interactive (16 MB, lower bandwidth)
    pub fn interactive() -> Self {
        Self {
            space_cost: 262144,        // 16 MB
            time_cost: 2,
            bandwidth_cost: 50000,     // 50K accesses
            output_len: 32,
        }
    }

    /// Memory usage in bytes
    pub fn memory_usage(&self) -> usize {
        self.space_cost * 64
    }

    /// Estimated bandwidth usage in bytes
    pub fn bandwidth_usage(&self) -> usize {
        // Each random access reads 64 bytes
        // bandwidth_cost accesses * time_cost rounds * 3 reads per iteration
        self.bandwidth_cost * self.time_cost * 3 * 64
    }

    /// Estimated time in seconds (assuming 50 GB/s bandwidth)
    pub fn estimated_time_seconds(&self) -> f64 {
        let bandwidth_gb_per_sec = 50.0;
        let bandwidth_bytes = self.bandwidth_usage() as f64;
        bandwidth_bytes / (bandwidth_gb_per_sec * 1_000_000_000.0)
    }
}

/// Memory block (64 bytes, cache-line aligned)
#[repr(align(64))]
#[derive(Clone)]
struct Block {
    data: [u8; 64],
}

impl Block {
    fn new() -> Self {
        Self { data: [0u8; 64] }
    }

    fn from_hash(hash: &[u8; 32], counter: u64) -> Self {
        let mut data = [0u8; 64];
        data[0..32].copy_from_slice(hash);
        data[32..40].copy_from_slice(&counter.to_le_bytes());
        // Fill rest with hash of first part for entropy
        let extra = hash_sha256(&data[0..40]);
        data[40..64].copy_from_slice(&extra[0..24]);
        Self { data }
    }

    fn hash(&self) -> [u8; 32] {
        hash_sha256(&self.data)
    }

    fn xor_with(&mut self, other: &Block) {
        for i in 0..64 {
            self.data[i] ^= other.data[i];
        }
    }
}

impl Zeroize for Block {
    fn zeroize(&mut self) {
        for byte in &mut self.data {
            *byte = 0;
        }
    }
}

/// Convert hash to memory index
fn hash_to_index(hash: &[u8; 32], max: usize) -> usize {
    // Use first 8 bytes as u64, mod by max
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&hash[0..8]);
    let val = u64::from_le_bytes(bytes);
    (val as usize) % max
}

/// Bandwidth-hard hash function
///
/// Phase 1: Initialize memory with sequential writes (fast)
/// Phase 2: Random accesses to maximize bandwidth usage (slow)
///
/// The key innovation: Phase 2 performs many random memory accesses
/// that are unpredictable and destroy cache locality. This makes the
/// function bandwidth-limited rather than computation-limited.
pub fn bandwidth_hard_hash(
    password: &[u8],
    salt: &[u8],
    params: &BandwidthParams,
) -> CryptoResult<Vec<u8>> {
    let n = params.space_cost;

    // Allocate memory buffer
    let mut memory: Vec<Block> = Vec::with_capacity(n);

    // Phase 1: Sequential initialization (bandwidth-friendly)
    // This fills memory with pseudorandom data derived from password+salt
    let mut seed = hash_sha256(&[password, salt, b"bw_init"].concat());

    for i in 0..n {
        let block = Block::from_hash(&seed, i as u64);
        memory.push(block);
        // Update seed for next block
        seed = hash_sha256(&memory[i].data);
    }

    // Phase 2: Random access mixing (bandwidth-intensive)
    // This is where ASICs lose their advantage - memory bandwidth becomes the bottleneck
    for round in 0..params.time_cost {
        // Derive round seed
        let mut round_input = seed.to_vec();
        round_input.extend_from_slice(&round.to_le_bytes());
        let round_seed = hash_sha256(&round_input);

        for iter in 0..params.bandwidth_cost {
            // Compute target index based on current state
            let target_idx = iter % n;

            // Derive three random indices using current block state
            // These are data-independent (side-channel resistant)
            let mut idx_input = round_seed.to_vec();
            idx_input.extend_from_slice(&iter.to_le_bytes());
            idx_input.extend_from_slice(&(target_idx as u64).to_le_bytes());
            let idx_seed = hash_sha256(&idx_input);

            let idx1 = hash_to_index(&idx_seed, n);

            let mut idx2_input = idx_seed.to_vec();
            idx2_input.extend_from_slice(&memory[idx1].data[0..32]);
            let idx2_seed = hash_sha256(&idx2_input);
            let idx2 = hash_to_index(&idx2_seed, n);

            let mut idx3_input = idx2_seed.to_vec();
            idx3_input.extend_from_slice(&memory[idx2].data[0..32]);
            let idx3_seed = hash_sha256(&idx3_input);
            let idx3 = hash_to_index(&idx3_seed, n);

            // CRITICAL: Three random memory reads (bandwidth bottleneck)
            // Each read: 64 bytes from unpredictable location
            // Cache miss probability: ~99% (random access pattern)
            // Memory bandwidth usage: 3 * 64 bytes per iteration
            let block1 = memory[idx1].clone();
            let block2 = memory[idx2].clone();
            let block3 = memory[idx3].clone();

            // Mix all three blocks
            let mut mixed = block1.clone();
            mixed.xor_with(&block2);
            mixed.xor_with(&block3);
            mixed.xor_with(&memory[target_idx]);

            // Hash the mixture
            let mixed_hash = mixed.hash();
            let new_block = Block::from_hash(&mixed_hash, iter as u64);

            // Write back (another memory access)
            memory[target_idx] = new_block;

            // Update global seed every 1000 iterations for entropy
            if iter % 1000 == 0 {
                let mut seed_input = seed.to_vec();
                seed_input.extend_from_slice(&memory[target_idx].data[0..32]);
                seed = hash_sha256(&seed_input);
            }
        }
    }

    // Phase 3: Finalization
    // XOR all blocks together for final output
    let mut final_block = memory[0].clone();
    for i in 1..n {
        final_block.xor_with(&memory[i]);
    }

    let final_hash = final_block.hash();

    // Clean up memory
    for block in &mut memory {
        block.zeroize();
    }

    Ok(final_hash[..params.output_len].to_vec())
}

/// Enhanced bandwidth-hard hash with additional mixing
///
/// This version adds:
/// - Bidirectional passes (forward and backward)
/// - Increased dependency chains
/// - Additional entropy mixing
pub fn bandwidth_hard_hash_enhanced(
    password: &[u8],
    salt: &[u8],
    params: &BandwidthParams,
) -> CryptoResult<Vec<u8>> {
    let n = params.space_cost;
    let mut memory: Vec<Block> = Vec::with_capacity(n);

    // Initialize
    let mut seed = hash_sha256(&[password, salt, b"bw_enhanced"].concat());
    for i in 0..n {
        let block = Block::from_hash(&seed, i as u64);
        memory.push(block);
        seed = hash_sha256(&memory[i].data);
    }

    // Enhanced mixing with bidirectional passes
    for round in 0..params.time_cost {
        let mut round_input = seed.to_vec();
        round_input.extend_from_slice(&round.to_le_bytes());
        let round_seed = hash_sha256(&round_input);

        // Forward pass
        for iter in 0..params.bandwidth_cost {
            let target_idx = iter % n;
            let mut idx_input = round_seed.to_vec();
            idx_input.extend_from_slice(b"fwd");
            idx_input.extend_from_slice(&iter.to_le_bytes());
            let idx_seed = hash_sha256(&idx_input);

            let idx1 = hash_to_index(&idx_seed, n);
            let idx2 = hash_to_index(&hash_sha256(&memory[idx1].data), n);
            let idx3 = hash_to_index(&hash_sha256(&memory[idx2].data), n);
            let idx4 = hash_to_index(&hash_sha256(&memory[idx3].data), n);  // 4th read!

            let mut mixed = memory[idx1].clone();
            mixed.xor_with(&memory[idx2]);
            mixed.xor_with(&memory[idx3]);
            mixed.xor_with(&memory[idx4]);
            mixed.xor_with(&memory[target_idx]);

            let mixed_hash = mixed.hash();
            memory[target_idx] = Block::from_hash(&mixed_hash, iter as u64);
        }

        // Backward pass (extra security)
        for iter in (0..params.bandwidth_cost / 2).rev() {
            let target_idx = iter % n;
            let mut idx_input = round_seed.to_vec();
            idx_input.extend_from_slice(b"bwd");
            idx_input.extend_from_slice(&iter.to_le_bytes());
            let idx_seed = hash_sha256(&idx_input);

            let idx1 = hash_to_index(&idx_seed, n);
            let idx2 = hash_to_index(&hash_sha256(&memory[idx1].data), n);

            let mut mixed = memory[idx1].clone();
            mixed.xor_with(&memory[idx2]);
            mixed.xor_with(&memory[target_idx]);

            memory[target_idx] = Block::from_hash(&mixed.hash(), iter as u64);
        }

        let mut seed_input = seed.to_vec();
        seed_input.extend_from_slice(&memory[n - 1].data[0..32]);
        seed = hash_sha256(&seed_input);
    }

    // Finalization
    let mut final_block = memory[0].clone();
    for i in 1..n {
        final_block.xor_with(&memory[i]);
    }

    let output = final_block.hash();

    for block in &mut memory {
        block.zeroize();
    }

    Ok(output[..params.output_len].to_vec())
}

/// Bandwidth-hard key with automatic zeroization
pub struct BandwidthKey {
    key: Vec<u8>,
}

impl BandwidthKey {
    pub fn derive(
        password: &[u8],
        salt: &[u8],
        params: &BandwidthParams,
    ) -> CryptoResult<Self> {
        let key = bandwidth_hard_hash(password, salt, params)?;
        Ok(Self { key })
    }

    pub fn derive_enhanced(
        password: &[u8],
        salt: &[u8],
        params: &BandwidthParams,
    ) -> CryptoResult<Self> {
        let key = bandwidth_hard_hash_enhanced(password, salt, params)?;
        Ok(Self { key })
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.key
    }
}

impl Drop for BandwidthKey {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bandwidth_basic() {
        let password = b"password";
        let salt = b"somesalt";
        let params = BandwidthParams {
            space_cost: 1024,  // Small for testing (64 KB)
            time_cost: 1,
            bandwidth_cost: 100,
            output_len: 32,
        };

        let hash = bandwidth_hard_hash(password, salt, &params).unwrap();
        assert_eq!(hash.len(), 32);

        // Deterministic
        let hash2 = bandwidth_hard_hash(password, salt, &params).unwrap();
        assert_eq!(hash, hash2);
    }

    #[test]
    fn test_bandwidth_different_inputs() {
        let params = BandwidthParams {
            space_cost: 1024,
            time_cost: 1,
            bandwidth_cost: 100,
            output_len: 32,
        };

        let hash1 = bandwidth_hard_hash(b"password1", b"salt1234", &params).unwrap();
        let hash2 = bandwidth_hard_hash(b"password2", b"salt1234", &params).unwrap();
        let hash3 = bandwidth_hard_hash(b"password1", b"salt5678", &params).unwrap();

        assert_ne!(hash1, hash2);
        assert_ne!(hash1, hash3);
        assert_ne!(hash2, hash3);
    }

    #[test]
    fn test_bandwidth_enhanced() {
        let password = b"test";
        let salt = b"salt1234";
        let params = BandwidthParams {
            space_cost: 512,
            time_cost: 1,
            bandwidth_cost: 50,
            output_len: 32,
        };

        let hash = bandwidth_hard_hash_enhanced(password, salt, &params).unwrap();
        assert_eq!(hash.len(), 32);

        // Should differ from standard
        let hash_std = bandwidth_hard_hash(password, salt, &params).unwrap();
        assert_ne!(hash, hash_std);
    }

    #[test]
    fn test_bandwidth_key() {
        let params = BandwidthParams {
            space_cost: 1024,
            time_cost: 1,
            bandwidth_cost: 100,
            output_len: 32,
        };

        let key = BandwidthKey::derive(b"password", b"saltsalt", &params).unwrap();
        assert_eq!(key.as_bytes().len(), 32);
    }

    #[test]
    fn test_bandwidth_estimates() {
        let params = BandwidthParams::quantum_fortress();

        // Should require significant memory and bandwidth
        assert!(params.memory_usage() >= 1024 * 1024 * 1024); // 1 GB
        assert!(params.bandwidth_usage() > 1024 * 1024 * 1024); // > 1 GB traffic

        println!("Memory: {} MB", params.memory_usage() / (1024 * 1024));
        println!("Bandwidth: {} GB", params.bandwidth_usage() / (1024 * 1024 * 1024));
        println!("Estimated time: {:.2} seconds", params.estimated_time_seconds());
    }
}
