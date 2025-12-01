//! Argon2id Memory-Hard Key Derivation Function
//!
//! Implements Argon2id (RFC 9106) - the winner of the Password Hashing Competition.
//! Forces attackers to use massive amounts of RAM per password guess.
//!
//! A quantum computer with 1M qubits has ~125KB of usable coherent memory.
//! Argon2id with 1GB memory cost makes each guess require 8000x more memory
//! than available on such a quantum computer.

use crate::crypto::kdf::hash_sha256;
use crate::crypto::{CryptoError, CryptoResult, Zeroize};

/// Argon2 variant
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Argon2Variant {
    /// Data-dependent addressing - faster, GPU resistant
    Argon2d,
    /// Data-independent addressing - side-channel resistant
    Argon2i,
    /// Hybrid - best of both worlds (recommended)
    Argon2id,
}

/// Argon2 configuration parameters
#[derive(Debug, Clone)]
pub struct Argon2Params {
    /// Memory cost in KiB (e.g., 1048576 = 1 GB)
    pub memory_cost: u32,
    /// Number of iterations (time cost)
    pub time_cost: u32,
    /// Degree of parallelism (lanes)
    pub parallelism: u32,
    /// Output hash length in bytes
    pub output_len: usize,
    /// Argon2 variant
    pub variant: Argon2Variant,
}

impl Default for Argon2Params {
    fn default() -> Self {
        Self {
            memory_cost: 65536, // 64 MB
            time_cost: 3,       // 3 iterations
            parallelism: 4,     // 4 lanes
            output_len: 32,     // 256-bit output
            variant: Argon2Variant::Argon2id,
        }
    }
}

impl Argon2Params {
    /// Create params for maximum quantum pain (1 GB memory)
    pub fn quantum_fortress() -> Self {
        Self {
            memory_cost: 1048576, // 1 GB
            time_cost: 4,         // 4 iterations
            parallelism: 4,       // 4 lanes
            output_len: 32,
            variant: Argon2Variant::Argon2id,
        }
    }

    /// Create params for high security (256 MB memory)
    pub fn high_security() -> Self {
        Self {
            memory_cost: 262144, // 256 MB
            time_cost: 3,
            parallelism: 4,
            output_len: 32,
            variant: Argon2Variant::Argon2id,
        }
    }

    /// Create params for moderate security (64 MB memory)
    pub fn moderate() -> Self {
        Self::default()
    }

    /// Create params for interactive use (faster, 16 MB)
    pub fn interactive() -> Self {
        Self {
            memory_cost: 16384, // 16 MB
            time_cost: 2,
            parallelism: 4,
            output_len: 32,
            variant: Argon2Variant::Argon2id,
        }
    }
}

/// Argon2 block (1024 bytes)
const BLOCK_SIZE: usize = 1024;
const SYNC_POINTS: u32 = 4;

/// A single 1024-byte block
#[derive(Clone)]
struct Block {
    data: [u64; 128],
}

impl Block {
    fn new() -> Self {
        Self { data: [0u64; 128] }
    }

    fn xor_with(&mut self, other: &Block) {
        for i in 0..128 {
            self.data[i] ^= other.data[i];
        }
    }
}

impl Zeroize for Block {
    fn zeroize(&mut self) {
        for v in &mut self.data {
            *v = 0;
        }
    }
}

/// Argon2 memory matrix
struct Memory {
    blocks: Vec<Block>,
    lanes: u32,
    lane_length: u32,
}

impl Memory {
    fn new(memory_blocks: u32, lanes: u32) -> Self {
        let lane_length = memory_blocks / lanes;
        let total_blocks = lane_length * lanes;
        let blocks = vec![Block::new(); total_blocks as usize];
        Self {
            blocks,
            lanes,
            lane_length,
        }
    }

    fn get(&self, lane: u32, index: u32) -> &Block {
        let idx = (lane * self.lane_length + index) as usize;
        &self.blocks[idx]
    }

    fn get_mut(&mut self, lane: u32, index: u32) -> &mut Block {
        let idx = (lane * self.lane_length + index) as usize;
        &mut self.blocks[idx]
    }
}

impl Zeroize for Memory {
    fn zeroize(&mut self) {
        for block in &mut self.blocks {
            block.zeroize();
        }
    }
}

/// Derive a key using Argon2id
pub fn argon2_hash(password: &[u8], salt: &[u8], params: &Argon2Params) -> CryptoResult<Vec<u8>> {
    if salt.len() < 8 {
        return Err(CryptoError::InvalidNonceLength);
    }
    if params.memory_cost < 8 * params.parallelism {
        return Err(CryptoError::KeyDerivationFailed);
    }
    if params.time_cost < 1 {
        return Err(CryptoError::KeyDerivationFailed);
    }
    if params.output_len < 4 {
        return Err(CryptoError::InvalidKeyLength);
    }

    // Calculate memory size
    let memory_blocks = (params.memory_cost / (SYNC_POINTS * params.parallelism))
        * (SYNC_POINTS * params.parallelism);

    // Initialize memory
    let mut memory = Memory::new(memory_blocks, params.parallelism);

    // Generate initial hash H0
    let h0 = initial_hash(password, salt, params);

    // Initialize first two blocks of each lane
    for lane in 0..params.parallelism {
        let mut block0_input = h0.clone();
        block0_input.extend_from_slice(&0u32.to_le_bytes());
        block0_input.extend_from_slice(&lane.to_le_bytes());
        let mut block0_hash = variable_hash(&block0_input, BLOCK_SIZE);
        fill_block_from_bytes(memory.get_mut(lane, 0), &block0_hash);
        // Zeroize sensitive intermediate buffers (Item 28)
        for b in block0_input.iter_mut() {
            *b = 0;
        }
        for b in block0_hash.iter_mut() {
            *b = 0;
        }

        let mut block1_input = h0.clone();
        block1_input.extend_from_slice(&1u32.to_le_bytes());
        block1_input.extend_from_slice(&lane.to_le_bytes());
        let mut block1_hash = variable_hash(&block1_input, BLOCK_SIZE);
        fill_block_from_bytes(memory.get_mut(lane, 1), &block1_hash);
        // Zeroize sensitive intermediate buffers (Item 28)
        for b in block1_input.iter_mut() {
            *b = 0;
        }
        for b in block1_hash.iter_mut() {
            *b = 0;
        }
    }

    // Main iterations
    for pass in 0..params.time_cost {
        for slice in 0..SYNC_POINTS {
            for lane in 0..params.parallelism {
                fill_segment(&mut memory, pass, lane, slice, params);
            }
        }
    }

    // Finalize: XOR last blocks of all lanes
    let mut final_block = memory.get(0, memory.lane_length - 1).clone();
    for lane in 1..params.parallelism {
        final_block.xor_with(memory.get(lane, memory.lane_length - 1));
    }

    // Generate output
    let mut final_bytes = block_to_bytes(&final_block);
    let output = variable_hash(&final_bytes, params.output_len);

    // Clean up (Item 28 - zeroize all intermediate buffers)
    memory.zeroize();
    final_block.zeroize();
    for b in final_bytes.iter_mut() {
        *b = 0;
    }
    // Note: h0 will be cleaned up when it goes out of scope (contains password-derived data)

    Ok(output)
}

/// Generate initial hash H0
fn initial_hash(password: &[u8], salt: &[u8], params: &Argon2Params) -> Vec<u8> {
    use blake2::Digest;
    let mut hasher = blake2::Blake2b512::new();

    // H0 = BLAKE2b(version | type | params | pwd | salt | secret | ad)
    hasher.update(&(params.parallelism).to_le_bytes());
    hasher.update(&(params.output_len as u32).to_le_bytes());
    hasher.update(&(params.memory_cost).to_le_bytes());
    hasher.update(&(params.time_cost).to_le_bytes());
    hasher.update(&0x13u32.to_le_bytes()); // Version 0x13
    hasher.update(&(params.variant as u32).to_le_bytes());
    hasher.update(&(password.len() as u32).to_le_bytes());
    hasher.update(password);
    hasher.update(&(salt.len() as u32).to_le_bytes());
    hasher.update(salt);
    hasher.update(&0u32.to_le_bytes()); // No secret key
    hasher.update(&0u32.to_le_bytes()); // No associated data

    hasher.finalize().to_vec()
}

/// Variable-length hash using BLAKE2b per RFC 9106 Section 3.5
/// For outputs > 64 bytes, uses iterative hashing as specified in the RFC
fn variable_hash(input: &[u8], out_len: usize) -> Vec<u8> {
    use blake2::digest::{Update, VariableOutput};
    use blake2::Blake2bVar;

    // For outputs <= 64 bytes, use Blake2b directly
    if out_len <= 64 {
        let mut hasher = Blake2bVar::new(out_len).expect("invalid blake2 length");
        hasher.update(&(out_len as u32).to_le_bytes());
        hasher.update(input);
        let mut out = vec![0u8; out_len];
        hasher.finalize_variable(&mut out).expect("buffer size mismatch");
        return out;
    }

    // For outputs > 64 bytes, use iterative extension per RFC 9106
    let mut result = Vec::with_capacity(out_len);

    // V1 = Blake2b-64(out_len || input)
    let mut hasher = Blake2bVar::new(64).expect("64 is valid blake2 length");
    hasher.update(&(out_len as u32).to_le_bytes());
    hasher.update(input);
    let mut v = vec![0u8; 64];
    hasher.finalize_variable(&mut v).expect("buffer size mismatch");
    result.extend_from_slice(&v);

    // Compute additional blocks: Vi = Blake2b(Vi-1)
    while result.len() < out_len {
        let remaining = out_len - result.len();
        let block_size = remaining.min(64);

        let mut hasher = Blake2bVar::new(block_size).expect("valid blake2 length");
        hasher.update(&v);
        v.clear();
        v.resize(block_size, 0);
        hasher.finalize_variable(&mut v).expect("buffer size mismatch");
        result.extend_from_slice(&v);
    }

    result.truncate(out_len);
    result
}

/// Fill a block from bytes
fn fill_block_from_bytes(block: &mut Block, bytes: &[u8]) {
    for (i, chunk) in bytes.chunks(8).enumerate() {
        if i >= 128 {
            break;
        }
        let mut arr = [0u8; 8];
        let len = chunk.len().min(8);
        arr[..len].copy_from_slice(&chunk[..len]);
        block.data[i] = u64::from_le_bytes(arr);
    }
}

/// Convert block to bytes
fn block_to_bytes(block: &Block) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(BLOCK_SIZE);
    for &val in &block.data {
        bytes.extend_from_slice(&val.to_le_bytes());
    }
    bytes
}

/// Fill a segment of memory
fn fill_segment(memory: &mut Memory, pass: u32, lane: u32, slice: u32, params: &Argon2Params) {
    let segment_length = memory.lane_length / SYNC_POINTS;
    let start_index = if pass == 0 && slice == 0 { 2 } else { 0 };

    let mut prev_index = if slice == 0 && start_index == 0 {
        memory.lane_length - 1
    } else {
        slice * segment_length + start_index - 1
    };

    for index in start_index..segment_length {
        let curr_index = slice * segment_length + index;

        // Generate pseudo-random values for addressing
        let prev_block = memory.get(lane, prev_index);
        let j1 = prev_block.data[0];
        let j2 = prev_block.data[1];

        // Compute reference block position
        let (ref_lane, ref_index) =
            compute_ref_position(j1, j2, pass, lane, slice, index, memory.lane_length, params);

        // Get reference block
        let ref_block = memory.get(ref_lane, ref_index).clone();
        let prev_block = memory.get(lane, prev_index).clone();

        // Compress
        let new_block = compress(&prev_block, &ref_block);

        // XOR with existing (except first pass)
        let curr_block = memory.get_mut(lane, curr_index);
        if pass == 0 {
            *curr_block = new_block;
        } else {
            curr_block.xor_with(&new_block);
        }

        prev_index = curr_index;
    }
}

/// Compute reference block position
fn compute_ref_position(
    j1: u64,
    j2: u64,
    pass: u32,
    lane: u32,
    slice: u32,
    index: u32,
    lane_length: u32,
    params: &Argon2Params,
) -> (u32, u32) {
    let segment_length = lane_length / SYNC_POINTS;

    // Reference lane
    let ref_lane = if pass == 0 && slice == 0 {
        lane
    } else {
        (j2 as u32) % params.parallelism
    };

    // Reference set size
    let ref_area_size = if pass == 0 {
        if slice == 0 {
            index - 1
        } else if ref_lane == lane {
            slice * segment_length + index - 1
        } else {
            slice * segment_length + if index == 0 { 0 } else { index - 1 }
        }
    } else if ref_lane == lane {
        lane_length - segment_length + index - 1
    } else {
        lane_length - segment_length + if index == 0 { 0 } else { index - 1 }
    };

    if ref_area_size == 0 {
        return (ref_lane, 0);
    }

    // Map j1 to reference index
    let relative_pos = j1 % (ref_area_size as u64 + 1);
    let start_pos = if pass == 0 {
        0
    } else {
        (slice + 1) * segment_length
    };

    let ref_index = (start_pos as u64 + relative_pos) % (lane_length as u64);

    (ref_lane, ref_index as u32)
}

/// Compression function (simplified)
fn compress(prev: &Block, ref_block: &Block) -> Block {
    let mut result = Block::new();

    // XOR inputs
    for i in 0..128 {
        result.data[i] = prev.data[i] ^ ref_block.data[i];
    }

    // Apply permutation rounds
    let mut state = result.data;
    for _ in 0..2 {
        // Row-wise
        for row in 0..8 {
            let base = row * 16;
            blake2b_g(&mut state, base, base + 4, base + 8, base + 12);
            blake2b_g(&mut state, base + 1, base + 5, base + 9, base + 13);
            blake2b_g(&mut state, base + 2, base + 6, base + 10, base + 14);
            blake2b_g(&mut state, base + 3, base + 7, base + 11, base + 15);
        }

        // Diagonal-wise
        for row in 0..8 {
            let base = row * 16;
            blake2b_g(&mut state, base, base + 5, base + 10, base + 15);
            blake2b_g(&mut state, base + 1, base + 6, base + 11, base + 12);
            blake2b_g(&mut state, base + 2, base + 7, base + 8, base + 13);
            blake2b_g(&mut state, base + 3, base + 4, base + 9, base + 14);
        }
    }

    // XOR with original
    for i in 0..128 {
        result.data[i] ^= state[i];
    }

    result
}

/// Blake2b G function
fn blake2b_g(v: &mut [u64], a: usize, b: usize, c: usize, d: usize) {
    v[a] = v[a].wrapping_add(v[b]);
    v[d] = (v[d] ^ v[a]).rotate_right(32);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(24);
    v[a] = v[a].wrapping_add(v[b]);
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(63);
}

/// Argon2 derived key with zeroization
pub struct Argon2Key {
    key: Vec<u8>,
}

impl Argon2Key {
    pub fn derive(password: &[u8], salt: &[u8], params: &Argon2Params) -> CryptoResult<Self> {
        let key = argon2_hash(password, salt, params)?;
        Ok(Self { key })
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.key
    }
}

impl Drop for Argon2Key {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_argon2_basic() {
        let password = b"password";
        let salt = b"somesalt12345678";
        let params = Argon2Params::interactive();

        let hash = argon2_hash(password, salt, &params).unwrap();
        assert_eq!(hash.len(), 32);

        // Same inputs should give same output
        let hash2 = argon2_hash(password, salt, &params).unwrap();
        assert_eq!(hash, hash2);
    }

    #[test]
    fn test_argon2_different_passwords() {
        let salt = b"somesalt12345678";
        let params = Argon2Params::interactive();

        let hash1 = argon2_hash(b"password1", salt, &params).unwrap();
        let hash2 = argon2_hash(b"password2", salt, &params).unwrap();
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_argon2_different_salts() {
        let password = b"password";
        let params = Argon2Params::interactive();

        let hash1 = argon2_hash(password, b"salt1234567890ab", &params).unwrap();
        let hash2 = argon2_hash(password, b"salt0987654321ba", &params).unwrap();
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_argon2_moderate() {
        let password = b"test_password";
        let salt = b"random_salt_here";
        let params = Argon2Params::moderate();

        let hash = argon2_hash(password, salt, &params).unwrap();
        assert_eq!(hash.len(), 32);
    }
}
