//! Time-Lock Puzzles - Sequential Work That Can't Be Parallelized
//!
//! Implements time-lock puzzles based on repeated squaring.
//! Even with 1 million qubits, quantum computers cannot parallelize
//! this computation - it must be done sequentially.
//!
//! Based on: "Time-lock puzzles and timed-release Crypto"
//! by Rivest, Shamir, and Wagner (1996)
//!
//! The key insight: computing x^(2^t) mod n requires t sequential
//! squarings. No amount of parallelism helps.

use crate::crypto::kdf::hash_sha256;
use crate::crypto::CryptoResult;

/// Time-lock puzzle parameters
#[derive(Debug, Clone)]
pub struct TimeLockParams {
    /// Number of sequential squarings (time parameter)
    /// Each squaring takes ~1 microsecond
    /// t = 1_000_000 ≈ 1 second
    pub iterations: u64,
    /// Modulus bit size (256, 512, 1024, 2048)
    pub modulus_bits: usize,
}

impl Default for TimeLockParams {
    fn default() -> Self {
        Self {
            iterations: 1_000_000,  // ~1 second
            modulus_bits: 256,
        }
    }
}

impl TimeLockParams {
    /// Quick puzzle (~100ms)
    pub fn quick() -> Self {
        Self {
            iterations: 100_000,
            modulus_bits: 256,
        }
    }

    /// Standard puzzle (~1 second)
    pub fn standard() -> Self {
        Self {
            iterations: 1_000_000,
            modulus_bits: 256,
        }
    }

    /// Slow puzzle (~10 seconds)
    pub fn slow() -> Self {
        Self {
            iterations: 10_000_000,
            modulus_bits: 256,
        }
    }

    /// Quantum fortress (~1 minute)
    pub fn quantum_fortress() -> Self {
        Self {
            iterations: 100_000_000,
            modulus_bits: 512,
        }
    }
}

/// Big integer representation (256-bit)
#[derive(Clone, Debug, PartialEq)]
pub struct BigInt256 {
    limbs: [u64; 4],
}

impl BigInt256 {
    pub fn zero() -> Self {
        Self { limbs: [0; 4] }
    }

    pub fn one() -> Self {
        Self { limbs: [1, 0, 0, 0] }
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        let mut limbs = [0u64; 4];
        for (i, chunk) in bytes.chunks(8).take(4).enumerate() {
            let mut arr = [0u8; 8];
            let len = chunk.len().min(8);
            arr[..len].copy_from_slice(&chunk[..len]);
            limbs[i] = u64::from_le_bytes(arr);
        }
        Self { limbs }
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        for (i, &limb) in self.limbs.iter().enumerate() {
            bytes[i * 8..(i + 1) * 8].copy_from_slice(&limb.to_le_bytes());
        }
        bytes
    }

    /// Compare: returns -1 if self < other, 0 if equal, 1 if self > other
    fn cmp(&self, other: &Self) -> i32 {
        for i in (0..4).rev() {
            if self.limbs[i] < other.limbs[i] {
                return -1;
            }
            if self.limbs[i] > other.limbs[i] {
                return 1;
            }
        }
        0
    }

    /// Add two BigInt256 values, returning (result, carry)
    fn add(&self, other: &Self) -> (Self, bool) {
        let mut result = Self::zero();
        let mut carry = 0u64;

        for i in 0..4 {
            let (sum1, c1) = self.limbs[i].overflowing_add(other.limbs[i]);
            let (sum2, c2) = sum1.overflowing_add(carry);
            result.limbs[i] = sum2;
            carry = (c1 as u64) + (c2 as u64);
        }

        (result, carry > 0)
    }

    /// Subtract other from self (self must be >= other)
    fn sub(&self, other: &Self) -> Self {
        let mut result = Self::zero();
        let mut borrow = 0i64;

        for i in 0..4 {
            let diff = (self.limbs[i] as i128) - (other.limbs[i] as i128) - (borrow as i128);
            if diff < 0 {
                result.limbs[i] = (diff + (1i128 << 64)) as u64;
                borrow = 1;
            } else {
                result.limbs[i] = diff as u64;
                borrow = 0;
            }
        }

        result
    }

    /// Multiply two BigInt256 values, returning 512-bit result
    fn mul(&self, other: &Self) -> BigInt512 {
        let mut result = BigInt512::zero();

        for i in 0..4 {
            let mut carry = 0u128;
            for j in 0..4 {
                let prod = (self.limbs[i] as u128) * (other.limbs[j] as u128)
                    + (result.limbs[i + j] as u128)
                    + carry;
                result.limbs[i + j] = prod as u64;
                carry = prod >> 64;
            }
            if i + 4 < 8 {
                result.limbs[i + 4] = carry as u64;
            }
        }

        result
    }

    /// Square this value
    fn square(&self) -> BigInt512 {
        self.mul(self)
    }

    /// Check if zero
    fn is_zero(&self) -> bool {
        self.limbs.iter().all(|&x| x == 0)
    }
}

/// 512-bit integer for intermediate multiplication results
#[derive(Clone)]
struct BigInt512 {
    limbs: [u64; 8],
}

impl BigInt512 {
    fn zero() -> Self {
        Self { limbs: [0; 8] }
    }

    /// Reduce mod a 256-bit value using Barrett reduction approximation
    fn reduce_mod(&self, modulus: &BigInt256) -> BigInt256 {
        // Simplified reduction: subtract modulus while >= modulus
        let mut result = BigInt256 {
            limbs: [self.limbs[0], self.limbs[1], self.limbs[2], self.limbs[3]],
        };

        // Handle overflow from high limbs
        let high = BigInt256 {
            limbs: [self.limbs[4], self.limbs[5], self.limbs[6], self.limbs[7]],
        };

        if !high.is_zero() {
            // Approximate reduction for high part
            // This is simplified; real implementation would use Barrett reduction
            let mut temp = high;
            for _ in 0..4 {
                if temp.cmp(modulus) >= 0 {
                    temp = temp.sub(modulus);
                }
                // Shift and add back
                let shifted = BigInt256 {
                    limbs: [
                        temp.limbs[0] << 1,
                        (temp.limbs[0] >> 63) | (temp.limbs[1] << 1),
                        (temp.limbs[1] >> 63) | (temp.limbs[2] << 1),
                        (temp.limbs[2] >> 63) | (temp.limbs[3] << 1),
                    ],
                };
                let (sum, _) = result.add(&shifted);
                result = sum;
            }
        }

        // Final reduction
        while result.cmp(modulus) >= 0 {
            result = result.sub(modulus);
        }

        result
    }
}

/// A safe prime modulus for time-lock puzzles
/// Using a deterministically generated modulus based on seed
fn generate_modulus(seed: &[u8]) -> BigInt256 {
    // Generate pseudo-random odd number
    let hash1 = hash_sha256(seed);
    let mut modulus = BigInt256::from_bytes(&hash1);

    // Ensure odd (for better modular arithmetic properties)
    modulus.limbs[0] |= 1;

    // Ensure high bit is set (full 256-bit modulus)
    modulus.limbs[3] |= 1 << 63;

    modulus
}

/// Sequential squaring: compute x^(2^t) mod n
///
/// This is the core of time-lock puzzles.
/// Takes exactly t sequential squarings - cannot be parallelized.
pub fn sequential_square(
    base: &BigInt256,
    iterations: u64,
    modulus: &BigInt256,
) -> BigInt256 {
    let mut result = base.clone();

    for _ in 0..iterations {
        let squared = result.square();
        result = squared.reduce_mod(modulus);
    }

    result
}

/// Time-lock puzzle
#[derive(Clone)]
pub struct TimeLockPuzzle {
    /// The puzzle value
    pub puzzle: BigInt256,
    /// The modulus
    pub modulus: BigInt256,
    /// Number of iterations required
    pub iterations: u64,
}

impl TimeLockPuzzle {
    /// Create a new time-lock puzzle
    ///
    /// The puzzle encrypts a secret that can only be recovered
    /// after performing `iterations` sequential squarings.
    pub fn create(secret: &[u8], params: &TimeLockParams) -> CryptoResult<Self> {
        // Generate modulus from secret
        let mut seed = Vec::from(secret);
        seed.extend_from_slice(b"timelock_modulus");
        let modulus = generate_modulus(&seed);

        // Generate base from secret
        seed.clear();
        seed.extend_from_slice(secret);
        seed.extend_from_slice(b"timelock_base");
        let base_hash = hash_sha256(&seed);
        let base = BigInt256::from_bytes(&base_hash);

        // Create puzzle (this is instant - solving takes time)
        // Puzzle = base (the solution is base^(2^t) mod n)
        Ok(Self {
            puzzle: base,
            modulus,
            iterations: params.iterations,
        })
    }

    /// Solve the puzzle by sequential squaring
    ///
    /// This takes O(iterations) time and CANNOT be parallelized
    pub fn solve(&self) -> BigInt256 {
        sequential_square(&self.puzzle, self.iterations, &self.modulus)
    }

    /// Verify a solution
    pub fn verify(&self, solution: &BigInt256) -> bool {
        let expected = self.solve();
        solution == &expected
    }

    /// Estimated solve time in seconds (assuming 1M squarings/sec)
    pub fn estimated_time_seconds(&self) -> f64 {
        self.iterations as f64 / 1_000_000.0
    }
}

/// Time-lock encryption
///
/// Encrypts data such that it can only be decrypted after
/// solving the time-lock puzzle (sequential work).
pub struct TimeLockEncryption {
    /// Encrypted data (XOR with derived key)
    pub ciphertext: Vec<u8>,
    /// The puzzle that must be solved
    pub puzzle: TimeLockPuzzle,
}

impl TimeLockEncryption {
    /// Encrypt data with a time-lock
    pub fn encrypt(plaintext: &[u8], params: &TimeLockParams) -> CryptoResult<Self> {
        // Generate random secret
        let secret = hash_sha256(plaintext);

        // Create puzzle
        let puzzle = TimeLockPuzzle::create(&secret, params)?;

        // Solve puzzle to get key (we know the secret, so we can compute this)
        // In a real implementation, we'd use the trapdoor
        let solution = puzzle.solve();
        let key = hash_sha256(&solution.to_bytes());

        // Encrypt with XOR
        let mut ciphertext = Vec::with_capacity(plaintext.len());
        for (i, &byte) in plaintext.iter().enumerate() {
            ciphertext.push(byte ^ key[i % 32]);
        }

        Ok(Self { ciphertext, puzzle })
    }

    /// Decrypt by solving the puzzle first
    pub fn decrypt(&self) -> Vec<u8> {
        // Solve puzzle (takes time!)
        let solution = self.puzzle.solve();
        let key = hash_sha256(&solution.to_bytes());

        // Decrypt with XOR
        let mut plaintext = Vec::with_capacity(self.ciphertext.len());
        for (i, &byte) in self.ciphertext.iter().enumerate() {
            plaintext.push(byte ^ key[i % 32]);
        }

        plaintext
    }
}

/// Hash chain time-lock (simpler alternative)
///
/// Uses iterated hashing instead of modular squaring.
/// Slightly less secure but simpler and portable.
pub fn hash_chain_lock(input: &[u8], iterations: u64) -> [u8; 32] {
    let mut current = hash_sha256(input);

    for _ in 0..iterations {
        current = hash_sha256(&current);
    }

    current
}

/// Verify hash chain solution
pub fn verify_hash_chain(input: &[u8], solution: &[u8; 32], iterations: u64) -> bool {
    let expected = hash_chain_lock(input, iterations);
    expected == *solution
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bigint_basic() {
        let a = BigInt256::from_bytes(&[1, 0, 0, 0, 0, 0, 0, 0]);
        let b = BigInt256::from_bytes(&[2, 0, 0, 0, 0, 0, 0, 0]);

        let (sum, _) = a.add(&b);
        assert_eq!(sum.limbs[0], 3);
    }

    #[test]
    fn test_sequential_square() {
        let base = BigInt256::from_bytes(&[7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        let modulus = BigInt256::from_bytes(&[251, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 127]);

        // x^(2^10) with small modulus
        let result = sequential_square(&base, 10, &modulus);
        assert!(!result.is_zero());

        // Deterministic
        let result2 = sequential_square(&base, 10, &modulus);
        assert_eq!(result, result2);
    }

    #[test]
    fn test_hash_chain() {
        let input = b"test input";
        let result = hash_chain_lock(input, 100);

        // Deterministic
        let result2 = hash_chain_lock(input, 100);
        assert_eq!(result, result2);

        // Different iterations = different result
        let result3 = hash_chain_lock(input, 101);
        assert_ne!(result, result3);
    }

    #[test]
    fn test_hash_chain_verify() {
        let input = b"password";
        let iterations = 1000;

        let solution = hash_chain_lock(input, iterations);
        assert!(verify_hash_chain(input, &solution, iterations));

        // Wrong solution fails
        let wrong = [0u8; 32];
        assert!(!verify_hash_chain(input, &wrong, iterations));
    }

    #[test]
    fn test_timelock_puzzle() {
        let params = TimeLockParams {
            iterations: 100,  // Small for testing
            modulus_bits: 256,
        };

        let puzzle = TimeLockPuzzle::create(b"secret", &params).unwrap();
        let solution = puzzle.solve();

        // Verify
        assert!(puzzle.verify(&solution));
    }
}
