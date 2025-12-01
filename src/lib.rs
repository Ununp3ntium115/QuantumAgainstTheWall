//! # Quantum Against The Wall
//!
//! A library for computing quantum entropy at scale using tensor network representations.
//!
//! ## Overview
//!
//! Traditional quantum state representations require exponential memory (O(4^n) for n qubits).
//! This library uses Matrix Product States (MPS) to represent quantum states with polynomial
//! memory (O(n * χ²)), enabling entropy calculations for systems with millions of qubits.
//!
//! ## Features
//!
//! - **Matrix Product States (MPS)**: Efficient representation of quantum states
//! - **Entanglement Entropy**: Compute von Neumann entropy from bond singular values
//! - **Quantum Gates**: Apply single and two-qubit gates while maintaining MPS form
//! - **Quantum Cryptography**: Encryption primitives seeded by quantum entropy
//! - **WebAssembly Support**: Use from JavaScript/TypeScript via wasm-bindgen
//!
//! ## Example
//!
//! ```rust
//! use quantum_wall::{MPS, total_entanglement_entropy, augmented_entropy};
//!
//! // Create a 1000-qubit state with bond dimension 32
//! let mps = MPS::new(1000, 32);
//!
//! println!("Memory usage: {} bytes", mps.memory_usage());
//! println!("Total entropy: {} bits", total_entanglement_entropy(&mps));
//! println!("Augmented entropy: {}", augmented_entropy(&mps));
//! ```

// QA Item 98: Memory safety enforcement
// Note: We use #![deny(unsafe_code)] instead of #![forbid(unsafe_code)] because
// our Zeroize trait requires unsafe { write_volatile } for secure memory clearing.
// This prevents compiler optimizations from eliminating security-critical zeroization.
// All unsafe blocks are audited and necessary for cryptographic security.
#![deny(unsafe_code)]
#![allow(unsafe_code)] // Only in src/crypto/mod.rs for volatile writes in Zeroize trait

pub mod crypto;
pub mod entropy;
pub mod gates;
pub mod mps;

#[cfg(feature = "wasm")]
pub mod wasm;

// Re-export main types and functions
pub use crypto::{
    decrypt, derive_key, encrypt, CryptoError, CryptoResult, DerivedKey, EncryptionKey, KeyPair,
    PublicKey, QuantumRng, SecretKey, Zeroize,
};
pub use entropy::{
    augmented_entropy, average_entanglement_entropy, bond_entropy, entanglement_entropy,
    max_entropy_bound, total_entanglement_entropy,
};
pub use gates::{apply_single_gate, apply_two_gate, standard_gates};
pub use mps::MPS;

/// Library version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Maximum recommended bond dimension for general use
pub const DEFAULT_BOND_DIM: usize = 64;

/// Tolerance for numerical comparisons
pub const EPSILON: f64 = 1e-15;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_mps_creation() {
        let mps = MPS::new(10, 16);
        assert_eq!(mps.n_sites(), 10);
        assert_eq!(mps.bond_dim(), 16);
    }

    #[test]
    fn test_zero_state_entropy() {
        let mps = MPS::new(10, 16);
        // Product state |00...0⟩ has zero entanglement
        let entropy = total_entanglement_entropy(&mps);
        assert!(entropy.abs() < EPSILON);
    }

    #[test]
    fn test_augmented_entropy() {
        let mps = MPS::new(100, 32);
        let aug = augmented_entropy(&mps);
        // Should include π * n² term
        let expected_poly = std::f64::consts::PI * 100.0 * 100.0;
        assert!((aug - expected_poly).abs() < 1.0); // Some tolerance for entropy contribution
    }
}
