//! Cryptographic primitives powered by quantum entropy.
//!
//! This module provides:
//! - **Quantum-seeded RNG**: Random number generation seeded by MPS entanglement entropy
//! - **Symmetric encryption**: AES-256-GCM and ChaCha20-Poly1305 for data at rest
//! - **Key exchange**: Post-quantum key encapsulation for data in transit
//! - **Key derivation**: HKDF for deriving keys from shared secrets
//! - **Memory-hard functions**: Argon2id and Balloon hashing
//! - **Time-lock puzzles**: Sequential work that can't be parallelized
//! - **Quantum Fortress**: Combined hardening for maximum security
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                    QuantumWall Crypto                            │
//! ├─────────────────────────────────────────────────────────────────┤
//! │  Quantum Entropy (MPS)  →  CSPRNG Seed  →  Key Generation       │
//! ├─────────────────────────────────────────────────────────────────┤
//! │                                                                  │
//! │  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐      │
//! │  │  At Rest     │    │  In Transit  │    │  Hardening   │      │
//! │  │  AES-256-GCM │    │  ML-KEM      │    │  Argon2id    │      │
//! │  │  ChaCha20    │    │  X25519      │    │  Balloon     │      │
//! │  └──────────────┘    └──────────────┘    │  Time-lock   │      │
//! │                                          └──────────────┘      │
//! └─────────────────────────────────────────────────────────────────┘
//! ```

pub mod keys;
pub mod rng;
pub mod symmetric;
pub mod kdf;

// Hardening modules for quantum resistance
pub mod argon2;
pub mod balloon;
pub mod timelock;
pub mod fortress;

// Re-exports
pub use keys::{SecretKey, PublicKey, KeyPair, EncryptionKey};
pub use rng::QuantumRng;
pub use symmetric::{encrypt, decrypt, EncryptedData};
pub use kdf::{derive_key, DerivedKey};

// Hardening re-exports
pub use argon2::{Argon2Params, Argon2Key, argon2_hash};
pub use balloon::{BalloonParams, BalloonKey, balloon_hash};
pub use timelock::{TimeLockParams, TimeLockPuzzle, hash_chain_lock};
pub use fortress::{QuantumFortress, FortressConfig, FortressLevel, FortressData, FortressKey};

/// Cryptographic error types
#[derive(Debug, Clone, PartialEq)]
pub enum CryptoError {
    /// Invalid key length
    InvalidKeyLength,
    /// Invalid nonce length
    InvalidNonceLength,
    /// Encryption failed
    EncryptionFailed,
    /// Decryption failed (authentication error)
    DecryptionFailed,
    /// Invalid ciphertext
    InvalidCiphertext,
    /// Key derivation failed
    KeyDerivationFailed,
    /// Insufficient entropy
    InsufficientEntropy,
    /// Key exchange failed
    KeyExchangeFailed,
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CryptoError::InvalidKeyLength => write!(f, "Invalid key length"),
            CryptoError::InvalidNonceLength => write!(f, "Invalid nonce length"),
            CryptoError::EncryptionFailed => write!(f, "Encryption failed"),
            CryptoError::DecryptionFailed => write!(f, "Decryption failed (authentication error)"),
            CryptoError::InvalidCiphertext => write!(f, "Invalid ciphertext"),
            CryptoError::KeyDerivationFailed => write!(f, "Key derivation failed"),
            CryptoError::InsufficientEntropy => write!(f, "Insufficient entropy"),
            CryptoError::KeyExchangeFailed => write!(f, "Key exchange failed"),
        }
    }
}

impl std::error::Error for CryptoError {}

/// Result type for cryptographic operations
pub type CryptoResult<T> = Result<T, CryptoError>;

/// Securely zero memory on drop
pub trait Zeroize {
    fn zeroize(&mut self);
}

impl Zeroize for Vec<u8> {
    fn zeroize(&mut self) {
        for byte in self.iter_mut() {
            unsafe {
                std::ptr::write_volatile(byte, 0);
            }
        }
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    }
}

impl Zeroize for [u8; 32] {
    fn zeroize(&mut self) {
        for byte in self.iter_mut() {
            unsafe {
                std::ptr::write_volatile(byte, 0);
            }
        }
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zeroize_vec() {
        let mut data = vec![1u8, 2, 3, 4, 5];
        data.zeroize();
        assert!(data.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_zeroize_array() {
        let mut data = [0xFFu8; 32];
        data.zeroize();
        assert!(data.iter().all(|&b| b == 0));
    }
}
