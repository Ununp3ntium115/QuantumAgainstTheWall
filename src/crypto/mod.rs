//! Cryptographic primitives powered by quantum entropy.
//!
//! This module provides:
//! - **Quantum-seeded RNG**: Random number generation seeded by MPS entanglement entropy
//! - **Symmetric encryption**: AES-256-GCM and ChaCha20-Poly1305 for data at rest
//! - **Key exchange**: Post-quantum key encapsulation for data in transit
//! - **Key derivation**: HKDF for deriving keys from shared secrets
//! - **Memory-hard functions**: Argon2id and Balloon hashing
//! - **Bandwidth-hard functions**: Memory bandwidth exploitation for ASIC resistance
//! - **Multi-hash**: Diversified hash functions for cryptanalysis resistance
//! - **Time-lock puzzles**: Sequential work that can't be parallelized
//! - **Quantum Fortress**: Combined hardening for maximum security
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                    QuantumWall Crypto (Enhanced)                 │
//! ├─────────────────────────────────────────────────────────────────┤
//! │  Quantum Entropy (MPS)  →  CSPRNG Seed  →  Key Generation       │
//! ├─────────────────────────────────────────────────────────────────┤
//! │                                                                  │
//! │  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐      │
//! │  │  At Rest     │    │  In Transit  │    │  Hardening   │      │
//! │  │  AES-256-GCM │    │  ML-KEM      │    │  Argon2id    │      │
//! │  │  ChaCha20    │    │  X25519      │    │  Balloon     │      │
//! │  └──────────────┘    └──────────────┘    │  Bandwidth   │      │
//! │                                          │  Multi-Hash  │      │
//! │                                          │  Time-lock   │      │
//! │                                          └──────────────┘      │
//! └─────────────────────────────────────────────────────────────────┘
//! ```

pub mod kdf;
pub mod keys;
pub mod rng;
pub mod symmetric;

// Hardening modules for quantum resistance
pub mod argon2;
pub mod balloon;
pub mod bandwidth; // NEW: Bandwidth-hard functions
pub mod fortress;
pub mod multihash; // NEW: Multi-hash support
pub mod pqc; // NEW: Post-Quantum Cryptography (NIST FIPS 203/204)
pub mod timelock;

// Re-exports
pub use kdf::{derive_key, DerivedKey};
pub use keys::{EncryptionKey, KeyPair, PublicKey, SecretKey};
pub use rng::QuantumRng;
pub use symmetric::{decrypt, encrypt, EncryptedData, SymmetricAlgorithm};

// Hardening re-exports
pub use argon2::{argon2_hash, Argon2Key, Argon2Params};
pub use balloon::{balloon_hash, BalloonKey, BalloonParams};
pub use bandwidth::{bandwidth_hard_hash, BandwidthKey, BandwidthParams}; // NEW
pub use fortress::{FortressConfig, FortressData, FortressKey, FortressLevel, QuantumFortress};
pub use multihash::{multi_hash, multi_hash_kdf, MultiHashKey, MultiHashMode}; // NEW
pub use timelock::{hash_chain_lock, TimeLockParams, TimeLockPuzzle};

// Post-Quantum Cryptography re-exports (NIST standards)
pub use pqc::{
    MlDsaSecurityLevel, MlDsaSigningKey, MlDsaVerificationKey, MlKemKeypair, MlKemPublicKey,
    MlKemSecretKey, MlKemSecurityLevel,
};

/// Cryptographic error types
#[derive(Debug, Clone, PartialEq)]
pub enum CryptoError {
    /// Invalid key length
    InvalidKeyLength,
    /// Invalid nonce length
    InvalidNonceLength,
    /// Invalid salt length (QA Item 27: dedicated error for Argon2 salt validation)
    InvalidSaltLength,
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
    /// Nonce budget exhausted
    NonceExhausted,
    /// Replay detected
    ReplayDetected,
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CryptoError::InvalidKeyLength => write!(f, "Invalid key length"),
            CryptoError::InvalidNonceLength => write!(f, "Invalid nonce length"),
            CryptoError::InvalidSaltLength => {
                write!(f, "Invalid salt length (minimum 8 bytes required)")
            }
            CryptoError::EncryptionFailed => write!(f, "Encryption failed"),
            CryptoError::DecryptionFailed => write!(f, "Decryption failed (authentication error)"),
            CryptoError::InvalidCiphertext => write!(f, "Invalid ciphertext"),
            CryptoError::KeyDerivationFailed => write!(f, "Key derivation failed"),
            CryptoError::InsufficientEntropy => write!(f, "Insufficient entropy"),
            CryptoError::KeyExchangeFailed => write!(f, "Key exchange failed"),
            CryptoError::NonceExhausted => write!(f, "Nonce space exhausted"),
            CryptoError::ReplayDetected => write!(f, "Replay detected"),
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
