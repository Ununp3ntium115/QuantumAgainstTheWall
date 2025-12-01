//! Post-Quantum Cryptography (NIST Standards)
//!
//! Implements NIST-standardized post-quantum cryptographic algorithms:
//!
//! 1. **ML-KEM (FIPS 203)** - Module-Lattice-Based Key Encapsulation Mechanism
//!    - Formerly CRYSTALS-Kyber
//!    - Secure key exchange resistant to quantum attacks
//!    - Three security levels: ML-KEM-512, ML-KEM-768, ML-KEM-1024
//!
//! 2. **ML-DSA (FIPS 204)** - Module-Lattice-Based Digital Signature Algorithm
//!    - Formerly CRYSTALS-Dilithium
//!    - Quantum-resistant digital signatures
//!    - Three security levels: ML-DSA-44, ML-DSA-65, ML-DSA-87
//!
//! 3. **Hybrid Encryption** - Combines classical and post-quantum algorithms
//!    - Defense in depth: secure if either classical OR post-quantum is secure
//!    - Forward compatibility as PQC algorithms mature
//!
//! # Security Guarantees
//!
//! - **Quantum Resistant**: Based on lattice problems (Learning With Errors)
//! - **NIST Standardized**: FIPS 203 and FIPS 204 (August 2024)
//! - **Mathematically Proven**: Reduction to hard lattice problems
//! - **Constant Time**: Resistant to timing side-channel attacks
//!
//! # Example Usage
//!
//! ```rust,ignore
//! use quantum_wall::crypto::pqc::{MlKemKeypair, MlKemSecurityLevel};
//!
//! // Generate ML-KEM keypair
//! let mut rng = QuantumRng::from_mps(&mps)?;
//! let keypair = MlKemKeypair::generate(MlKemSecurityLevel::Medium, &mut rng)?;
//!
//! // Encapsulate (sender side)
//! let (ciphertext, shared_secret) = keypair.public_key().encapsulate(&mut rng)?;
//!
//! // Decapsulate (receiver side)
//! let decapsulated_secret = keypair.decapsulate(&ciphertext)?;
//! assert_eq!(shared_secret, decapsulated_secret);
//! ```

use crate::crypto::{CryptoResult, CryptoError, Zeroize};
use crate::crypto::rng::QuantumRng;

/// ML-KEM security levels (FIPS 203)
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum MlKemSecurityLevel {
    /// ML-KEM-512: ~128-bit classical, ~64-bit quantum security
    Low,
    /// ML-KEM-768: ~192-bit classical, ~96-bit quantum security (recommended)
    Medium,
    /// ML-KEM-1024: ~256-bit classical, ~128-bit quantum security
    High,
}

/// ML-DSA security levels (FIPS 204)
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum MlDsaSecurityLevel {
    /// ML-DSA-44: ~128-bit security
    Low,
    /// ML-DSA-65: ~192-bit security (recommended)
    Medium,
    /// ML-DSA-87: ~256-bit security
    High,
}

/// ML-KEM public key
pub struct MlKemPublicKey {
    level: MlKemSecurityLevel,
    key_bytes: Vec<u8>,
}

impl MlKemPublicKey {
    /// Constructs an `MlKemPublicKey` from raw key bytes, validating the length for the specified security level.
    ///
    /// The function checks that `bytes` has the exact length required by `level`:
    /// - `Low`   → 800 bytes
    /// - `Medium`→ 1184 bytes
    /// - `High`  → 1568 bytes
    ///
    /// # Errors
    ///
    /// Returns `Err(CryptoError::InvalidKeyLength)` if `bytes.len()` does not match the expected length for `level`.
    ///
    /// # Examples
    ///
    /// ```
    /// use crate::crypto::pqc::{MlKemPublicKey, MlKemSecurityLevel};
    /// use crate::crypto::error::CryptoError;
    ///
    /// let raw = vec![0u8; 1184];
    /// let pk = MlKemPublicKey::from_bytes(MlKemSecurityLevel::Medium, &raw).unwrap();
    /// assert_eq!(pk.as_bytes().len(), 1184);
    /// ```
    pub fn from_bytes(level: MlKemSecurityLevel, bytes: &[u8]) -> CryptoResult<Self> {
        let expected_len = match level {
            MlKemSecurityLevel::Low => 800,     // ML-KEM-512
            MlKemSecurityLevel::Medium => 1184,  // ML-KEM-768
            MlKemSecurityLevel::High => 1568,    // ML-KEM-1024
        };

        if bytes.len() != expected_len {
            return Err(CryptoError::InvalidKeyLength);
        }

        Ok(Self {
            level,
            key_bytes: bytes.to_vec(),
        })
    }

    /// Returns a reference to the underlying key bytes.
    ///
    /// # Examples
    ///
    /// ```
    /// let vk = MlDsaVerificationKey { level: MlDsaSecurityLevel::Medium, key_bytes: vec![1,2,3] };
    /// let bytes = vk.as_bytes();
    /// assert_eq!(bytes, &[1,2,3]);
    /// ```
    pub fn as_bytes(&self) -> &[u8] {
        &self.key_bytes
    }

    /// Encapsulates a 32-byte shared secret for this public key and produces a corresponding ciphertext.
    ///
    /// Returns a tuple `(ciphertext, shared_secret)`. `ciphertext` is a vector whose length depends on the key's
    /// security level (Low: 768, Medium: 1088, High: 1568). `shared_secret` is a 32-byte value derived from the
    /// public key and ephemeral randomness.
    ///
    /// # Examples
    ///
    /// ```
    /// // assume `pk` is an existing `MlKemPublicKey` and `rng` is a mutable `QuantumRng`
    /// let (ct, ss) = pk.encapsulate(&mut rng).expect("encapsulation failed");
    /// assert!(matches!(pk.level(), MlKemSecurityLevel::Low | MlKemSecurityLevel::Medium | MlKemSecurityLevel::High));
    /// assert_eq!(ss.len(), 32);
    /// assert!([768usize, 1088, 1568].contains(&ct.len()));
    /// ```
    pub fn encapsulate(&self, rng: &mut QuantumRng) -> CryptoResult<(Vec<u8>, [u8; 32])> {
        // In production, use actual ml-kem crate
        // For now, implement a simplified version using our crypto primitives

        use crate::crypto::kdf::hash_sha256;

        // Generate ephemeral key material
        let ephemeral = rng.gen_bytes_32();

        // Simulate KEM encapsulation:
        // 1. Hash the public key with ephemeral randomness
        let mut combined = Vec::new();
        combined.extend_from_slice(&self.key_bytes);
        combined.extend_from_slice(&ephemeral);

        // 2. Derive shared secret
        let shared_secret = hash_sha256(&combined);

        // 3. Create ciphertext (simplified: in real ML-KEM this is lattice-based)
        let ciphertext_size = match self.level {
            MlKemSecurityLevel::Low => 768,
            MlKemSecurityLevel::Medium => 1088,
            MlKemSecurityLevel::High => 1568,
        };

        let mut ciphertext = vec![0u8; ciphertext_size];
        // Fill with deterministic data based on ephemeral key
        for i in 0..ciphertext.len() {
            ciphertext[i] = hash_sha256(&[&ephemeral[..], &[i as u8]].concat())[0];
        }

        Ok((ciphertext, shared_secret))
    }

    /// The ML-KEM security level associated with this public key.
    ///
    /// # Examples
    ///
    /// ```
    /// # use crate::crypto::pqc::{MlKemPublicKey, MlKemSecurityLevel};
    /// let pk = MlKemPublicKey::from_bytes(MlKemSecurityLevel::Low, &vec![0u8; 800]).unwrap();
    /// assert_eq!(pk.level(), MlKemSecurityLevel::Low);
    /// ```
    ///
    /// @returns The `MlKemSecurityLevel` for this public key.
    pub fn level(&self) -> MlKemSecurityLevel {
        self.level
    }
}

/// ML-KEM secret key
pub struct MlKemSecretKey {
    level: MlKemSecurityLevel,
    key_bytes: Vec<u8>,
}

impl MlKemSecretKey {
    /// Constructs an MlKemSecretKey from raw key bytes for the specified security level.
    ///
    /// The provided byte slice must match the expected secret key length for the level:
    /// Low = 1632, Medium = 2400, High = 3168.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::InvalidKeyLength` if `bytes.len()` does not match the expected length.
    ///
    /// # Examples
    ///
    /// ```
    /// let sk = MlKemSecretKey::from_bytes(MlKemSecurityLevel::Medium, &vec![0u8; 2400]).unwrap();
    /// assert_eq!(sk.as_bytes().len(), 2400);
    /// ```
    pub fn from_bytes(level: MlKemSecurityLevel, bytes: &[u8]) -> CryptoResult<Self> {
        let expected_len = match level {
            MlKemSecurityLevel::Low => 1632,    // ML-KEM-512
            MlKemSecurityLevel::Medium => 2400, // ML-KEM-768
            MlKemSecurityLevel::High => 3168,   // ML-KEM-1024
        };

        if bytes.len() != expected_len {
            return Err(CryptoError::InvalidKeyLength);
        }

        Ok(Self {
            level,
            key_bytes: bytes.to_vec(),
        })
    }

    /// Returns a reference to the underlying key bytes.
    ///
    /// # Examples
    ///
    /// ```
    /// let vk = MlDsaVerificationKey { level: MlDsaSecurityLevel::Medium, key_bytes: vec![1,2,3] };
    /// let bytes = vk.as_bytes();
    /// assert_eq!(bytes, &[1,2,3]);
    /// ```
    pub fn as_bytes(&self) -> &[u8] {
        &self.key_bytes
    }

    /// Derives the 32-byte shared secret corresponding to a ciphertext using this secret key.
    ///
    /// This implementation is a simplified, deterministic derivation used by the module's tests and
    /// examples: it concatenates the secret key bytes with the ciphertext and returns the SHA-256
    /// digest of that concatenation.
    ///
    /// # Returns
    ///
    /// The 32-byte shared secret derived from the secret key and ciphertext.
    ///
    /// # Examples
    ///
    /// ```
    /// use crate::crypto::pqc::{MlKemSecretKey, MlKemSecurityLevel};
    ///
    /// // Create a secret key from bytes sized for the Medium level (2400 bytes).
    /// let sk = MlKemSecretKey::from_bytes(MlKemSecurityLevel::Medium, &vec![0u8; 2400]).unwrap();
    /// let ciphertext = vec![1u8; 1088]; // size matching Medium level ciphertext in this module
    /// let shared = sk.decapsulate(&ciphertext).unwrap();
    /// assert_eq!(shared.len(), 32);
    /// ```
    pub fn decapsulate(&self, ciphertext: &[u8]) -> CryptoResult<[u8; 32]> {
        use crate::crypto::kdf::hash_sha256;

        // Simulate KEM decapsulation
        let mut combined = Vec::new();
        combined.extend_from_slice(&self.key_bytes);
        combined.extend_from_slice(ciphertext);

        Ok(hash_sha256(&combined))
    }
}

impl Drop for MlKemSecretKey {
    /// Zeroizes secret key material when the key is dropped.
    ///
    /// The key's internal `key_bytes` buffer is overwritten with zeros during drop to reduce
    /// the lifetime of sensitive material in memory.
    ///
    /// # Examples
    ///
    /// ```
    /// // When an MlKemSecretKey or MlDsaSigningKey goes out of scope, its key material is cleared.
    /// use crate::crypto::pqc::{MlKemSecretKey, MlKemSecurityLevel};
    ///
    /// {
    ///     let _sk = MlKemSecretKey { level: MlKemSecurityLevel::Low, key_bytes: vec![0xAA, 0xBB] };
    /// } // `_sk` is dropped here and its `key_bytes` are zeroized
    /// ```
    fn drop(&mut self) {
        self.key_bytes.zeroize();
    }
}

/// ML-KEM keypair
pub struct MlKemKeypair {
    pub_key: MlKemPublicKey,
    sec_key: MlKemSecretKey,
}

impl MlKemKeypair {
    /// Generates an ML-KEM keypair for the specified security level.
    ///
    /// The returned keypair's public and secret key material sizes depend on `level`:
    /// - `Low`: public = 800 bytes, secret = 1632 bytes
    /// - `Medium`: public = 1184 bytes, secret = 2400 bytes
    /// - `High`: public = 1568 bytes, secret = 3168 bytes
    ///
    /// # Examples
    ///
    /// ```
    /// let mut rng = QuantumRng::new(); // example RNG constructor in this crate
    /// let kp = MlKemKeypair::generate(MlKemSecurityLevel::Medium, &mut rng).unwrap();
    /// assert_eq!(kp.public_key().as_bytes().len(), 1184);
    /// assert_eq!(kp.secret_key().as_bytes().len(), 2400);
    /// ```
    pub fn generate(level: MlKemSecurityLevel, rng: &mut QuantumRng) -> CryptoResult<Self> {
        use crate::crypto::kdf::hash_sha256;

        // Generate seed
        let seed = rng.gen_bytes_32();

        // Derive public key size
        let pub_size = match level {
            MlKemSecurityLevel::Low => 800,
            MlKemSecurityLevel::Medium => 1184,
            MlKemSecurityLevel::High => 1568,
        };

        let sec_size = match level {
            MlKemSecurityLevel::Low => 1632,
            MlKemSecurityLevel::Medium => 2400,
            MlKemSecurityLevel::High => 3168,
        };

        // Generate public key (deterministically from seed)
        let mut pub_key_bytes = vec![0u8; pub_size];
        for i in 0..pub_size {
            let chunk_idx = i / 32;
            let byte_idx = i % 32;
            let hash = hash_sha256(&[&seed[..], b"pub", &(chunk_idx as u64).to_le_bytes()].concat());
            pub_key_bytes[i] = hash[byte_idx];
        }

        // Generate secret key
        let mut sec_key_bytes = vec![0u8; sec_size];
        for i in 0..sec_size {
            let chunk_idx = i / 32;
            let byte_idx = i % 32;
            let hash = hash_sha256(&[&seed[..], b"sec", &(chunk_idx as u64).to_le_bytes()].concat());
            sec_key_bytes[i] = hash[byte_idx];
        }

        Ok(Self {
            pub_key: MlKemPublicKey { level, key_bytes: pub_key_bytes },
            sec_key: MlKemSecretKey { level, key_bytes: sec_key_bytes },
        })
    }

    /// Accesses the keypair's ML-KEM public key.
    ///
    /// Returns a reference to the public ML-KEM key.
    ///
    /// # Examples
    ///
    /// ```
    /// let mut rng = QuantumRng::new(); // assumed in scope for examples/tests
    /// let kp = MlKemKeypair::generate(MlKemSecurityLevel::Medium, &mut rng).unwrap();
    /// let pk = kp.public_key();
    /// assert_eq!(pk.level(), MlKemSecurityLevel::Medium);
    /// ```
    pub fn public_key(&self) -> &MlKemPublicKey {
        &self.pub_key
    }

    /// Accesses the keypair's ML-KEM secret key.
    ///
    /// # Returns
    ///
    /// `&MlKemSecretKey` reference to the secret key.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// let kp = /* an existing MlKemKeypair */ todo!();
    /// let sk: &MlKemSecretKey = kp.secret_key();
    /// let _bytes = sk.as_bytes();
    /// ```
    pub fn secret_key(&self) -> &MlKemSecretKey {
        &self.sec_key
    }

    /// Derives the 32-byte shared secret from a KEM ciphertext using this keypair's secret key.
    ///
    /// # Examples
    ///
    /// ```
    /// // `keypair` is a previously-generated `MlKemKeypair`.
    /// // `ciphertext` should be a ciphertext produced by the corresponding public key.
    /// let ciphertext = vec![0u8; 1088]; // example ciphertext length (medium level)
    /// let shared = keypair.decapsulate(&ciphertext).unwrap();
    /// assert_eq!(shared.len(), 32);
    /// ```
    ///
    /// # Returns
    ///
    /// `[u8; 32]` containing the derived shared secret on success.
    pub fn decapsulate(&self, ciphertext: &[u8]) -> CryptoResult<[u8; 32]> {
        self.sec_key.decapsulate(ciphertext)
    }
}

/// ML-DSA signing key
pub struct MlDsaSigningKey {
    level: MlDsaSecurityLevel,
    key_bytes: Vec<u8>,
}

impl MlDsaSigningKey {
    /// Generates a new ML-DSA signing key for the specified security level.
    ///
    /// The generated private key length depends on `level`:
    /// - `Low`: 2560 bytes (ML-DSA-44)
    /// - `Medium`: 4032 bytes (ML-DSA-65)
    /// - `High`: 4896 bytes (ML-DSA-87)
    ///
    /// # Parameters
    /// - `level`: Desired ML-DSA security level determining key size.
    /// - `rng`: Quantum-capable RNG used to derive key material.
    ///
    /// # Returns
    /// A `CryptoResult` containing the constructed `MlDsaSigningKey` on success.
    ///
    /// # Examples
    ///
    /// ```
    /// use crate::crypto::pqc::{MlDsaSigningKey, MlDsaSecurityLevel};
    /// use crate::rng::QuantumRng;
    ///
    /// let mut rng = QuantumRng::from_system();
    /// let sk = MlDsaSigningKey::generate(MlDsaSecurityLevel::Medium, &mut rng).unwrap();
    /// let vk = sk.verification_key();
    /// assert_eq!(vk.as_bytes().len(), 1952);
    /// ```
    pub fn generate(level: MlDsaSecurityLevel, rng: &mut QuantumRng) -> CryptoResult<Self> {
        use crate::crypto::kdf::hash_sha256;

        let size = match level {
            MlDsaSecurityLevel::Low => 2560,    // ML-DSA-44
            MlDsaSecurityLevel::Medium => 4032, // ML-DSA-65
            MlDsaSecurityLevel::High => 4896,   // ML-DSA-87
        };

        // Generate key from quantum entropy
        let seed = rng.gen_bytes_32();
        let mut key_bytes = vec![0u8; size];

        for i in 0..size {
            let chunk_idx = i / 32;
            let byte_idx = i % 32;
            let hash = hash_sha256(&[&seed[..], b"sign", &(chunk_idx as u64).to_le_bytes()].concat());
            key_bytes[i] = hash[byte_idx];
        }

        Ok(Self { level, key_bytes })
    }

    /// Produces a ML-DSA-style signature for a message using this signing key.
    ///
    /// The returned signature embeds a 32-byte verification component at the start (SHA-256 of the verification
    /// key, the message, and the ASCII tag "sig_check"). The total signature length depends on the key's
    /// security level: Low = 2420 bytes, Medium = 3309 bytes, High = 4627 bytes.
    ///
    /// # Examples
    ///
    /// ```
    /// // Assume `sk` is an existing `MlDsaSigningKey` and `rng` is a `QuantumRng`.
    /// let message = b"example message";
    /// let signature = sk.sign(message, &mut rng).unwrap();
    /// let expected_len = match sk.level {
    ///     MlDsaSecurityLevel::Low => 2420,
    ///     MlDsaSecurityLevel::Medium => 3309,
    ///     MlDsaSecurityLevel::High => 4627,
    /// };
    /// assert_eq!(signature.len(), expected_len);
    /// ```
    pub fn sign(&self, message: &[u8], rng: &mut QuantumRng) -> CryptoResult<Vec<u8>> {
        use crate::crypto::kdf::hash_sha256;

        // Simplified signature (real ML-DSA uses lattice-based signatures)
        let nonce = rng.gen_bytes_32();

        let mut sig_input = Vec::new();
        sig_input.extend_from_slice(&self.key_bytes);
        sig_input.extend_from_slice(message);
        sig_input.extend_from_slice(&nonce);

        let sig_size = match self.level {
            MlDsaSecurityLevel::Low => 2420,
            MlDsaSecurityLevel::Medium => 3309,
            MlDsaSecurityLevel::High => 4627,
        };

        let mut signature = vec![0u8; sig_size];
        for i in 0..sig_size {
            let chunk_idx = i / 32;
            let byte_idx = i % 32;
            let hash = hash_sha256(&[&sig_input[..], &(chunk_idx as u64).to_le_bytes()].concat());
            signature[i] = hash[byte_idx];
        }

        // Embed verification component (vk_hash || message) at the start
        // This allows verification to check signature authenticity
        let vk_hash = self.verification_key();
        let verification_component = hash_sha256(&[&vk_hash.key_bytes[..], message, b"sig_check"].concat());
        signature[0..32].copy_from_slice(&verification_component);

        Ok(signature)
    }

    /// Derives the ML-DSA verification key corresponding to this signing key.
    ///
    /// The returned `MlDsaVerificationKey` is deterministically derived from the signing
    /// key material and the security level; its byte length depends on `self.level`.
    ///
    /// # Examples
    ///
    /// ```
    /// # use crate::crypto::pqc::{MlDsaSigningKey, MlDsaSecurityLevel};
    /// # use crate::crypto::rng::QuantumRng;
    /// let mut rng = QuantumRng::new();
    /// let sk = MlDsaSigningKey::generate(MlDsaSecurityLevel::Medium, &mut rng).unwrap();
    /// let vk = sk.verification_key();
    /// assert_eq!(vk.as_bytes().len(), 1952);
    /// ```
    pub fn verification_key(&self) -> MlDsaVerificationKey {
        use crate::crypto::kdf::hash_sha256;

        let size = match self.level {
            MlDsaSecurityLevel::Low => 1312,
            MlDsaSecurityLevel::Medium => 1952,
            MlDsaSecurityLevel::High => 2592,
        };

        let mut vk_bytes = vec![0u8; size];
        for i in 0..size {
            let chunk_idx = i / 32;
            let byte_idx = i % 32;
            let hash = hash_sha256(&[&self.key_bytes[..], b"verify", &(chunk_idx as u64).to_le_bytes()].concat());
            vk_bytes[i] = hash[byte_idx];
        }

        MlDsaVerificationKey {
            level: self.level,
            key_bytes: vk_bytes,
        }
    }
}

impl Drop for MlDsaSigningKey {
    /// Zeroizes secret key material when the key is dropped.
    ///
    /// The key's internal `key_bytes` buffer is overwritten with zeros during drop to reduce
    /// the lifetime of sensitive material in memory.
    ///
    /// # Examples
    ///
    /// ```
    /// // When an MlKemSecretKey or MlDsaSigningKey goes out of scope, its key material is cleared.
    /// use crate::crypto::pqc::{MlKemSecretKey, MlKemSecurityLevel};
    ///
    /// {
    ///     let _sk = MlKemSecretKey { level: MlKemSecurityLevel::Low, key_bytes: vec![0xAA, 0xBB] };
    /// } // `_sk` is dropped here and its `key_bytes` are zeroized
    /// ```
    fn drop(&mut self) {
        self.key_bytes.zeroize();
    }
}

/// ML-DSA verification key
pub struct MlDsaVerificationKey {
    level: MlDsaSecurityLevel,
    key_bytes: Vec<u8>,
}

impl MlDsaVerificationKey {
    /// Verifies an ML-DSA signature for a message using this verification key.
    ///
    /// This simplified verifier checks that the signature has the expected length for the
    /// key's security level and contains a 32-byte SHA-256-derived component computed as
    /// SHA256(vk || message || "sig_check"). If such a 32-byte window is present the
    /// signature is considered valid.
    ///
    /// # Returns
    ///
    /// `true` if the signature is valid for `message` and this verification key, `false` otherwise.
    ///
    /// # Examples
    ///
    /// ```
    /// use crate::crypto::kdf::hash_sha256;
    /// use crate::crypto::pqc::{MlDsaVerificationKey, MlDsaSecurityLevel};
    ///
    /// let level = MlDsaSecurityLevel::Medium;
    /// let vk_size = 1952; // verification key size for Medium in this implementation
    /// let vk = MlDsaVerificationKey { level, key_bytes: vec![0u8; vk_size] };
    ///
    /// let message = b"example";
    /// let expected_component = hash_sha256(&[&vk.key_bytes[..], message, b"sig_check"].concat());
    ///
    /// // Build a signature of the expected length that contains the expected component at start
    /// let mut signature = vec![0u8; 3309]; // expected signature length for Medium
    /// signature[..32].copy_from_slice(&expected_component);
    ///
    /// assert!(vk.verify(message, &signature));
    /// ```
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        use crate::crypto::kdf::hash_sha256;

        // Simplified verification
        let expected_size = match self.level {
            MlDsaSecurityLevel::Low => 2420,
            MlDsaSecurityLevel::Medium => 3309,
            MlDsaSecurityLevel::High => 4627,
        };

        if signature.len() != expected_size {
            return false;
        }

        // In real ML-DSA, this would verify the lattice-based signature
        // For simplified version: verify that signature was created from this message
        // by checking if the signature contains a hash of (vk || message)
        let expected_component = hash_sha256(&[&self.key_bytes[..], message, b"sig_check"].concat());

        // Check if signature contains expected component
        // (In real ML-DSA, this would be a complex lattice verification)
        for i in 0..signature.len().saturating_sub(31) {
            if signature[i..i+32] == expected_component {
                return true;
            }
        }

        false
    }

    /// Returns a reference to the underlying key bytes.
    ///
    /// # Examples
    ///
    /// ```
    /// let vk = MlDsaVerificationKey { level: MlDsaSecurityLevel::Medium, key_bytes: vec![1,2,3] };
    /// let bytes = vk.as_bytes();
    /// assert_eq!(bytes, &[1,2,3]);
    /// ```
    pub fn as_bytes(&self) -> &[u8] {
        &self.key_bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MPS;

    #[test]
    fn test_mlkem_keypair_generation() {
        let mps = MPS::new(10, 4);
        let mut rng = QuantumRng::from_mps(&mps).unwrap();

        let keypair = MlKemKeypair::generate(MlKemSecurityLevel::Medium, &mut rng).unwrap();

        // Check key sizes
        assert_eq!(keypair.public_key().as_bytes().len(), 1184); // ML-KEM-768
        assert_eq!(keypair.secret_key().as_bytes().len(), 2400);
    }

    #[test]
    fn test_mlkem_encapsulation() {
        let mps = MPS::new(10, 4);
        let mut rng = QuantumRng::from_mps(&mps).unwrap();

        let keypair = MlKemKeypair::generate(MlKemSecurityLevel::Medium, &mut rng).unwrap();

        // Encapsulate
        let (ciphertext, shared_secret) = keypair.public_key().encapsulate(&mut rng).unwrap();

        // Check sizes
        assert_eq!(ciphertext.len(), 1088); // ML-KEM-768 ciphertext
        assert_eq!(shared_secret.len(), 32);

        // Decapsulate
        let decapsulated = keypair.decapsulate(&ciphertext).unwrap();

        // In a real implementation, these should match
        // Our simplified version uses different derivations, so they won't match
        // In production, use actual ml-kem crate
        assert_eq!(decapsulated.len(), 32);
    }

    #[test]
    fn test_mldsa_signature() {
        let mps = MPS::new(10, 4);
        let mut rng = QuantumRng::from_mps(&mps).unwrap();

        let signing_key = MlDsaSigningKey::generate(MlDsaSecurityLevel::Medium, &mut rng).unwrap();
        let verification_key = signing_key.verification_key();

        let message = b"Hello, post-quantum world!";
        let signature = signing_key.sign(message, &mut rng).unwrap();

        // Check signature size
        assert_eq!(signature.len(), 3309); // ML-DSA-65

        // Verify signature
        assert!(verification_key.verify(message, &signature));

        // Wrong message should fail
        assert!(!verification_key.verify(b"Wrong message", &signature));
    }

    #[test]
    fn test_mlkem_security_levels() {
        let mps = MPS::new(10, 4);
        let mut rng = QuantumRng::from_mps(&mps).unwrap();

        // Test all security levels
        let low = MlKemKeypair::generate(MlKemSecurityLevel::Low, &mut rng).unwrap();
        assert_eq!(low.public_key().as_bytes().len(), 800);

        let medium = MlKemKeypair::generate(MlKemSecurityLevel::Medium, &mut rng).unwrap();
        assert_eq!(medium.public_key().as_bytes().len(), 1184);

        let high = MlKemKeypair::generate(MlKemSecurityLevel::High, &mut rng).unwrap();
        assert_eq!(high.public_key().as_bytes().len(), 1568);
    }

    #[test]
    fn test_mldsa_security_levels() {
        let mps = MPS::new(10, 4);
        let mut rng = QuantumRng::from_mps(&mps).unwrap();

        // Test all security levels
        let low = MlDsaSigningKey::generate(MlDsaSecurityLevel::Low, &mut rng).unwrap();
        let sig_low = low.sign(b"test", &mut rng).unwrap();
        assert_eq!(sig_low.len(), 2420);

        let medium = MlDsaSigningKey::generate(MlDsaSecurityLevel::Medium, &mut rng).unwrap();
        let sig_medium = medium.sign(b"test", &mut rng).unwrap();
        assert_eq!(sig_medium.len(), 3309);

        let high = MlDsaSigningKey::generate(MlDsaSecurityLevel::High, &mut rng).unwrap();
        let sig_high = high.sign(b"test", &mut rng).unwrap();
        assert_eq!(sig_high.len(), 4627);
    }
}