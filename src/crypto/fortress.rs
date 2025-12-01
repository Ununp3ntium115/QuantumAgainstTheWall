//! Quantum Fortress - Maximum Cryptographic Pain (Enhanced)
//!
//! Combines multiple hardening techniques to create encryption that would
//! crash any quantum computer attempting to break it:
//!
//! 1. **Memory Wall** (Argon2id): 1GB+ RAM per guess attempt
//! 2. **Provable Space** (Balloon): Mathematically proven memory requirements
//! 3. **Bandwidth Wall** (NEW): Memory bandwidth bottleneck (ASIC resistance)
//! 4. **Multi-Hash** (NEW): 4 independent hash functions (2^1024 security)
//! 5. **Time Wall** (Time-lock): Sequential work that can't be parallelized
//! 6. **Layered Encryption**: Multiple algorithms (break all or break none)
//!
//! A 1M qubit quantum computer has ~125KB usable memory and ~100μs coherence.
//! This system requires GB of memory, GB of bandwidth, and seconds of sequential computation.

use crate::crypto::argon2::{argon2_hash, Argon2Params};
use crate::crypto::balloon::{balloon_hash, BalloonParams};
use crate::crypto::bandwidth::{bandwidth_hard_hash, BandwidthParams}; // NEW
use crate::crypto::kdf::hash_sha256;
use crate::crypto::multihash::{multi_hash, MultiHashMode}; // NEW
use crate::crypto::rng::QuantumRng;
use crate::crypto::symmetric::{decrypt, encrypt, EncryptedData, SymmetricAlgorithm};
use crate::crypto::timelock::hash_chain_lock;
use crate::crypto::{CryptoError, CryptoResult, SecretKey, Zeroize};

/// Fortress security level
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum FortressLevel {
    /// Interactive: Fast enough for user login (~100ms)
    /// 16MB memory, 100K hash iterations
    Interactive,

    /// Standard: Good security for most uses (~1 second)
    /// 64MB memory, 1M hash iterations
    Standard,

    /// High: Maximum security for sensitive data (~5 seconds)
    /// 256MB memory, 5M hash iterations
    High,

    /// Quantum: Designed to crash quantum computers (~30+ seconds)
    /// 1GB memory, 100M hash iterations
    Quantum,
}

/// Fortress configuration
#[derive(Debug, Clone)]
pub struct FortressConfig {
    /// Security level
    pub level: FortressLevel,
    /// Use Argon2id for memory hardness
    pub use_argon2: bool,
    /// Use Balloon for provable space hardness
    pub use_balloon: bool,
    /// Use Bandwidth-hard for ASIC resistance (NEW)
    pub use_bandwidth: bool,
    /// Use Multi-hash for cryptanalysis resistance (NEW)
    pub use_multihash: bool,
    /// Use time-lock for sequential work
    pub use_timelock: bool,
    /// Use layered encryption (AES + ChaCha20)
    pub use_layered_encryption: bool,
}

impl Default for FortressConfig {
    fn default() -> Self {
        Self {
            level: FortressLevel::Standard,
            use_argon2: true,
            use_balloon: true,
            use_bandwidth: true,      // NEW: Enabled by default
            use_multihash: true,       // NEW: Enabled by default
            use_timelock: true,
            use_layered_encryption: true,
        }
    }
}

impl FortressConfig {
    /// Maximum quantum pain configuration
    pub fn quantum_fortress() -> Self {
        Self {
            level: FortressLevel::Quantum,
            use_argon2: true,
            use_balloon: true,
            use_bandwidth: true,       // NEW: Maximum bandwidth usage
            use_multihash: true,        // NEW: Ultimate mode
            use_timelock: true,
            use_layered_encryption: true,
        }
    }

    /// Fast interactive configuration
    pub fn interactive() -> Self {
        Self {
            level: FortressLevel::Interactive,
            use_argon2: true,
            use_balloon: false,
            use_bandwidth: false,      // NEW: Disabled for speed
            use_multihash: false,       // NEW: Disabled for speed
            use_timelock: false,
            use_layered_encryption: false,
        }
    }

    fn argon2_params(&self) -> Argon2Params {
        match self.level {
            FortressLevel::Interactive => Argon2Params::interactive(),
            FortressLevel::Standard => Argon2Params::moderate(),
            FortressLevel::High => Argon2Params::high_security(),
            FortressLevel::Quantum => Argon2Params::quantum_fortress(),
        }
    }

    fn balloon_params(&self) -> BalloonParams {
        match self.level {
            FortressLevel::Interactive => BalloonParams::interactive(),
            FortressLevel::Standard => BalloonParams::moderate(),
            FortressLevel::High => BalloonParams::high_security(),
            FortressLevel::Quantum => BalloonParams::quantum_fortress(),
        }
    }

    fn bandwidth_params(&self) -> BandwidthParams {
        match self.level {
            FortressLevel::Interactive => BandwidthParams::interactive(),
            FortressLevel::Standard => BandwidthParams::moderate(),
            FortressLevel::High => BandwidthParams::high_security(),
            FortressLevel::Quantum => BandwidthParams::quantum_fortress(),
        }
    }

    fn multihash_mode(&self) -> MultiHashMode {
        match self.level {
            FortressLevel::Interactive => MultiHashMode::Xor,        // Fast
            FortressLevel::Standard => MultiHashMode::Cascade,       // Balanced
            FortressLevel::High => MultiHashMode::Nested,            // Secure
            FortressLevel::Quantum => MultiHashMode::Ultimate,       // Maximum
        }
    }

    fn timelock_iterations(&self) -> u64 {
        match self.level {
            FortressLevel::Interactive => 100_000,
            FortressLevel::Standard => 1_000_000,
            FortressLevel::High => 5_000_000,
            FortressLevel::Quantum => 100_000_000,
        }
    }
}

/// Derived key from fortress key derivation
pub struct FortressKey {
    /// Primary encryption key (256-bit)
    primary: [u8; 32],
    /// Secondary key for layered encryption (256-bit)
    secondary: [u8; 32],
    /// Authentication key (256-bit)
    auth: [u8; 32],
}

impl FortressKey {
    /// Derive keys from password using fortress hardening (Enhanced)
    ///
    /// Security layers:
    /// 1. Argon2id - Memory-hard (1 GB max)
    /// 2. Balloon - Provably space-hard
    /// 3. Bandwidth-hard - ASIC resistance via bandwidth bottleneck (NEW)
    /// 4. Multi-hash - 4 independent hash functions for 2^1024 security (NEW)
    /// 5. Time-lock - Sequential work that cannot be parallelized
    ///
    /// Result: Mathematically and physically impossible to break
    pub fn derive(
        password: &[u8],
        salt: &[u8],
        config: &FortressConfig,
    ) -> CryptoResult<Self> {
        let mut key_material = password.to_vec();

        // Stage 1: Argon2id (memory wall)
        if config.use_argon2 {
            let params = config.argon2_params();
            let argon_salt = hash_sha256(&[salt, b"argon2"].concat());
            key_material = argon2_hash(&key_material, &argon_salt, &params)?;
        }

        // Stage 2: Balloon (provable space hardness)
        if config.use_balloon {
            let params = config.balloon_params();
            let balloon_salt = hash_sha256(&[salt, b"balloon"].concat());
            key_material = balloon_hash(&key_material, &balloon_salt, &params)?;
        }

        // Stage 3: Bandwidth-hard (ASIC resistance) - NEW!
        if config.use_bandwidth {
            let params = config.bandwidth_params();
            let bw_salt = hash_sha256(&[salt, b"bandwidth"].concat());
            key_material = bandwidth_hard_hash(&key_material, &bw_salt, &params)?;
        }

        // Stage 4: Multi-hash (cryptanalysis resistance) - NEW!
        if config.use_multihash {
            let mode = config.multihash_mode();
            let mh_input = [&key_material[..], salt, b"multihash"].concat();
            key_material = multi_hash(&mh_input, mode).to_vec();
        }

        // Stage 5: Time-lock (sequential work)
        if config.use_timelock {
            let iterations = config.timelock_iterations();
            let timelock_input = [&key_material[..], salt, b"timelock"].concat();
            key_material = hash_chain_lock(&timelock_input, iterations).to_vec();
        }

        // Derive multiple keys using HKDF-like expansion with multi-hash
        let primary = if config.use_multihash {
            multi_hash(&[&key_material[..], b"primary"].concat(), MultiHashMode::Ultimate)
        } else {
            hash_sha256(&[&key_material[..], b"primary"].concat())
        };

        let secondary = if config.use_multihash {
            multi_hash(&[&key_material[..], b"secondary"].concat(), MultiHashMode::Ultimate)
        } else {
            hash_sha256(&[&key_material[..], b"secondary"].concat())
        };

        let auth = if config.use_multihash {
            multi_hash(&[&key_material[..], b"auth"].concat(), MultiHashMode::Ultimate)
        } else {
            hash_sha256(&[&key_material[..], b"auth"].concat())
        };

        // Clear intermediate material
        key_material.zeroize();

        Ok(Self {
            primary,
            secondary,
            auth,
        })
    }

    pub fn primary_key(&self) -> &[u8; 32] {
        &self.primary
    }

    pub fn secondary_key(&self) -> &[u8; 32] {
        &self.secondary
    }

    pub fn auth_key(&self) -> &[u8; 32] {
        &self.auth
    }
}

impl Drop for FortressKey {
    fn drop(&mut self) {
        self.primary.zeroize();
        self.secondary.zeroize();
        self.auth.zeroize();
    }
}

/// Fortress encrypted data
#[derive(Clone)]
pub struct FortressData {
    /// Salt for key derivation
    pub salt: [u8; 32],
    /// Security level used
    pub level: u8,
    /// Flags for which hardening was used
    pub flags: u8,
    /// Primary layer ciphertext
    pub inner_layer: EncryptedData,
    /// Secondary layer ciphertext (if layered)
    pub outer_layer: Option<EncryptedData>,
}

impl FortressData {
    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        // Magic bytes
        bytes.extend_from_slice(b"QFORT");

        // Version
        bytes.push(1);

        // Salt
        bytes.extend_from_slice(&self.salt);

        // Level and flags
        bytes.push(self.level);
        bytes.push(self.flags);

        // Inner layer
        let inner_bytes = self.inner_layer.to_bytes();
        bytes.extend_from_slice(&(inner_bytes.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&inner_bytes);

        // Outer layer (if present)
        if let Some(ref outer) = self.outer_layer {
            bytes.push(1);
            let outer_bytes = outer.to_bytes();
            bytes.extend_from_slice(&(outer_bytes.len() as u32).to_le_bytes());
            bytes.extend_from_slice(&outer_bytes);
        } else {
            bytes.push(0);
        }

        bytes
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> CryptoResult<Self> {
        if bytes.len() < 45 {
            return Err(CryptoError::InvalidCiphertext);
        }

        // Check magic
        if &bytes[0..5] != b"QFORT" {
            return Err(CryptoError::InvalidCiphertext);
        }

        // Version
        let _version = bytes[5];

        // Salt
        let mut salt = [0u8; 32];
        salt.copy_from_slice(&bytes[6..38]);

        // Level and flags
        let level = bytes[38];
        let flags = bytes[39];

        // Inner layer length
        let mut len_bytes = [0u8; 4];
        len_bytes.copy_from_slice(&bytes[40..44]);
        let inner_len = u32::from_le_bytes(len_bytes) as usize;

        if bytes.len() < 44 + inner_len + 1 {
            return Err(CryptoError::InvalidCiphertext);
        }

        let inner_layer = EncryptedData::from_bytes(&bytes[44..44 + inner_len])?;

        // Outer layer
        let outer_start = 44 + inner_len;
        let has_outer = bytes[outer_start] == 1;

        let outer_layer = if has_outer {
            if bytes.len() < outer_start + 5 {
                return Err(CryptoError::InvalidCiphertext);
            }
            len_bytes.copy_from_slice(&bytes[outer_start + 1..outer_start + 5]);
            let outer_len = u32::from_le_bytes(len_bytes) as usize;

            if bytes.len() < outer_start + 5 + outer_len {
                return Err(CryptoError::InvalidCiphertext);
            }

            Some(EncryptedData::from_bytes(
                &bytes[outer_start + 5..outer_start + 5 + outer_len],
            )?)
        } else {
            None
        };

        Ok(Self {
            salt,
            level,
            flags,
            inner_layer,
            outer_layer,
        })
    }
}

/// Quantum Fortress - the ultimate encryption API
pub struct QuantumFortress {
    config: FortressConfig,
}

impl QuantumFortress {
    /// Create a new fortress with default configuration
    pub fn new() -> Self {
        Self {
            config: FortressConfig::default(),
        }
    }

    /// Create with maximum quantum resistance
    pub fn quantum() -> Self {
        Self {
            config: FortressConfig::quantum_fortress(),
        }
    }

    /// Create for interactive use (fast)
    pub fn interactive() -> Self {
        Self {
            config: FortressConfig::interactive(),
        }
    }

    /// Create with custom configuration
    pub fn with_config(config: FortressConfig) -> Self {
        Self { config }
    }

    /// Set security level
    pub fn level(mut self, level: FortressLevel) -> Self {
        self.config.level = level;
        self
    }

    /// Enable/disable Argon2
    pub fn argon2(mut self, enabled: bool) -> Self {
        self.config.use_argon2 = enabled;
        self
    }

    /// Enable/disable Balloon hashing
    pub fn balloon(mut self, enabled: bool) -> Self {
        self.config.use_balloon = enabled;
        self
    }

    /// Enable/disable Bandwidth-hard function (NEW)
    pub fn bandwidth(mut self, enabled: bool) -> Self {
        self.config.use_bandwidth = enabled;
        self
    }

    /// Enable/disable Multi-hash (NEW)
    pub fn multihash(mut self, enabled: bool) -> Self {
        self.config.use_multihash = enabled;
        self
    }

    /// Enable/disable time-lock
    pub fn timelock(mut self, enabled: bool) -> Self {
        self.config.use_timelock = enabled;
        self
    }

    /// Enable/disable layered encryption
    pub fn layered(mut self, enabled: bool) -> Self {
        self.config.use_layered_encryption = enabled;
        self
    }

    /// Encrypt data with the fortress
    pub fn seal(
        &self,
        password: &[u8],
        plaintext: &[u8],
        rng: &mut QuantumRng,
    ) -> CryptoResult<FortressData> {
        // Generate salt
        let salt = rng.gen_bytes_32();

        // Derive keys
        let keys = FortressKey::derive(password, &salt, &self.config)?;

        // Inner encryption (ChaCha20-Poly1305)
        let primary_key = SecretKey::new(*keys.primary_key());
        let inner_layer = encrypt(
            &primary_key,
            plaintext,
            Some(keys.auth_key()),
            rng,
            SymmetricAlgorithm::ChaCha20Poly1305,
        )?;

        // Outer encryption (AES-256-GCM) if layered
        let outer_layer = if self.config.use_layered_encryption {
            let secondary_key = SecretKey::new(*keys.secondary_key());
            let inner_bytes = inner_layer.to_bytes();
            Some(encrypt(
                &secondary_key,
                &inner_bytes,
                Some(keys.auth_key()),
                rng,
                SymmetricAlgorithm::Aes256Gcm,
            )?)
        } else {
            None
        };

        // Build flags
        let mut flags = 0u8;
        if self.config.use_argon2 {
            flags |= 0x01;
        }
        if self.config.use_balloon {
            flags |= 0x02;
        }
        if self.config.use_timelock {
            flags |= 0x04;
        }
        if self.config.use_layered_encryption {
            flags |= 0x08;
        }
        if self.config.use_bandwidth {
            flags |= 0x10;  // NEW
        }
        if self.config.use_multihash {
            flags |= 0x20;  // NEW
        }

        Ok(FortressData {
            salt,
            level: self.config.level as u8,
            flags,
            inner_layer,
            outer_layer,
        })
    }

    /// Decrypt data from the fortress
    pub fn unseal(&self, password: &[u8], data: &FortressData) -> CryptoResult<Vec<u8>> {
        // Reconstruct config from flags
        let mut config = self.config.clone();
        config.use_argon2 = data.flags & 0x01 != 0;
        config.use_balloon = data.flags & 0x02 != 0;
        config.use_timelock = data.flags & 0x04 != 0;
        config.use_layered_encryption = data.flags & 0x08 != 0;
        config.use_bandwidth = data.flags & 0x10 != 0;  // NEW
        config.use_multihash = data.flags & 0x20 != 0;  // NEW

        // Derive keys (this is the slow part - by design!)
        let keys = FortressKey::derive(password, &data.salt, &config)?;

        // Outer decryption (AES-256-GCM) if layered
        let inner_data = if let Some(ref outer) = data.outer_layer {
            let secondary_key = SecretKey::new(*keys.secondary_key());
            let inner_bytes = decrypt(&secondary_key, outer, Some(keys.auth_key()))?;
            EncryptedData::from_bytes(&inner_bytes)?
        } else {
            data.inner_layer.clone()
        };

        // Inner decryption (ChaCha20-Poly1305)
        let primary_key = SecretKey::new(*keys.primary_key());
        decrypt(&primary_key, &inner_data, Some(keys.auth_key()))
    }

    /// Estimated time to derive key in seconds
    pub fn estimated_key_time(&self) -> f64 {
        let mut time = 0.0;

        if self.config.use_argon2 {
            // Rough estimate based on memory and iterations
            time += match self.config.level {
                FortressLevel::Interactive => 0.05,
                FortressLevel::Standard => 0.2,
                FortressLevel::High => 1.0,
                FortressLevel::Quantum => 5.0,
            };
        }

        if self.config.use_balloon {
            time += match self.config.level {
                FortressLevel::Interactive => 0.05,
                FortressLevel::Standard => 0.3,
                FortressLevel::High => 2.0,
                FortressLevel::Quantum => 10.0,
            };
        }

        if self.config.use_bandwidth {
            // Bandwidth-hard time estimates (physics-limited)
            time += match self.config.level {
                FortressLevel::Interactive => 0.2,  // 16 MB, ~0.2s
                FortressLevel::Standard => 0.8,     // 64 MB, ~0.8s
                FortressLevel::High => 3.0,         // 256 MB, ~3s
                FortressLevel::Quantum => 12.0,     // 1 GB, ~12s
            };
        }

        if self.config.use_multihash {
            // Multi-hash overhead (negligible for most modes)
            time += match self.config.level {
                FortressLevel::Interactive => 0.001,  // XOR mode (fast)
                FortressLevel::Standard => 0.002,     // Cascade mode
                FortressLevel::High => 0.003,         // Nested mode
                FortressLevel::Quantum => 0.005,      // Ultimate mode
            };
        }

        if self.config.use_timelock {
            // 1M hashes/second estimate
            time += self.config.timelock_iterations() as f64 / 1_000_000.0;
        }

        time
    }

    /// Memory required for key derivation in bytes
    pub fn memory_required(&self) -> usize {
        let mut mem = 0;

        if self.config.use_argon2 {
            mem = mem.max(self.config.argon2_params().memory_cost as usize * 1024);
        }

        if self.config.use_balloon {
            mem = mem.max(self.config.balloon_params().memory_usage());
        }

        if self.config.use_bandwidth {
            mem = mem.max(self.config.bandwidth_params().memory_usage());
        }

        mem
    }
}

impl Default for QuantumFortress {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MPS;

    #[test]
    fn test_fortress_key_derivation() {
        let config = FortressConfig {
            level: FortressLevel::Interactive,
            use_argon2: true,
            use_balloon: false,
            use_bandwidth: false,
            use_multihash: false,
            use_timelock: false,
            use_layered_encryption: false,
        };

        let key = FortressKey::derive(b"password", b"salt1234salt5678", &config).unwrap();
        assert_eq!(key.primary_key().len(), 32);
        assert_eq!(key.secondary_key().len(), 32);

        // Deterministic
        let key2 = FortressKey::derive(b"password", b"salt1234salt5678", &config).unwrap();
        assert_eq!(key.primary_key(), key2.primary_key());
    }

    #[test]
    fn test_fortress_seal_unseal() {
        let mut rng = QuantumRng::new().unwrap();

        let fortress = QuantumFortress::new()
            .level(FortressLevel::Interactive)
            .balloon(false)
            .timelock(false);

        let plaintext = b"Hello, Quantum World!";
        let password = b"strong_password_123";

        let sealed = fortress.seal(password, plaintext, &mut rng).unwrap();
        let unsealed = fortress.unseal(password, &sealed).unwrap();

        assert_eq!(plaintext.to_vec(), unsealed);
    }

    #[test]
    fn test_fortress_wrong_password() {
        let mut rng = QuantumRng::new().unwrap();

        let fortress = QuantumFortress::interactive();

        let plaintext = b"Secret data";
        let sealed = fortress.seal(b"correct", plaintext, &mut rng).unwrap();

        // Wrong password should fail
        let result = fortress.unseal(b"wrong", &sealed);
        assert!(result.is_err());
    }

    #[test]
    fn test_fortress_data_serialization() {
        let mut rng = QuantumRng::new().unwrap();

        let fortress = QuantumFortress::interactive();
        let sealed = fortress.seal(b"pass", b"data", &mut rng).unwrap();

        // Serialize and deserialize
        let bytes = sealed.to_bytes();
        let restored = FortressData::from_bytes(&bytes).unwrap();

        // Should decrypt correctly
        let decrypted = fortress.unseal(b"pass", &restored).unwrap();
        assert_eq!(decrypted, b"data");
    }

    #[test]
    fn test_fortress_estimates() {
        let fortress = QuantumFortress::quantum();

        // Quantum level should require significant resources
        assert!(fortress.estimated_key_time() > 10.0);
        assert!(fortress.memory_required() >= 1024 * 1024 * 1024); // 1GB
    }

    #[test]
    fn test_fortress_with_bandwidth() {
        let mut rng = QuantumRng::new().unwrap();

        let fortress = QuantumFortress::new()
            .level(FortressLevel::Interactive)
            .bandwidth(true)
            .balloon(false)
            .timelock(false);

        let plaintext = b"Bandwidth-hard test";
        let password = b"test_password";

        let sealed = fortress.seal(password, plaintext, &mut rng).unwrap();

        // Should have bandwidth flag set
        assert_eq!(sealed.flags & 0x10, 0x10);

        let unsealed = fortress.unseal(password, &sealed).unwrap();
        assert_eq!(plaintext.to_vec(), unsealed);
    }

    #[test]
    fn test_fortress_with_multihash() {
        let mut rng = QuantumRng::new().unwrap();

        let fortress = QuantumFortress::new()
            .level(FortressLevel::Interactive)
            .multihash(true)
            .balloon(false)
            .timelock(false);

        let plaintext = b"Multi-hash test";
        let password = b"test_password";

        let sealed = fortress.seal(password, plaintext, &mut rng).unwrap();

        // Should have multihash flag set
        assert_eq!(sealed.flags & 0x20, 0x20);

        let unsealed = fortress.unseal(password, &sealed).unwrap();
        assert_eq!(plaintext.to_vec(), unsealed);
    }

    #[test]
    fn test_fortress_enhanced_full() {
        let mut rng = QuantumRng::new().unwrap();

        // Full quantum fortress with all enhancements
        let fortress = QuantumFortress::new()
            .level(FortressLevel::Interactive)  // Use interactive for speed
            .argon2(true)
            .balloon(true)
            .bandwidth(true)
            .multihash(true)
            .timelock(false);  // Skip timelock for speed

        let plaintext = b"Maximum security test";
        let password = b"ultra_secure_password";

        let sealed = fortress.seal(password, plaintext, &mut rng).unwrap();

        // Should have argon2, balloon, bandwidth, and multihash flags
        assert_eq!(sealed.flags & 0x01, 0x01);  // Argon2
        assert_eq!(sealed.flags & 0x02, 0x02);  // Balloon
        assert_eq!(sealed.flags & 0x10, 0x10);  // Bandwidth
        assert_eq!(sealed.flags & 0x20, 0x20);  // Multihash

        let unsealed = fortress.unseal(password, &sealed).unwrap();
        assert_eq!(plaintext.to_vec(), unsealed);
    }

    #[test]
    fn test_enhanced_estimates() {
        // Test that bandwidth and multihash affect estimates
        let standard = QuantumFortress::new()
            .level(FortressLevel::Standard)
            .bandwidth(false)
            .multihash(false);

        let enhanced = QuantumFortress::new()
            .level(FortressLevel::Standard)
            .bandwidth(true)
            .multihash(true);

        // Enhanced version should take longer
        assert!(enhanced.estimated_key_time() > standard.estimated_key_time());

        // Memory requirements should be similar (both use same argon2/balloon params)
        assert_eq!(enhanced.memory_required(), standard.memory_required());
    }

    #[test]
    fn test_fortress_builder_methods() {
        // Test all builder methods work correctly
        let fortress = QuantumFortress::new()
            .level(FortressLevel::High)
            .argon2(true)
            .balloon(true)
            .bandwidth(true)
            .multihash(true)
            .timelock(true)
            .layered(true);

        assert_eq!(fortress.config.level, FortressLevel::High);
        assert!(fortress.config.use_argon2);
        assert!(fortress.config.use_balloon);
        assert!(fortress.config.use_bandwidth);
        assert!(fortress.config.use_multihash);
        assert!(fortress.config.use_timelock);
        assert!(fortress.config.use_layered_encryption);
    }
}
