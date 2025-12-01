//! WebAssembly bindings for the quantum entropy library.
//!
//! This module provides JavaScript-friendly wrappers around the core
//! Rust functionality, enabling use from web browsers and Node.js.

use wasm_bindgen::prelude::*;

use crate::crypto::symmetric::SymmetricAlgorithm;
use crate::crypto::{self, EncryptedData, QuantumRng, SecretKey};
use crate::entropy;
use crate::gates::{apply_single_gate, standard_gates};
use crate::mps::MPS;

/// Initialize panic hook for better error messages in WASM
#[wasm_bindgen(start)]
pub fn init() {
    #[cfg(feature = "console_error_panic_hook")]
    console_error_panic_hook::set_once();
}

/// A quantum state represented as a Matrix Product State.
///
/// This is the main interface for working with quantum states from JavaScript.
#[wasm_bindgen]
pub struct QuantumState {
    mps: MPS,
}

#[wasm_bindgen]
impl QuantumState {
    /// Create a new quantum state initialized to |00...0⟩
    ///
    /// # Arguments
    /// * `n_qubits` - Number of qubits in the system
    /// * `bond_dim` - Bond dimension (controls accuracy vs memory)
    ///
    /// # Example (JavaScript)
    /// ```js
    /// const state = new QuantumState(1000, 64);
    /// ```
    #[wasm_bindgen(constructor)]
    pub fn new(n_qubits: usize, bond_dim: usize) -> Result<QuantumState, JsError> {
        if n_qubits == 0 {
            return Err(JsError::new("Number of qubits must be positive"));
        }
        if bond_dim == 0 {
            return Err(JsError::new("Bond dimension must be positive"));
        }

        Ok(QuantumState {
            mps: MPS::new(n_qubits, bond_dim),
        })
    }

    /// Create a state initialized to |++...+⟩ (uniform superposition)
    #[wasm_bindgen(js_name = newPlusState)]
    pub fn new_plus_state(n_qubits: usize, bond_dim: usize) -> Result<QuantumState, JsError> {
        if n_qubits == 0 {
            return Err(JsError::new("Number of qubits must be positive"));
        }
        if bond_dim == 0 {
            return Err(JsError::new("Bond dimension must be positive"));
        }

        Ok(QuantumState {
            mps: MPS::new_plus_state(n_qubits, bond_dim),
        })
    }

    /// Get the number of qubits
    #[wasm_bindgen(getter, js_name = nQubits)]
    pub fn n_qubits(&self) -> usize {
        self.mps.n_sites()
    }

    /// Get the bond dimension
    #[wasm_bindgen(getter, js_name = bondDim)]
    pub fn bond_dim(&self) -> usize {
        self.mps.bond_dim()
    }

    /// Get memory usage in bytes
    #[wasm_bindgen(getter, js_name = memoryBytes)]
    pub fn memory_bytes(&self) -> usize {
        self.mps.memory_usage()
    }

    /// Get memory usage in a human-readable format
    #[wasm_bindgen(getter, js_name = memoryString)]
    pub fn memory_string(&self) -> String {
        let bytes = self.mps.memory_usage();
        if bytes < 1024 {
            format!("{} B", bytes)
        } else if bytes < 1024 * 1024 {
            format!("{:.2} KB", bytes as f64 / 1024.0)
        } else if bytes < 1024 * 1024 * 1024 {
            format!("{:.2} MB", bytes as f64 / (1024.0 * 1024.0))
        } else {
            format!("{:.2} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
        }
    }

    /// Compute entanglement entropy at a specific bond
    ///
    /// # Arguments
    /// * `bond` - Bond index (0 to n_qubits - 2)
    ///
    /// # Returns
    /// Entropy in bits
    #[wasm_bindgen(js_name = entropyAtBond)]
    pub fn entropy_at_bond(&self, bond: usize) -> f64 {
        entropy::entanglement_entropy(&self.mps, bond)
    }

    /// Compute total entanglement entropy (sum over all bonds)
    #[wasm_bindgen(js_name = totalEntropy)]
    pub fn total_entropy(&self) -> f64 {
        entropy::total_entanglement_entropy(&self.mps)
    }

    /// Compute average entanglement entropy per bond
    #[wasm_bindgen(js_name = averageEntropy)]
    pub fn average_entropy(&self) -> f64 {
        entropy::average_entanglement_entropy(&self.mps)
    }

    /// Compute maximum entropy at any bond
    #[wasm_bindgen(js_name = maxEntropy)]
    pub fn max_entropy(&self) -> f64 {
        entropy::max_bond_entropy(&self.mps)
    }

    /// Compute augmented entropy: S + π n²
    #[wasm_bindgen(js_name = augmentedEntropy)]
    pub fn augmented_entropy(&self) -> f64 {
        entropy::augmented_entropy(&self.mps)
    }

    /// Get the entropy profile as an array
    #[wasm_bindgen(js_name = entropyProfile)]
    pub fn entropy_profile(&self) -> Vec<f64> {
        entropy::entropy_profile(&self.mps)
    }

    /// Get the maximum possible entropy for this bond dimension
    #[wasm_bindgen(js_name = maxEntropyBound)]
    pub fn max_entropy_bound(&self) -> f64 {
        entropy::max_entropy_bound(self.mps.bond_dim(), self.mps.n_sites())
    }

    /// Apply a Hadamard gate to a qubit
    #[wasm_bindgen]
    pub fn hadamard(&mut self, site: usize) -> Result<(), JsError> {
        if site >= self.mps.n_sites() {
            return Err(JsError::new(&format!(
                "Site {} out of bounds (max {})",
                site,
                self.mps.n_sites() - 1
            )));
        }
        apply_single_gate(&mut self.mps, site, &standard_gates::hadamard());
        Ok(())
    }

    /// Apply a Pauli-X (NOT) gate to a qubit
    #[wasm_bindgen(js_name = pauliX)]
    pub fn pauli_x(&mut self, site: usize) -> Result<(), JsError> {
        if site >= self.mps.n_sites() {
            return Err(JsError::new(&format!(
                "Site {} out of bounds (max {})",
                site,
                self.mps.n_sites() - 1
            )));
        }
        apply_single_gate(&mut self.mps, site, &standard_gates::pauli_x());
        Ok(())
    }

    /// Apply a Pauli-Y gate to a qubit
    #[wasm_bindgen(js_name = pauliY)]
    pub fn pauli_y(&mut self, site: usize) -> Result<(), JsError> {
        if site >= self.mps.n_sites() {
            return Err(JsError::new(&format!(
                "Site {} out of bounds (max {})",
                site,
                self.mps.n_sites() - 1
            )));
        }
        apply_single_gate(&mut self.mps, site, &standard_gates::pauli_y());
        Ok(())
    }

    /// Apply a Pauli-Z gate to a qubit
    #[wasm_bindgen(js_name = pauliZ)]
    pub fn pauli_z(&mut self, site: usize) -> Result<(), JsError> {
        if site >= self.mps.n_sites() {
            return Err(JsError::new(&format!(
                "Site {} out of bounds (max {})",
                site,
                self.mps.n_sites() - 1
            )));
        }
        apply_single_gate(&mut self.mps, site, &standard_gates::pauli_z());
        Ok(())
    }

    /// Apply an S (phase) gate to a qubit
    #[wasm_bindgen(js_name = sGate)]
    pub fn s_gate(&mut self, site: usize) -> Result<(), JsError> {
        if site >= self.mps.n_sites() {
            return Err(JsError::new(&format!(
                "Site {} out of bounds (max {})",
                site,
                self.mps.n_sites() - 1
            )));
        }
        apply_single_gate(&mut self.mps, site, &standard_gates::s_gate());
        Ok(())
    }

    /// Apply a T gate to a qubit
    #[wasm_bindgen(js_name = tGate)]
    pub fn t_gate(&mut self, site: usize) -> Result<(), JsError> {
        if site >= self.mps.n_sites() {
            return Err(JsError::new(&format!(
                "Site {} out of bounds (max {})",
                site,
                self.mps.n_sites() - 1
            )));
        }
        apply_single_gate(&mut self.mps, site, &standard_gates::t_gate());
        Ok(())
    }

    /// Apply Rx rotation gate
    #[wasm_bindgen]
    pub fn rx(&mut self, site: usize, theta: f64) -> Result<(), JsError> {
        if site >= self.mps.n_sites() {
            return Err(JsError::new(&format!(
                "Site {} out of bounds (max {})",
                site,
                self.mps.n_sites() - 1
            )));
        }
        apply_single_gate(&mut self.mps, site, &standard_gates::rx(theta));
        Ok(())
    }

    /// Apply Ry rotation gate
    #[wasm_bindgen]
    pub fn ry(&mut self, site: usize, theta: f64) -> Result<(), JsError> {
        if site >= self.mps.n_sites() {
            return Err(JsError::new(&format!(
                "Site {} out of bounds (max {})",
                site,
                self.mps.n_sites() - 1
            )));
        }
        apply_single_gate(&mut self.mps, site, &standard_gates::ry(theta));
        Ok(())
    }

    /// Apply Rz rotation gate
    #[wasm_bindgen]
    pub fn rz(&mut self, site: usize, theta: f64) -> Result<(), JsError> {
        if site >= self.mps.n_sites() {
            return Err(JsError::new(&format!(
                "Site {} out of bounds (max {})",
                site,
                self.mps.n_sites() - 1
            )));
        }
        apply_single_gate(&mut self.mps, site, &standard_gates::rz(theta));
        Ok(())
    }

    /// Apply Hadamard gates to all qubits
    #[wasm_bindgen(js_name = hadamardAll)]
    pub fn hadamard_all(&mut self) {
        let h = standard_gates::hadamard();
        for site in 0..self.mps.n_sites() {
            apply_single_gate(&mut self.mps, site, &h);
        }
    }

    /// Get a string representation of the state
    #[wasm_bindgen(js_name = toString)]
    pub fn to_string(&self) -> String {
        format!(
            "QuantumState(n={}, χ={}, mem={})",
            self.mps.n_sites(),
            self.mps.bond_dim(),
            self.memory_string()
        )
    }
}

/// Compute entropy from a histogram of counts.
///
/// This is useful for classical entropy calculations.
///
/// # Arguments
/// * `counts` - Array of counts for each bin
///
/// # Returns
/// Shannon entropy in bits
#[wasm_bindgen(js_name = shannonEntropyFromCounts)]
pub fn shannon_entropy_from_counts(counts: &[u64]) -> f64 {
    let total: u64 = counts.iter().sum();
    if total == 0 {
        return 0.0;
    }

    let total_f64 = total as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / total_f64;
            -p * p.log2()
        })
        .sum()
}

/// Get the library version
#[wasm_bindgen(js_name = getVersion)]
pub fn get_version() -> String {
    crate::VERSION.to_string()
}

/// Calculate memory requirements for a given system size
///
/// # Arguments
/// * `n_qubits` - Number of qubits
/// * `bond_dim` - Bond dimension
///
/// # Returns
/// Approximate memory in bytes
#[wasm_bindgen(js_name = estimateMemory)]
pub fn estimate_memory(n_qubits: usize, bond_dim: usize) -> usize {
    // Each tensor is roughly bond_dim * 2 * bond_dim * 16 bytes
    // Plus some overhead for singular values
    let tensor_size = bond_dim * 2 * bond_dim * 16;
    let sv_size = bond_dim * 8;
    n_qubits * tensor_size + (n_qubits - 1) * sv_size
}

// ============================================================================
// Cryptography WASM Bindings
// ============================================================================

/// A quantum-seeded cryptographically secure RNG.
#[wasm_bindgen]
pub struct CryptoRng {
    rng: QuantumRng,
}

#[wasm_bindgen]
impl CryptoRng {
    /// Create a new RNG seeded from a quantum state.
    ///
    /// The entropy from the MPS entanglement structure is used to seed
    /// a ChaCha20-based CSPRNG.
    #[wasm_bindgen(js_name = fromQuantumState)]
    pub fn from_quantum_state(state: &QuantumState) -> Result<CryptoRng, JsError> {
        QuantumRng::from_mps(&state.mps)
            .map(|rng| CryptoRng { rng })
            .map_err(|e| JsError::new(&format!("Failed to create RNG: {}", e)))
    }

    /// Create a new RNG from a 32-byte seed.
    #[wasm_bindgen(js_name = fromSeed)]
    pub fn from_seed(seed: &[u8]) -> Result<CryptoRng, JsError> {
        if seed.len() != 32 {
            return Err(JsError::new("Seed must be exactly 32 bytes"));
        }
        let mut seed_arr = [0u8; 32];
        seed_arr.copy_from_slice(seed);
        QuantumRng::from_seed(&seed_arr, 256)
            .map(|rng| CryptoRng { rng })
            .map_err(|e| JsError::new(&format!("Failed to create RNG: {}", e)))
    }

    /// Generate random bytes.
    #[wasm_bindgen(js_name = randomBytes)]
    pub fn random_bytes(&mut self, len: usize) -> Vec<u8> {
        let mut bytes = vec![0u8; len];
        self.rng.fill_bytes(&mut bytes);
        bytes
    }

    /// Get the entropy bits used to seed this RNG.
    #[wasm_bindgen(getter, js_name = entropyBits)]
    pub fn entropy_bits(&self) -> f64 {
        self.rng.entropy_bits() as f64
    }
}

/// Encrypted data container for WASM.
#[wasm_bindgen]
pub struct EncryptedPayload {
    data: EncryptedData,
}

#[wasm_bindgen]
impl EncryptedPayload {
    /// Get the ciphertext bytes.
    #[wasm_bindgen(getter)]
    pub fn ciphertext(&self) -> Vec<u8> {
        self.data.ciphertext.clone()
    }

    /// Get the nonce bytes.
    #[wasm_bindgen(getter)]
    pub fn nonce(&self) -> Vec<u8> {
        self.data.nonce.to_vec()
    }

    /// Get the authentication tag bytes.
    #[wasm_bindgen(getter)]
    pub fn tag(&self) -> Vec<u8> {
        self.data.tag.to_vec()
    }

    /// Get the algorithm name.
    #[wasm_bindgen(getter)]
    pub fn algorithm(&self) -> String {
        format!("{:?}", self.data.algorithm)
    }

    /// Serialize to bytes for storage/transmission.
    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.data.to_bytes()
    }

    /// Deserialize from bytes.
    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(bytes: &[u8]) -> Result<EncryptedPayload, JsError> {
        EncryptedData::from_bytes(bytes)
            .map(|data| EncryptedPayload { data })
            .map_err(|e| JsError::new(&format!("Failed to parse encrypted data: {}", e)))
    }
}

/// Symmetric encryption interface for WASM.
#[wasm_bindgen]
pub struct SymmetricCrypto {
    key: SecretKey,
    rng: QuantumRng,
}

#[wasm_bindgen]
impl SymmetricCrypto {
    /// Create a new symmetric encryption context with a quantum-seeded key.
    #[wasm_bindgen(js_name = fromQuantumState)]
    pub fn from_quantum_state(state: &QuantumState) -> Result<SymmetricCrypto, JsError> {
        let mut rng = QuantumRng::from_mps(&state.mps)
            .map_err(|e| JsError::new(&format!("Failed to create RNG: {}", e)))?;
        let key = SecretKey::generate(&mut rng);
        Ok(SymmetricCrypto { key, rng })
    }

    /// Create a new symmetric encryption context from a 32-byte key.
    #[wasm_bindgen(js_name = fromKey)]
    pub fn from_key(key_bytes: &[u8], seed: &[u8]) -> Result<SymmetricCrypto, JsError> {
        if key_bytes.len() != 32 {
            return Err(JsError::new("Key must be exactly 32 bytes"));
        }
        if seed.len() != 32 {
            return Err(JsError::new("Seed must be exactly 32 bytes"));
        }

        let mut key_arr = [0u8; 32];
        key_arr.copy_from_slice(key_bytes);
        let key = SecretKey::new(key_arr);

        let mut seed_arr = [0u8; 32];
        seed_arr.copy_from_slice(seed);
        let rng = QuantumRng::from_seed(&seed_arr, 256)
            .map_err(|e| JsError::new(&format!("Failed to create RNG: {}", e)))?;

        Ok(SymmetricCrypto { key, rng })
    }

    /// Get the encryption key bytes.
    ///
    /// WARNING: Handle with care - this exposes the raw key material.
    #[wasm_bindgen(js_name = keyBytes)]
    pub fn key_bytes(&self) -> Vec<u8> {
        self.key.as_bytes().to_vec()
    }

    /// Encrypt data using AES-256-GCM.
    #[wasm_bindgen(js_name = encryptAesGcm)]
    pub fn encrypt_aes_gcm(&mut self, plaintext: &[u8]) -> Result<EncryptedPayload, JsError> {
        crypto::encrypt(
            &self.key,
            plaintext,
            None,
            &mut self.rng,
            SymmetricAlgorithm::Aes256Gcm,
        )
        .map(|data| EncryptedPayload { data })
        .map_err(|e| JsError::new(&format!("Encryption failed: {}", e)))
    }

    /// Encrypt data using ChaCha20-Poly1305.
    #[wasm_bindgen(js_name = encryptChaCha20)]
    pub fn encrypt_chacha20(&mut self, plaintext: &[u8]) -> Result<EncryptedPayload, JsError> {
        crypto::encrypt(
            &self.key,
            plaintext,
            None,
            &mut self.rng,
            SymmetricAlgorithm::ChaCha20Poly1305,
        )
        .map(|data| EncryptedPayload { data })
        .map_err(|e| JsError::new(&format!("Encryption failed: {}", e)))
    }

    /// Encrypt data with additional authenticated data (AAD).
    #[wasm_bindgen(js_name = encryptWithAad)]
    pub fn encrypt_with_aad(
        &mut self,
        plaintext: &[u8],
        aad: &[u8],
        algorithm: &str,
    ) -> Result<EncryptedPayload, JsError> {
        let algo = match algorithm {
            "aes-256-gcm" | "aes" | "AES" => SymmetricAlgorithm::Aes256Gcm,
            "chacha20-poly1305" | "chacha20" | "ChaCha20" => SymmetricAlgorithm::ChaCha20Poly1305,
            _ => {
                return Err(JsError::new(
                    "Unknown algorithm. Use 'aes-256-gcm' or 'chacha20-poly1305'",
                ))
            }
        };

        crypto::encrypt(&self.key, plaintext, Some(aad), &mut self.rng, algo)
            .map(|data| EncryptedPayload { data })
            .map_err(|e| JsError::new(&format!("Encryption failed: {}", e)))
    }

    /// Decrypt data.
    #[wasm_bindgen]
    pub fn decrypt(&self, encrypted: &EncryptedPayload) -> Result<Vec<u8>, JsError> {
        crypto::decrypt(&self.key, &encrypted.data, None)
            .map_err(|e| JsError::new(&format!("Decryption failed: {}", e)))
    }

    /// Decrypt data with additional authenticated data (AAD).
    #[wasm_bindgen(js_name = decryptWithAad)]
    pub fn decrypt_with_aad(
        &self,
        encrypted: &EncryptedPayload,
        aad: &[u8],
    ) -> Result<Vec<u8>, JsError> {
        crypto::decrypt(&self.key, &encrypted.data, Some(aad))
            .map_err(|e| JsError::new(&format!("Decryption failed: {}", e)))
    }
}

/// Derive a key using HKDF.
///
/// # Arguments
/// * `input_key` - Input keying material
/// * `salt` - Optional salt (can be empty)
/// * `info` - Context/application-specific info
///
/// # Returns
/// A 32-byte derived key
#[wasm_bindgen(js_name = deriveKey)]
pub fn derive_key(input_key: &[u8], salt: &[u8], info: &[u8]) -> Result<Vec<u8>, JsError> {
    crypto::derive_key(input_key, salt, info)
        .map(|k| k.as_bytes().to_vec())
        .map_err(|e| JsError::new(&format!("Key derivation failed: {}", e)))
}

/// Hash data with SHA-256.
#[wasm_bindgen(js_name = sha256)]
pub fn sha256(data: &[u8]) -> Vec<u8> {
    crypto::kdf::hash_sha256(data).to_vec()
}

// ============================================================================
// Quantum Fortress WASM Bindings
// ============================================================================

use crate::crypto::argon2::{argon2_hash, Argon2Params};
use crate::crypto::balloon::{balloon_hash, BalloonParams};
use crate::crypto::fortress::FortressLevel;
use crate::crypto::timelock::hash_chain_lock;

/// Quantum Fortress - maximum cryptographic hardening
#[wasm_bindgen]
pub struct Fortress {
    level: FortressLevel,
    use_argon2: bool,
    use_balloon: bool,
    use_timelock: bool,
}

#[wasm_bindgen]
impl Fortress {
    /// Create a new Fortress with interactive settings (fast)
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self {
            level: FortressLevel::Interactive,
            use_argon2: true,
            use_balloon: false,
            use_timelock: false,
        }
    }

    /// Create with standard security
    #[wasm_bindgen(js_name = standard)]
    pub fn standard() -> Self {
        Self {
            level: FortressLevel::Standard,
            use_argon2: true,
            use_balloon: true,
            use_timelock: true,
        }
    }

    /// Create with maximum quantum resistance
    #[wasm_bindgen(js_name = quantum)]
    pub fn quantum() -> Self {
        Self {
            level: FortressLevel::Quantum,
            use_argon2: true,
            use_balloon: true,
            use_timelock: true,
        }
    }

    /// Hash a password using the Fortress pipeline
    /// Returns hex-encoded hash
    #[wasm_bindgen(js_name = hashPassword)]
    pub fn hash_password(&self, password: &str, salt: &str) -> Result<String, JsError> {
        let password_bytes = password.as_bytes();
        let salt_bytes = salt.as_bytes();

        // Ensure salt is at least 16 bytes
        let mut full_salt = [0u8; 32];
        let salt_hash = crypto::kdf::hash_sha256(salt_bytes);
        full_salt.copy_from_slice(&salt_hash);

        let mut result = password_bytes.to_vec();

        // Stage 1: Argon2id
        if self.use_argon2 {
            let params = match self.level {
                FortressLevel::Interactive => Argon2Params::interactive(),
                FortressLevel::Standard => Argon2Params::moderate(),
                FortressLevel::High => Argon2Params::high_security(),
                FortressLevel::Quantum => Argon2Params {
                    memory_cost: 262144, // 256MB for WASM (limited)
                    time_cost: 4,
                    parallelism: 1,
                    output_len: 32,
                    variant: crate::crypto::argon2::Argon2Variant::Argon2id,
                },
            };
            result = argon2_hash(&result, &full_salt, &params)
                .map_err(|e| JsError::new(&format!("Argon2 failed: {}", e)))?;
        }

        // Stage 2: Balloon hashing
        if self.use_balloon {
            let params = match self.level {
                FortressLevel::Interactive => BalloonParams {
                    space_cost: 16384,
                    time_cost: 1,
                    delta: 3,
                    output_len: 32,
                },
                FortressLevel::Standard => BalloonParams {
                    space_cost: 65536,
                    time_cost: 2,
                    delta: 4,
                    output_len: 32,
                },
                _ => BalloonParams {
                    space_cost: 262144,
                    time_cost: 3,
                    delta: 4,
                    output_len: 32,
                },
            };
            result = balloon_hash(&result, &full_salt, &params)
                .map_err(|e| JsError::new(&format!("Balloon failed: {}", e)))?;
        }

        // Stage 3: Time-lock (hash chain)
        if self.use_timelock {
            let iterations = match self.level {
                FortressLevel::Interactive => 10_000,
                FortressLevel::Standard => 100_000,
                FortressLevel::High => 500_000,
                FortressLevel::Quantum => 1_000_000,
            };
            let input = [&result[..], &full_salt].concat();
            result = hash_chain_lock(&input, iterations).to_vec();
        }

        // Return as hex
        Ok(hex_encode(&result))
    }

    /// Verify a password against a hash
    #[wasm_bindgen(js_name = verifyPassword)]
    pub fn verify_password(
        &self,
        password: &str,
        salt: &str,
        expected_hash: &str,
    ) -> Result<bool, JsError> {
        let computed = self.hash_password(password, salt)?;
        Ok(constant_time_compare(&computed, expected_hash))
    }

    /// Get estimated time in seconds
    #[wasm_bindgen(getter, js_name = estimatedTime)]
    pub fn estimated_time(&self) -> f64 {
        let mut time = 0.0;
        if self.use_argon2 {
            time += match self.level {
                FortressLevel::Interactive => 0.1,
                FortressLevel::Standard => 0.5,
                FortressLevel::High => 2.0,
                FortressLevel::Quantum => 5.0,
            };
        }
        if self.use_balloon {
            time += match self.level {
                FortressLevel::Interactive => 0.05,
                FortressLevel::Standard => 0.3,
                FortressLevel::High => 1.0,
                FortressLevel::Quantum => 3.0,
            };
        }
        if self.use_timelock {
            time += match self.level {
                FortressLevel::Interactive => 0.01,
                FortressLevel::Standard => 0.1,
                FortressLevel::High => 0.5,
                FortressLevel::Quantum => 1.0,
            };
        }
        time
    }

    /// Get memory required in bytes
    #[wasm_bindgen(getter, js_name = memoryRequired)]
    pub fn memory_required(&self) -> usize {
        let mut mem = 0;
        if self.use_argon2 {
            mem = match self.level {
                FortressLevel::Interactive => 16 * 1024 * 1024,
                FortressLevel::Standard => 64 * 1024 * 1024,
                FortressLevel::High => 256 * 1024 * 1024,
                FortressLevel::Quantum => 256 * 1024 * 1024, // Limited for WASM
            };
        }
        if self.use_balloon {
            let balloon_mem = match self.level {
                FortressLevel::Interactive => 16384 * 32,
                FortressLevel::Standard => 65536 * 32,
                _ => 262144 * 32,
            };
            mem = mem.max(balloon_mem);
        }
        mem
    }
}

/// Quick hash using Argon2id only (for testing)
#[wasm_bindgen(js_name = quickHash)]
pub fn quick_hash(password: &str, salt: &str) -> Result<String, JsError> {
    let params = Argon2Params::interactive();
    let salt_hash = crypto::kdf::hash_sha256(salt.as_bytes());
    let hash = argon2_hash(password.as_bytes(), &salt_hash, &params)
        .map_err(|e| JsError::new(&format!("Hash failed: {}", e)))?;
    Ok(hex_encode(&hash))
}

/// Full fortress hash (Argon2 + Balloon + Time-lock)
#[wasm_bindgen(js_name = fortressHash)]
pub fn fortress_hash(password: &str, salt: &str) -> Result<String, JsError> {
    let fortress = Fortress::standard();
    fortress.hash_password(password, salt)
}

/// Convert bytes to hex string
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Constant-time string comparison
fn constant_time_compare(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut result = 0u8;
    for (x, y) in a.bytes().zip(b.bytes()) {
        result |= x ^ y;
    }
    result == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_quantum_state_creation() {
        let state = QuantumState::new(100, 32).unwrap();
        assert_eq!(state.n_qubits(), 100);
        assert_eq!(state.bond_dim(), 32);
    }

    #[test]
    fn test_entropy_calculation() {
        let state = QuantumState::new(10, 16).unwrap();
        let entropy = state.total_entropy();
        // Product state should have ~0 entropy
        assert!(entropy.abs() < 1e-10);
    }

    #[test]
    fn test_gate_application() {
        let mut state = QuantumState::new(5, 8).unwrap();
        state.hadamard(0).unwrap();
        state.pauli_x(1).unwrap();
        // Should not panic
    }

    #[test]
    fn test_shannon_entropy() {
        // Uniform distribution over 4 bins: entropy = 2 bits
        let counts = vec![100, 100, 100, 100];
        let entropy = shannon_entropy_from_counts(&counts);
        assert!((entropy - 2.0).abs() < 1e-10);
    }
}
