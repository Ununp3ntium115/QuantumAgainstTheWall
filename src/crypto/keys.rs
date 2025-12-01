//! Cryptographic key types and management.

use crate::crypto::rng::QuantumRng;
use crate::crypto::{CryptoError, CryptoResult, Zeroize};
use x25519_dalek::{PublicKey as DalekPublicKey, StaticSecret};

/// A 256-bit secret key for symmetric encryption.
#[derive(Clone)]
pub struct SecretKey {
    bytes: [u8; 32],
}

impl SecretKey {
    /// Create a new secret key from bytes.
    pub fn new(bytes: [u8; 32]) -> Self {
        Self { bytes }
    }

    /// Generate a random secret key using quantum RNG.
    pub fn generate(rng: &mut QuantumRng) -> Self {
        Self {
            bytes: rng.gen_bytes_32(),
        }
    }

    /// Get the key bytes (use carefully).
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }

    /// Create from a slice (must be exactly 32 bytes).
    pub fn from_slice(slice: &[u8]) -> CryptoResult<Self> {
        if slice.len() != 32 {
            return Err(CryptoError::InvalidKeyLength);
        }
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(slice);
        Ok(Self { bytes })
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

impl std::fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecretKey([REDACTED])")
    }
}

/// A public key for asymmetric operations.
#[derive(Clone, Debug, PartialEq)]
pub struct PublicKey {
    bytes: Vec<u8>,
    algorithm: KeyAlgorithm,
}

impl PublicKey {
    /// Create a new public key.
    pub fn new(bytes: Vec<u8>, algorithm: KeyAlgorithm) -> Self {
        Self { bytes, algorithm }
    }

    /// Get the key bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Get the algorithm.
    pub fn algorithm(&self) -> KeyAlgorithm {
        self.algorithm
    }

    /// Export as hex string.
    pub fn to_hex(&self) -> String {
        self.bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    /// Import from hex string.
    pub fn from_hex(hex: &str, algorithm: KeyAlgorithm) -> CryptoResult<Self> {
        let bytes = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16))
            .collect::<Result<Vec<u8>, _>>()
            .map_err(|_| CryptoError::InvalidKeyLength)?;
        Ok(Self::new(bytes, algorithm))
    }
}

/// A key pair (public + secret).
pub struct KeyPair {
    pub public: PublicKey,
    secret: Vec<u8>,
    algorithm: KeyAlgorithm,
}

impl KeyPair {
    /// Create a new key pair.
    pub fn new(public: PublicKey, secret: Vec<u8>, algorithm: KeyAlgorithm) -> Self {
        Self {
            public,
            secret,
            algorithm,
        }
    }

    /// Get the secret key bytes (use carefully).
    pub fn secret_bytes(&self) -> &[u8] {
        &self.secret
    }

    /// Get the public key.
    pub fn public_key(&self) -> &PublicKey {
        &self.public
    }

    /// Get the algorithm.
    pub fn algorithm(&self) -> KeyAlgorithm {
        self.algorithm
    }

    /// Generate a new X25519 key pair for key exchange.
    pub fn generate_x25519(rng: &mut QuantumRng) -> Self {
        let secret_bytes = rng.gen_bytes_32();
        let secret = StaticSecret::from(secret_bytes);
        let public = DalekPublicKey::from(&secret);

        Self {
            public: PublicKey::new(public.to_bytes().to_vec(), KeyAlgorithm::X25519),
            secret: secret.to_bytes().to_vec(),
            algorithm: KeyAlgorithm::X25519,
        }
    }

    /// Perform X25519 key exchange.
    pub fn x25519_exchange(&self, their_public: &PublicKey) -> CryptoResult<[u8; 32]> {
        if their_public.algorithm() != KeyAlgorithm::X25519 {
            return Err(CryptoError::KeyExchangeFailed);
        }
        if their_public.as_bytes().len() != 32 || self.secret.len() != 32 {
            return Err(CryptoError::InvalidKeyLength);
        }

        let mut secret_bytes = [0u8; 32];
        secret_bytes.copy_from_slice(&self.secret);
        let secret = StaticSecret::from(secret_bytes);

        let mut pub_bytes = [0u8; 32];
        pub_bytes.copy_from_slice(their_public.as_bytes());
        let their_pub = DalekPublicKey::from(pub_bytes);

        let shared = secret.diffie_hellman(&their_pub);
        let mut out = [0u8; 32];
        out.copy_from_slice(shared.as_bytes());
        if out.iter().all(|&b| b == 0) {
            return Err(CryptoError::KeyExchangeFailed);
        }
        Ok(out)
    }
}

impl Drop for KeyPair {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

impl std::fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyPair")
            .field("public", &self.public)
            .field("secret", &"[REDACTED]")
            .field("algorithm", &self.algorithm)
            .finish()
    }
}

/// Key derivation for encryption.
#[derive(Clone)]
pub struct EncryptionKey {
    key: SecretKey,
    /// Counter for nonce generation
    nonce_counter: u64,
}

impl EncryptionKey {
    /// Create a new encryption key.
    pub fn new(key: SecretKey) -> Self {
        Self {
            key,
            nonce_counter: 0,
        }
    }

    /// Generate a random encryption key.
    pub fn generate(rng: &mut QuantumRng) -> Self {
        Self::new(SecretKey::generate(rng))
    }

    /// Get the underlying key.
    pub fn key(&self) -> &SecretKey {
        &self.key
    }

    /// Generate a unique nonce (combines random + counter).
    pub fn next_nonce(&mut self, rng: &mut QuantumRng) -> [u8; 12] {
        let mut nonce = [0u8; 12];

        // First 4 bytes: random
        let random_part = rng.next_u32().to_le_bytes();
        nonce[0..4].copy_from_slice(&random_part);

        // Last 8 bytes: counter
        let counter_bytes = self.nonce_counter.to_le_bytes();
        nonce[4..12].copy_from_slice(&counter_bytes);

        self.nonce_counter = self.nonce_counter.wrapping_add(1);

        nonce
    }

    /// Derive from a shared secret (e.g., from key exchange).
    pub fn from_shared_secret(shared: &[u8; 32], context: &[u8]) -> CryptoResult<Self> {
        use crate::crypto::kdf::derive_key;
        let derived = derive_key(shared, context, b"encryption")?;
        Ok(Self::new(SecretKey::new(derived.as_bytes())))
    }
}

/// Supported key algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyAlgorithm {
    /// AES-256-GCM symmetric encryption
    Aes256Gcm,
    /// ChaCha20-Poly1305 symmetric encryption
    ChaCha20Poly1305,
    /// X25519 key exchange
    X25519,
    /// ML-KEM (post-quantum)
    MlKem768,
}

// X25519 implementation (simplified)

/// X25519 base point multiplication (compute public from secret).
fn x25519_base_mul(secret: &[u8; 32]) -> [u8; 32] {
    // Base point: 9
    let mut basepoint = [0u8; 32];
    basepoint[0] = 9;
    x25519_scalar_mul(secret, &basepoint)
}

/// X25519 scalar multiplication.
fn x25519_scalar_mul(scalar: &[u8; 32], point: &[u8; 32]) -> [u8; 32] {
    // Field element representation
    let x1 = fe_from_bytes(point);
    let mut x2 = fe_one();
    let mut z2 = fe_zero();
    let mut x3 = x1;
    let mut z3 = fe_one();

    let mut swap: u32 = 0;

    // Montgomery ladder
    for i in (0..255).rev() {
        let bit = ((scalar[i / 8] >> (i % 8)) & 1) as u32;
        swap ^= bit;
        fe_cswap(&mut x2, &mut x3, swap);
        fe_cswap(&mut z2, &mut z3, swap);
        swap = bit;

        let a = fe_add(&x2, &z2);
        let aa = fe_sq(&a);
        let b = fe_sub(&x2, &z2);
        let bb = fe_sq(&b);
        let e = fe_sub(&aa, &bb);
        let c = fe_add(&x3, &z3);
        let d = fe_sub(&x3, &z3);
        let da = fe_mul(&d, &a);
        let cb = fe_mul(&c, &b);
        x3 = fe_sq(&fe_add(&da, &cb));
        z3 = fe_mul(&x1, &fe_sq(&fe_sub(&da, &cb)));
        x2 = fe_mul(&aa, &bb);
        z2 = fe_mul(&e, &fe_add(&aa, &fe_mul_121666(&e)));
    }

    fe_cswap(&mut x2, &mut x3, swap);
    fe_cswap(&mut z2, &mut z3, swap);

    let result = fe_mul(&x2, &fe_invert(&z2));
    fe_to_bytes(&result)
}

// Field element operations for X25519 (mod 2^255 - 19)
type Fe = [i64; 10];

fn fe_zero() -> Fe {
    [0; 10]
}

fn fe_one() -> Fe {
    let mut f = [0i64; 10];
    f[0] = 1;
    f
}

fn fe_from_bytes(bytes: &[u8; 32]) -> Fe {
    let mut h = [0i64; 10];
    let load4 = |i: usize| -> i64 {
        (bytes[i] as i64)
            | ((bytes[i + 1] as i64) << 8)
            | ((bytes[i + 2] as i64) << 16)
            | ((bytes[i + 3] as i64) << 24)
    };

    h[0] = load4(0);
    h[1] = load4(3) >> 2;
    h[2] = load4(6) >> 3;
    h[3] = load4(9) >> 5;
    h[4] = load4(12) >> 6;
    h[5] = load4(16);
    h[6] = load4(19) >> 1;
    h[7] = load4(22) >> 3;
    h[8] = load4(25) >> 4;
    h[9] = (load4(28) >> 6) & 0x3ffffff;

    h
}

fn fe_to_bytes(f: &Fe) -> [u8; 32] {
    let mut h = *f;
    fe_reduce(&mut h);

    let mut s = [0u8; 32];
    s[0] = h[0] as u8;
    s[1] = (h[0] >> 8) as u8;
    s[2] = (h[0] >> 16) as u8;
    s[3] = ((h[0] >> 24) | (h[1] << 2)) as u8;
    s[4] = (h[1] >> 6) as u8;
    s[5] = (h[1] >> 14) as u8;
    s[6] = ((h[1] >> 22) | (h[2] << 3)) as u8;
    s[7] = (h[2] >> 5) as u8;
    s[8] = (h[2] >> 13) as u8;
    s[9] = ((h[2] >> 21) | (h[3] << 5)) as u8;
    s[10] = (h[3] >> 3) as u8;
    s[11] = (h[3] >> 11) as u8;
    s[12] = ((h[3] >> 19) | (h[4] << 6)) as u8;
    s[13] = (h[4] >> 2) as u8;
    s[14] = (h[4] >> 10) as u8;
    s[15] = (h[4] >> 18) as u8;
    s[16] = h[5] as u8;
    s[17] = (h[5] >> 8) as u8;
    s[18] = (h[5] >> 16) as u8;
    s[19] = ((h[5] >> 24) | (h[6] << 1)) as u8;
    s[20] = (h[6] >> 7) as u8;
    s[21] = (h[6] >> 15) as u8;
    s[22] = ((h[6] >> 23) | (h[7] << 3)) as u8;
    s[23] = (h[7] >> 5) as u8;
    s[24] = (h[7] >> 13) as u8;
    s[25] = ((h[7] >> 21) | (h[8] << 4)) as u8;
    s[26] = (h[8] >> 4) as u8;
    s[27] = (h[8] >> 12) as u8;
    s[28] = ((h[8] >> 20) | (h[9] << 6)) as u8;
    s[29] = (h[9] >> 2) as u8;
    s[30] = (h[9] >> 10) as u8;
    s[31] = (h[9] >> 18) as u8;

    s
}

fn fe_add(f: &Fe, g: &Fe) -> Fe {
    let mut h = [0i64; 10];
    for i in 0..10 {
        h[i] = f[i].wrapping_add(g[i]);
    }
    fe_reduce(&mut h);
    h
}

fn fe_sub(f: &Fe, g: &Fe) -> Fe {
    // Add 2*p to ensure positive result before subtraction
    let mut h = [0i64; 10];
    // 2*p in radix 2^25.5 representation
    let two_p: [i64; 10] = [
        0x7ffffda, 0x3fffffe, 0x7fffffe, 0x3fffffe, 0x7fffffe, 0x3fffffe, 0x7fffffe, 0x3fffffe,
        0x7fffffe, 0x3fffffe,
    ];
    for i in 0..10 {
        h[i] = f[i].wrapping_add(two_p[i]).wrapping_sub(g[i]);
    }
    fe_reduce(&mut h);
    h
}

fn fe_mul(f: &Fe, g: &Fe) -> Fe {
    // Simplified multiplication (not constant-time for brevity)
    let mut h = [0i128; 10];

    for i in 0..10 {
        for j in 0..10 {
            let idx = (i + j) % 10;
            let mult = if i + j >= 10 { 38 } else { 1 };
            h[idx] += (f[i] as i128) * (g[j] as i128) * mult;
        }
    }

    let mut result = [0i64; 10];
    let mut carry = 0i128;
    for i in 0..10 {
        let val = h[i] + carry;
        let mask = if i % 2 == 0 { 0x3ffffff } else { 0x1ffffff };
        let bits = if i % 2 == 0 { 26 } else { 25 };
        result[i] = (val & mask) as i64;
        carry = val >> bits;
    }
    result[0] += (carry * 38) as i64;

    result
}

fn fe_sq(f: &Fe) -> Fe {
    fe_mul(f, f)
}

fn fe_mul_121666(f: &Fe) -> Fe {
    let mut h = [0i128; 10];
    for i in 0..10 {
        h[i] = (f[i] as i128) * 121666;
    }

    let mut result = [0i64; 10];
    let mut carry = 0i128;
    for i in 0..10 {
        let val = h[i] + carry;
        let mask = if i % 2 == 0 { 0x3ffffff } else { 0x1ffffff };
        let bits = if i % 2 == 0 { 26 } else { 25 };
        result[i] = (val & mask) as i64;
        carry = val >> bits;
    }
    result[0] += (carry * 38) as i64;

    result
}

fn fe_reduce(h: &mut Fe) {
    let mut carry;
    for _ in 0..2 {
        for i in 0..10 {
            let bits = if i % 2 == 0 { 26 } else { 25 };
            carry = h[i] >> bits;
            h[i] -= carry << bits;
            if i == 9 {
                h[0] += carry * 38;
            } else {
                h[i + 1] += carry;
            }
        }
    }
}

fn fe_cswap(f: &mut Fe, g: &mut Fe, swap: u32) {
    let swap = -(swap as i64);
    for i in 0..10 {
        let t = swap & (f[i] ^ g[i]);
        f[i] ^= t;
        g[i] ^= t;
    }
}

fn fe_invert(z: &Fe) -> Fe {
    // Compute z^(p-2) using exponentiation by squaring
    let mut t0 = fe_sq(z);
    let mut t1 = fe_sq(&t0);
    t1 = fe_sq(&t1);
    t1 = fe_mul(&t1, z);
    t0 = fe_mul(&t0, &t1);
    let mut t2 = fe_sq(&t0);
    t1 = fe_mul(&t1, &t2);
    t2 = fe_sq(&t1);
    for _ in 1..5 {
        t2 = fe_sq(&t2);
    }
    t1 = fe_mul(&t2, &t1);
    t2 = fe_sq(&t1);
    for _ in 1..10 {
        t2 = fe_sq(&t2);
    }
    t2 = fe_mul(&t2, &t1);
    let mut t3 = fe_sq(&t2);
    for _ in 1..20 {
        t3 = fe_sq(&t3);
    }
    t2 = fe_mul(&t3, &t2);
    t2 = fe_sq(&t2);
    for _ in 1..10 {
        t2 = fe_sq(&t2);
    }
    t1 = fe_mul(&t2, &t1);
    t2 = fe_sq(&t1);
    for _ in 1..50 {
        t2 = fe_sq(&t2);
    }
    t2 = fe_mul(&t2, &t1);
    t3 = fe_sq(&t2);
    for _ in 1..100 {
        t3 = fe_sq(&t3);
    }
    t2 = fe_mul(&t3, &t2);
    t2 = fe_sq(&t2);
    for _ in 1..50 {
        t2 = fe_sq(&t2);
    }
    t1 = fe_mul(&t2, &t1);
    t1 = fe_sq(&t1);
    for _ in 1..5 {
        t1 = fe_sq(&t1);
    }
    fe_mul(&t1, &t0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secret_key_generation() {
        let seed = [0x42u8; 32];
        let mut rng = QuantumRng::from_seed(&seed, 256.0).expect("rng");
        let key = SecretKey::generate(&mut rng);
        assert_eq!(key.as_bytes().len(), 32);
    }

    #[test]
    fn test_x25519_key_exchange() {
        let seed = [0x42u8; 32];
        let mut rng = QuantumRng::from_seed(&seed, 256.0).expect("rng");

        let alice = KeyPair::generate_x25519(&mut rng);
        let bob = KeyPair::generate_x25519(&mut rng);

        let alice_shared = alice.x25519_exchange(&bob.public).unwrap();
        let bob_shared = bob.x25519_exchange(&alice.public).unwrap();

        assert_eq!(alice_shared, bob_shared);
    }

    #[test]
    fn test_encryption_key_nonce() {
        let seed = [0x42u8; 32];
        let mut rng = QuantumRng::from_seed(&seed, 256.0).expect("rng");

        let mut key = EncryptionKey::generate(&mut rng);
        let nonce1 = key.next_nonce(&mut rng);
        let nonce2 = key.next_nonce(&mut rng);

        // Nonces should be different
        assert_ne!(nonce1, nonce2);
    }
}
