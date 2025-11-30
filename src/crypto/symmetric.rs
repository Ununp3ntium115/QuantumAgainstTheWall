//! Symmetric encryption for data at rest.
//!
//! Provides AES-256-GCM and ChaCha20-Poly1305 authenticated encryption.

use crate::crypto::{CryptoError, CryptoResult, Zeroize};
use crate::crypto::keys::SecretKey;
use crate::crypto::rng::QuantumRng;

/// Encrypted data with authentication tag.
#[derive(Clone, Debug)]
pub struct EncryptedData {
    /// The ciphertext
    pub ciphertext: Vec<u8>,
    /// The nonce used for encryption
    pub nonce: [u8; 12],
    /// The authentication tag
    pub tag: [u8; 16],
    /// Algorithm used
    pub algorithm: SymmetricAlgorithm,
}

impl EncryptedData {
    /// Serialize to bytes for storage/transmission.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(1 + 12 + 16 + self.ciphertext.len());
        result.push(self.algorithm as u8);
        result.extend_from_slice(&self.nonce);
        result.extend_from_slice(&self.tag);
        result.extend_from_slice(&self.ciphertext);
        result
    }

    /// Deserialize from bytes.
    pub fn from_bytes(bytes: &[u8]) -> CryptoResult<Self> {
        if bytes.len() < 1 + 12 + 16 {
            return Err(CryptoError::InvalidCiphertext);
        }

        let algorithm = match bytes[0] {
            0 => SymmetricAlgorithm::Aes256Gcm,
            1 => SymmetricAlgorithm::ChaCha20Poly1305,
            _ => return Err(CryptoError::InvalidCiphertext),
        };

        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&bytes[1..13]);

        let mut tag = [0u8; 16];
        tag.copy_from_slice(&bytes[13..29]);

        let ciphertext = bytes[29..].to_vec();

        Ok(Self {
            ciphertext,
            nonce,
            tag,
            algorithm,
        })
    }
}

/// Supported symmetric encryption algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SymmetricAlgorithm {
    /// AES-256-GCM
    Aes256Gcm = 0,
    /// ChaCha20-Poly1305
    ChaCha20Poly1305 = 1,
}

/// Encrypt data using AES-256-GCM or ChaCha20-Poly1305.
///
/// # Arguments
/// * `key` - The 256-bit encryption key
/// * `plaintext` - The data to encrypt
/// * `aad` - Additional authenticated data (optional, not encrypted but authenticated)
/// * `rng` - Random number generator for nonce
/// * `algorithm` - The encryption algorithm to use
///
/// # Returns
/// The encrypted data with nonce and authentication tag
pub fn encrypt(
    key: &SecretKey,
    plaintext: &[u8],
    aad: Option<&[u8]>,
    rng: &mut QuantumRng,
    algorithm: SymmetricAlgorithm,
) -> CryptoResult<EncryptedData> {
    let nonce = rng.gen_bytes_12();

    match algorithm {
        SymmetricAlgorithm::Aes256Gcm => encrypt_aes_gcm(key, plaintext, &nonce, aad),
        SymmetricAlgorithm::ChaCha20Poly1305 => encrypt_chacha20_poly1305(key, plaintext, &nonce, aad),
    }
}

/// Decrypt data.
///
/// # Arguments
/// * `key` - The 256-bit encryption key
/// * `encrypted` - The encrypted data
/// * `aad` - Additional authenticated data (must match what was used during encryption)
///
/// # Returns
/// The decrypted plaintext, or an error if authentication fails
pub fn decrypt(
    key: &SecretKey,
    encrypted: &EncryptedData,
    aad: Option<&[u8]>,
) -> CryptoResult<Vec<u8>> {
    match encrypted.algorithm {
        SymmetricAlgorithm::Aes256Gcm => {
            decrypt_aes_gcm(key, &encrypted.ciphertext, &encrypted.nonce, &encrypted.tag, aad)
        }
        SymmetricAlgorithm::ChaCha20Poly1305 => {
            decrypt_chacha20_poly1305(key, &encrypted.ciphertext, &encrypted.nonce, &encrypted.tag, aad)
        }
    }
}

// ============================================================================
// ChaCha20-Poly1305 Implementation
// ============================================================================

fn encrypt_chacha20_poly1305(
    key: &SecretKey,
    plaintext: &[u8],
    nonce: &[u8; 12],
    aad: Option<&[u8]>,
) -> CryptoResult<EncryptedData> {
    let aad = aad.unwrap_or(&[]);

    // Generate keystream and encrypt
    let mut ciphertext = plaintext.to_vec();
    let mut chacha = ChaCha20::new(key.as_bytes(), nonce, 1);
    chacha.apply_keystream(&mut ciphertext);

    // Generate Poly1305 key
    let mut poly_key = [0u8; 32];
    let mut chacha_poly = ChaCha20::new(key.as_bytes(), nonce, 0);
    chacha_poly.apply_keystream(&mut poly_key);

    // Compute authentication tag
    let tag = poly1305_compute(&poly_key, aad, &ciphertext);

    poly_key.zeroize();

    Ok(EncryptedData {
        ciphertext,
        nonce: *nonce,
        tag,
        algorithm: SymmetricAlgorithm::ChaCha20Poly1305,
    })
}

fn decrypt_chacha20_poly1305(
    key: &SecretKey,
    ciphertext: &[u8],
    nonce: &[u8; 12],
    tag: &[u8; 16],
    aad: Option<&[u8]>,
) -> CryptoResult<Vec<u8>> {
    let aad = aad.unwrap_or(&[]);

    // Generate Poly1305 key
    let mut poly_key = [0u8; 32];
    let mut chacha_poly = ChaCha20::new(key.as_bytes(), nonce, 0);
    chacha_poly.apply_keystream(&mut poly_key);

    // Verify tag
    let computed_tag = poly1305_compute(&poly_key, aad, ciphertext);
    poly_key.zeroize();

    // Constant-time comparison
    let mut diff = 0u8;
    for i in 0..16 {
        diff |= tag[i] ^ computed_tag[i];
    }
    if diff != 0 {
        return Err(CryptoError::DecryptionFailed);
    }

    // Decrypt
    let mut plaintext = ciphertext.to_vec();
    let mut chacha = ChaCha20::new(key.as_bytes(), nonce, 1);
    chacha.apply_keystream(&mut plaintext);

    Ok(plaintext)
}

/// ChaCha20 stream cipher.
struct ChaCha20 {
    state: [u32; 16],
    buffer: [u8; 64],
    position: usize,
}

impl ChaCha20 {
    fn new(key: &[u8; 32], nonce: &[u8; 12], counter: u32) -> Self {
        let mut state = [0u32; 16];

        // Constants
        state[0] = 0x61707865;
        state[1] = 0x3320646e;
        state[2] = 0x79622d32;
        state[3] = 0x6b206574;

        // Key
        for i in 0..8 {
            state[4 + i] = u32::from_le_bytes([
                key[i * 4],
                key[i * 4 + 1],
                key[i * 4 + 2],
                key[i * 4 + 3],
            ]);
        }

        // Counter
        state[12] = counter;

        // Nonce
        state[13] = u32::from_le_bytes([nonce[0], nonce[1], nonce[2], nonce[3]]);
        state[14] = u32::from_le_bytes([nonce[4], nonce[5], nonce[6], nonce[7]]);
        state[15] = u32::from_le_bytes([nonce[8], nonce[9], nonce[10], nonce[11]]);

        Self {
            state,
            buffer: [0u8; 64],
            position: 64,
        }
    }

    fn apply_keystream(&mut self, data: &mut [u8]) {
        for byte in data.iter_mut() {
            if self.position >= 64 {
                self.generate_block();
            }
            *byte ^= self.buffer[self.position];
            self.position += 1;
        }
    }

    fn generate_block(&mut self) {
        let mut working = self.state;

        for _ in 0..10 {
            // Column rounds
            quarter_round(&mut working, 0, 4, 8, 12);
            quarter_round(&mut working, 1, 5, 9, 13);
            quarter_round(&mut working, 2, 6, 10, 14);
            quarter_round(&mut working, 3, 7, 11, 15);
            // Diagonal rounds
            quarter_round(&mut working, 0, 5, 10, 15);
            quarter_round(&mut working, 1, 6, 11, 12);
            quarter_round(&mut working, 2, 7, 8, 13);
            quarter_round(&mut working, 3, 4, 9, 14);
        }

        for i in 0..16 {
            working[i] = working[i].wrapping_add(self.state[i]);
            let bytes = working[i].to_le_bytes();
            self.buffer[i * 4] = bytes[0];
            self.buffer[i * 4 + 1] = bytes[1];
            self.buffer[i * 4 + 2] = bytes[2];
            self.buffer[i * 4 + 3] = bytes[3];
        }

        self.state[12] = self.state[12].wrapping_add(1);
        self.position = 0;
    }
}

#[inline]
fn quarter_round(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(16);

    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(12);

    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(8);

    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(7);
}

/// Poly1305 MAC computation.
fn poly1305_compute(key: &[u8; 32], aad: &[u8], ciphertext: &[u8]) -> [u8; 16] {
    let mut poly = Poly1305::new(key);

    // Process AAD
    poly.update(aad);
    if aad.len() % 16 != 0 {
        let padding = 16 - (aad.len() % 16);
        poly.update(&[0u8; 16][..padding]);
    }

    // Process ciphertext
    poly.update(ciphertext);
    if ciphertext.len() % 16 != 0 {
        let padding = 16 - (ciphertext.len() % 16);
        poly.update(&[0u8; 16][..padding]);
    }

    // Lengths
    poly.update(&(aad.len() as u64).to_le_bytes());
    poly.update(&(ciphertext.len() as u64).to_le_bytes());

    poly.finalize()
}

/// Poly1305 authenticator.
struct Poly1305 {
    r: [u32; 5],
    h: [u32; 5],
    pad: [u32; 4],
    buffer: [u8; 16],
    buffer_len: usize,
}

impl Poly1305 {
    fn new(key: &[u8; 32]) -> Self {
        let mut r = [0u32; 5];
        let mut pad = [0u32; 4];

        // Clamp r
        r[0] = u32::from_le_bytes([key[0], key[1], key[2], key[3]]) & 0x0fffffff;
        r[1] = u32::from_le_bytes([key[3], key[4], key[5], key[6]]) >> 4 & 0x0ffffffc;
        r[2] = u32::from_le_bytes([key[6], key[7], key[8], key[9]]) >> 6 & 0x0ffffffc;
        r[3] = u32::from_le_bytes([key[9], key[10], key[11], key[12]]) >> 8 & 0x0ffffffc;
        r[4] = u32::from_le_bytes([key[12], key[13], key[14], key[15]]) >> 8 >> 2 & 0x00fffffc;

        pad[0] = u32::from_le_bytes([key[16], key[17], key[18], key[19]]);
        pad[1] = u32::from_le_bytes([key[20], key[21], key[22], key[23]]);
        pad[2] = u32::from_le_bytes([key[24], key[25], key[26], key[27]]);
        pad[3] = u32::from_le_bytes([key[28], key[29], key[30], key[31]]);

        Self {
            r,
            h: [0; 5],
            pad,
            buffer: [0; 16],
            buffer_len: 0,
        }
    }

    fn update(&mut self, data: &[u8]) {
        let mut offset = 0;

        // Fill buffer
        if self.buffer_len > 0 {
            let to_copy = (16 - self.buffer_len).min(data.len());
            self.buffer[self.buffer_len..self.buffer_len + to_copy]
                .copy_from_slice(&data[..to_copy]);
            self.buffer_len += to_copy;
            offset = to_copy;

            if self.buffer_len == 16 {
                self.process_block(&self.buffer.clone(), true);
                self.buffer_len = 0;
            }
        }

        // Process full blocks
        while offset + 16 <= data.len() {
            let mut block = [0u8; 16];
            block.copy_from_slice(&data[offset..offset + 16]);
            self.process_block(&block, true);
            offset += 16;
        }

        // Buffer remainder
        if offset < data.len() {
            let remaining = data.len() - offset;
            self.buffer[..remaining].copy_from_slice(&data[offset..]);
            self.buffer_len = remaining;
        }
    }

    fn process_block(&mut self, block: &[u8; 16], full: bool) {
        let hibit = if full { 1u32 << 24 } else { 0 };

        // h += block
        self.h[0] = self.h[0].wrapping_add(
            u32::from_le_bytes([block[0], block[1], block[2], block[3]]) & 0x3ffffff,
        );
        self.h[1] = self.h[1].wrapping_add(
            (u32::from_le_bytes([block[3], block[4], block[5], block[6]]) >> 2) & 0x3ffffff,
        );
        self.h[2] = self.h[2].wrapping_add(
            (u32::from_le_bytes([block[6], block[7], block[8], block[9]]) >> 4) & 0x3ffffff,
        );
        self.h[3] = self.h[3].wrapping_add(
            (u32::from_le_bytes([block[9], block[10], block[11], block[12]]) >> 6) & 0x3ffffff,
        );
        self.h[4] = self.h[4].wrapping_add(
            (u32::from_le_bytes([block[12], block[13], block[14], block[15]]) >> 8) | hibit,
        );

        // h *= r (simplified)
        let mut d = [0u64; 5];
        for i in 0..5 {
            for j in 0..5 {
                let r_val = if i + j >= 5 {
                    self.r[(i + j) % 5] as u64 * 5
                } else {
                    self.r[(i + j) % 5] as u64
                };
                d[i] += self.h[j] as u64 * r_val;
            }
        }

        // Reduce
        let mut c: u64 = 0;
        for i in 0..5 {
            c += d[i];
            self.h[i] = (c & 0x3ffffff) as u32;
            c >>= 26;
        }
        self.h[0] += (c * 5) as u32;
    }

    fn finalize(mut self) -> [u8; 16] {
        // Process remaining
        if self.buffer_len > 0 {
            self.buffer[self.buffer_len] = 1;
            for i in self.buffer_len + 1..16 {
                self.buffer[i] = 0;
            }
            let buffer_copy = self.buffer;
            self.process_block(&buffer_copy, false);
        }

        // Fully reduce h
        let mut c = self.h[0] >> 26;
        self.h[0] &= 0x3ffffff;
        for i in 1..5 {
            self.h[i] += c;
            c = self.h[i] >> 26;
            self.h[i] &= 0x3ffffff;
        }
        self.h[0] += c * 5;
        c = self.h[0] >> 26;
        self.h[0] &= 0x3ffffff;
        self.h[1] += c;

        // h + pad
        let mut f: u64 = self.h[0] as u64 + self.pad[0] as u64;
        self.h[0] = f as u32;
        f = (f >> 32) + self.h[1] as u64 + ((self.pad[0] >> 26) | (self.pad[1] << 6)) as u64;
        self.h[1] = f as u32;
        f = (f >> 32) + self.h[2] as u64 + ((self.pad[1] >> 20) | (self.pad[2] << 12)) as u64;
        self.h[2] = f as u32;
        f = (f >> 32) + self.h[3] as u64 + ((self.pad[2] >> 14) | (self.pad[3] << 18)) as u64;
        self.h[3] = f as u32;
        f = (f >> 32) + self.h[4] as u64 + (self.pad[3] >> 8) as u64;
        self.h[4] = f as u32;

        // Output
        let mut tag = [0u8; 16];
        tag[0..4].copy_from_slice(&self.h[0].to_le_bytes());
        tag[3..7].copy_from_slice(&((self.h[0] >> 24) as u32 | (self.h[1] << 8)).to_le_bytes());
        // Simplified output
        let val = ((self.h[0] as u128)
            | ((self.h[1] as u128) << 26)
            | ((self.h[2] as u128) << 52)
            | ((self.h[3] as u128) << 78)
            | ((self.h[4] as u128) << 104)) as u128;
        tag.copy_from_slice(&val.to_le_bytes()[..16]);

        tag
    }
}

// ============================================================================
// AES-256-GCM Implementation (simplified)
// ============================================================================

fn encrypt_aes_gcm(
    key: &SecretKey,
    plaintext: &[u8],
    nonce: &[u8; 12],
    aad: Option<&[u8]>,
) -> CryptoResult<EncryptedData> {
    let aad = aad.unwrap_or(&[]);
    let aes = Aes256::new(key.as_bytes());

    // Generate counter block
    let mut counter = [0u8; 16];
    counter[..12].copy_from_slice(nonce);
    counter[15] = 1;

    // Encrypt plaintext using CTR mode
    let mut ciphertext = plaintext.to_vec();
    for chunk in ciphertext.chunks_mut(16) {
        increment_counter(&mut counter);
        let keystream = aes.encrypt_block(&counter);
        for (i, byte) in chunk.iter_mut().enumerate() {
            *byte ^= keystream[i];
        }
    }

    // Compute GHASH
    let mut h = [0u8; 16];
    let zero_block = [0u8; 16];
    let h_block = aes.encrypt_block(&zero_block);
    h.copy_from_slice(&h_block);

    let tag = ghash(&h, aad, &ciphertext, nonce, &aes);

    Ok(EncryptedData {
        ciphertext,
        nonce: *nonce,
        tag,
        algorithm: SymmetricAlgorithm::Aes256Gcm,
    })
}

fn decrypt_aes_gcm(
    key: &SecretKey,
    ciphertext: &[u8],
    nonce: &[u8; 12],
    tag: &[u8; 16],
    aad: Option<&[u8]>,
) -> CryptoResult<Vec<u8>> {
    let aad = aad.unwrap_or(&[]);
    let aes = Aes256::new(key.as_bytes());

    // Compute expected tag
    let mut h = [0u8; 16];
    let zero_block = [0u8; 16];
    let h_block = aes.encrypt_block(&zero_block);
    h.copy_from_slice(&h_block);

    let expected_tag = ghash(&h, aad, ciphertext, nonce, &aes);

    // Constant-time comparison
    let mut diff = 0u8;
    for i in 0..16 {
        diff |= tag[i] ^ expected_tag[i];
    }
    if diff != 0 {
        return Err(CryptoError::DecryptionFailed);
    }

    // Decrypt using CTR mode
    let mut counter = [0u8; 16];
    counter[..12].copy_from_slice(nonce);
    counter[15] = 1;

    let mut plaintext = ciphertext.to_vec();
    for chunk in plaintext.chunks_mut(16) {
        increment_counter(&mut counter);
        let keystream = aes.encrypt_block(&counter);
        for (i, byte) in chunk.iter_mut().enumerate() {
            *byte ^= keystream[i];
        }
    }

    Ok(plaintext)
}

fn increment_counter(counter: &mut [u8; 16]) {
    for i in (12..16).rev() {
        counter[i] = counter[i].wrapping_add(1);
        if counter[i] != 0 {
            break;
        }
    }
}

fn ghash(h: &[u8; 16], aad: &[u8], ciphertext: &[u8], nonce: &[u8; 12], aes: &Aes256) -> [u8; 16] {
    let mut y = [0u8; 16];

    // Process AAD
    for chunk in aad.chunks(16) {
        let mut block = [0u8; 16];
        block[..chunk.len()].copy_from_slice(chunk);
        xor_blocks(&mut y, &block);
        y = gf_mul(&y, h);
    }

    // Process ciphertext
    for chunk in ciphertext.chunks(16) {
        let mut block = [0u8; 16];
        block[..chunk.len()].copy_from_slice(chunk);
        xor_blocks(&mut y, &block);
        y = gf_mul(&y, h);
    }

    // Length block
    let mut len_block = [0u8; 16];
    len_block[..8].copy_from_slice(&((aad.len() * 8) as u64).to_be_bytes());
    len_block[8..16].copy_from_slice(&((ciphertext.len() * 8) as u64).to_be_bytes());
    xor_blocks(&mut y, &len_block);
    y = gf_mul(&y, h);

    // Final XOR with E(K, Y0)
    let mut y0 = [0u8; 16];
    y0[..12].copy_from_slice(nonce);
    y0[15] = 1;
    let ek_y0 = aes.encrypt_block(&y0);
    xor_blocks(&mut y, &ek_y0);

    y
}

fn xor_blocks(a: &mut [u8; 16], b: &[u8; 16]) {
    for i in 0..16 {
        a[i] ^= b[i];
    }
}

fn gf_mul(x: &[u8; 16], y: &[u8; 16]) -> [u8; 16] {
    let mut z = [0u8; 16];
    let mut v = *y;

    for i in 0..128 {
        let byte_idx = i / 8;
        let bit_idx = 7 - (i % 8);

        if (x[byte_idx] >> bit_idx) & 1 == 1 {
            xor_blocks(&mut z, &v);
        }

        let lsb = v[15] & 1;
        // Right shift v
        for j in (1..16).rev() {
            v[j] = (v[j] >> 1) | (v[j - 1] << 7);
        }
        v[0] >>= 1;

        if lsb == 1 {
            v[0] ^= 0xe1; // R = 11100001
        }
    }

    z
}

/// Simplified AES-256 implementation.
struct Aes256 {
    round_keys: [[u8; 16]; 15],
}

impl Aes256 {
    fn new(key: &[u8; 32]) -> Self {
        let round_keys = Self::key_expansion(key);
        Self { round_keys }
    }

    fn key_expansion(key: &[u8; 32]) -> [[u8; 16]; 15] {
        let mut w = [[0u8; 4]; 60];

        // Copy key into first 8 words
        for i in 0..8 {
            w[i].copy_from_slice(&key[i * 4..(i + 1) * 4]);
        }

        // Expand
        for i in 8..60 {
            let mut temp = w[i - 1];
            if i % 8 == 0 {
                // RotWord + SubWord + Rcon
                temp = [
                    SBOX[temp[1] as usize] ^ RCON[i / 8],
                    SBOX[temp[2] as usize],
                    SBOX[temp[3] as usize],
                    SBOX[temp[0] as usize],
                ];
            } else if i % 8 == 4 {
                temp = [
                    SBOX[temp[0] as usize],
                    SBOX[temp[1] as usize],
                    SBOX[temp[2] as usize],
                    SBOX[temp[3] as usize],
                ];
            }
            for j in 0..4 {
                w[i][j] = w[i - 8][j] ^ temp[j];
            }
        }

        // Convert to round keys
        let mut round_keys = [[0u8; 16]; 15];
        for i in 0..15 {
            for j in 0..4 {
                round_keys[i][j * 4..(j + 1) * 4].copy_from_slice(&w[i * 4 + j]);
            }
        }

        round_keys
    }

    fn encrypt_block(&self, input: &[u8; 16]) -> [u8; 16] {
        let mut state = *input;

        // Initial round
        xor_blocks(&mut state, &self.round_keys[0]);

        // Main rounds
        for i in 1..14 {
            state = self.sub_bytes(&state);
            state = self.shift_rows(&state);
            state = self.mix_columns(&state);
            xor_blocks(&mut state, &self.round_keys[i]);
        }

        // Final round
        state = self.sub_bytes(&state);
        state = self.shift_rows(&state);
        xor_blocks(&mut state, &self.round_keys[14]);

        state
    }

    fn sub_bytes(&self, state: &[u8; 16]) -> [u8; 16] {
        let mut result = [0u8; 16];
        for i in 0..16 {
            result[i] = SBOX[state[i] as usize];
        }
        result
    }

    fn shift_rows(&self, state: &[u8; 16]) -> [u8; 16] {
        [
            state[0], state[5], state[10], state[15],
            state[4], state[9], state[14], state[3],
            state[8], state[13], state[2], state[7],
            state[12], state[1], state[6], state[11],
        ]
    }

    fn mix_columns(&self, state: &[u8; 16]) -> [u8; 16] {
        let mut result = [0u8; 16];
        for i in 0..4 {
            let col = i * 4;
            result[col] = gf_mul_byte(2, state[col]) ^ gf_mul_byte(3, state[col + 1])
                ^ state[col + 2] ^ state[col + 3];
            result[col + 1] = state[col] ^ gf_mul_byte(2, state[col + 1])
                ^ gf_mul_byte(3, state[col + 2]) ^ state[col + 3];
            result[col + 2] = state[col] ^ state[col + 1]
                ^ gf_mul_byte(2, state[col + 2]) ^ gf_mul_byte(3, state[col + 3]);
            result[col + 3] = gf_mul_byte(3, state[col]) ^ state[col + 1]
                ^ state[col + 2] ^ gf_mul_byte(2, state[col + 3]);
        }
        result
    }
}

fn gf_mul_byte(a: u8, b: u8) -> u8 {
    let mut p = 0u8;
    let mut a = a;
    let mut b = b;
    for _ in 0..8 {
        if b & 1 != 0 {
            p ^= a;
        }
        let hi_bit = a & 0x80;
        a <<= 1;
        if hi_bit != 0 {
            a ^= 0x1b;
        }
        b >>= 1;
    }
    p
}

// AES S-Box
const SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

// AES Rcon
const RCON: [u8; 15] = [
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d,
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chacha20_poly1305_roundtrip() {
        let seed = [0x42u8; 32];
        let mut rng = QuantumRng::from_seed(&seed, 256.0);

        let key = SecretKey::generate(&mut rng);
        let plaintext = b"Hello, QuantumWall!";

        let encrypted = encrypt(&key, plaintext, None, &mut rng, SymmetricAlgorithm::ChaCha20Poly1305)
            .unwrap();
        let decrypted = decrypt(&key, &encrypted, None).unwrap();

        assert_eq!(&decrypted, plaintext);
    }

    #[test]
    fn test_aes_gcm_roundtrip() {
        let seed = [0x42u8; 32];
        let mut rng = QuantumRng::from_seed(&seed, 256.0);

        let key = SecretKey::generate(&mut rng);
        let plaintext = b"Hello, QuantumWall with AES!";

        let encrypted = encrypt(&key, plaintext, None, &mut rng, SymmetricAlgorithm::Aes256Gcm)
            .unwrap();
        let decrypted = decrypt(&key, &encrypted, None).unwrap();

        assert_eq!(&decrypted, plaintext);
    }

    #[test]
    fn test_encryption_with_aad() {
        let seed = [0x42u8; 32];
        let mut rng = QuantumRng::from_seed(&seed, 256.0);

        let key = SecretKey::generate(&mut rng);
        let plaintext = b"Secret message";
        let aad = b"Additional authenticated data";

        let encrypted = encrypt(&key, plaintext, Some(aad), &mut rng, SymmetricAlgorithm::ChaCha20Poly1305)
            .unwrap();
        let decrypted = decrypt(&key, &encrypted, Some(aad)).unwrap();

        assert_eq!(&decrypted, plaintext);

        // Wrong AAD should fail
        let wrong_aad = b"Wrong AAD";
        let result = decrypt(&key, &encrypted, Some(wrong_aad));
        assert!(result.is_err());
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let seed = [0x42u8; 32];
        let mut rng = QuantumRng::from_seed(&seed, 256.0);

        let key = SecretKey::generate(&mut rng);
        let plaintext = b"Secret message";

        let mut encrypted = encrypt(&key, plaintext, None, &mut rng, SymmetricAlgorithm::ChaCha20Poly1305)
            .unwrap();

        // Tamper with ciphertext
        if !encrypted.ciphertext.is_empty() {
            encrypted.ciphertext[0] ^= 0xff;
        }

        let result = decrypt(&key, &encrypted, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_encrypted_data_serialization() {
        let seed = [0x42u8; 32];
        let mut rng = QuantumRng::from_seed(&seed, 256.0);

        let key = SecretKey::generate(&mut rng);
        let plaintext = b"Test serialization";

        let encrypted = encrypt(&key, plaintext, None, &mut rng, SymmetricAlgorithm::ChaCha20Poly1305)
            .unwrap();

        let bytes = encrypted.to_bytes();
        let restored = EncryptedData::from_bytes(&bytes).unwrap();

        let decrypted = decrypt(&key, &restored, None).unwrap();
        assert_eq!(&decrypted, plaintext);
    }
}
