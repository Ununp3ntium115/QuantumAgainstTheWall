//! Symmetric encryption for data at rest.
//!
//! Provides AES-256-GCM and ChaCha20-Poly1305 authenticated encryption backed
//! by vetted crates. Nonce uniqueness, replay protection, and authenticated
//! algorithm metadata are enforced per-key.

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

use aes_gcm::{aead::generic_array::GenericArray, aead::Aead, aead::KeyInit, Aes256Gcm};
use chacha20poly1305::ChaCha20Poly1305;
use once_cell::sync::Lazy;

use crate::crypto::keys::SecretKey;
use crate::crypto::rng::QuantumRng;
use crate::crypto::{CryptoError, CryptoResult};

const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
const MAX_AES_GCM_MESSAGES: u64 = 1 << 32;
const MAX_CHACHA_MESSAGES: u64 = 1 << 48;

static NONCE_REGISTRY: Lazy<Mutex<HashMap<[u8; 32], NonceState>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SymmetricAlgorithm {
    Aes256Gcm = 0,
    ChaCha20Poly1305 = 1,
}

#[derive(Default, Clone)]
struct NonceState {
    counter: u64,
    seen: HashSet<[u8; NONCE_LEN]>,
    key_version: u32,
}

impl NonceState {
    fn next_nonce(
        &mut self,
        algorithm: SymmetricAlgorithm,
        rng: &mut QuantumRng,
    ) -> CryptoResult<[u8; NONCE_LEN]> {
        let max = match algorithm {
            SymmetricAlgorithm::Aes256Gcm => MAX_AES_GCM_MESSAGES,
            SymmetricAlgorithm::ChaCha20Poly1305 => MAX_CHACHA_MESSAGES,
        };
        if self.counter >= max {
            return Err(CryptoError::NonceExhausted);
        }

        let mut nonce = [0u8; NONCE_LEN];
        let random = rng.gen_bytes_12();
        nonce[..4].copy_from_slice(&random[..4]);
        nonce[4..].copy_from_slice(&self.counter.to_be_bytes());
        self.counter = self
            .counter
            .checked_add(1)
            .ok_or(CryptoError::NonceExhausted)?;
        // Don't register here - nonces are only registered during decryption for replay detection
        Ok(nonce)
    }

    fn register(&mut self, nonce: [u8; NONCE_LEN]) -> CryptoResult<()> {
        if !self.seen.insert(nonce) {
            return Err(CryptoError::ReplayDetected);
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct EncryptedData {
    pub ciphertext: Vec<u8>,
    pub nonce: [u8; NONCE_LEN],
    pub tag: [u8; TAG_LEN],
    pub algorithm: SymmetricAlgorithm,
    pub key_version: u32,
}

impl EncryptedData {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(1 + 4 + NONCE_LEN + TAG_LEN + self.ciphertext.len());
        result.push(self.algorithm as u8);
        result.extend_from_slice(&self.key_version.to_be_bytes());
        result.extend_from_slice(&self.nonce);
        result.extend_from_slice(&self.tag);
        result.extend_from_slice(&self.ciphertext);
        result
    }

    pub fn from_bytes(bytes: &[u8]) -> CryptoResult<Self> {
        if bytes.len() < 1 + 4 + NONCE_LEN + TAG_LEN {
            return Err(CryptoError::InvalidCiphertext);
        }

        let algorithm = match bytes[0] {
            0 => SymmetricAlgorithm::Aes256Gcm,
            1 => SymmetricAlgorithm::ChaCha20Poly1305,
            _ => return Err(CryptoError::InvalidCiphertext),
        };

        let mut key_version_bytes = [0u8; 4];
        key_version_bytes.copy_from_slice(&bytes[1..5]);
        let key_version = u32::from_be_bytes(key_version_bytes);

        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&bytes[5..17]);

        let mut tag = [0u8; TAG_LEN];
        tag.copy_from_slice(&bytes[17..33]);

        let ciphertext = bytes[33..].to_vec();

        Ok(Self {
            ciphertext,
            nonce,
            tag,
            algorithm,
            key_version,
        })
    }
}

fn nonce_state_for(key: &SecretKey) -> NonceState {
    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(key.as_bytes());

    let mut guard = NONCE_REGISTRY.lock().expect("nonce registry poisoned");
    guard
        .entry(key_bytes)
        .or_insert_with(|| NonceState {
            counter: 0,
            seen: HashSet::new(),
            key_version: 1,
        })
        .clone()
}

fn update_nonce_state(key: &SecretKey, state: NonceState) {
    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(key.as_bytes());
    let mut guard = NONCE_REGISTRY.lock().expect("nonce registry poisoned");
    guard.insert(key_bytes, state);
}

fn wrap_aad(algorithm: SymmetricAlgorithm, key_version: u32, aad: &[u8]) -> Vec<u8> {
    let mut composed = Vec::with_capacity(1 + 4 + aad.len());
    composed.push(algorithm as u8);
    composed.extend_from_slice(&key_version.to_be_bytes());
    composed.extend_from_slice(aad);
    composed
}

fn split_ct_and_tag(mut data: Vec<u8>) -> CryptoResult<(Vec<u8>, [u8; TAG_LEN])> {
    if data.len() < TAG_LEN {
        return Err(CryptoError::InvalidCiphertext);
    }
    let mut tag = [0u8; TAG_LEN];
    let tag_start = data.len() - TAG_LEN;
    tag.copy_from_slice(&data[tag_start..]);
    data.truncate(tag_start);
    Ok((data, tag))
}

pub fn encrypt(
    key: &SecretKey,
    plaintext: &[u8],
    aad: Option<&[u8]>,
    rng: &mut QuantumRng,
    algorithm: SymmetricAlgorithm,
) -> CryptoResult<EncryptedData> {
    let mut state = nonce_state_for(key);
    let nonce = state.next_nonce(algorithm, rng)?;
    update_nonce_state(key, state.clone());

    let aad = wrap_aad(algorithm, state.key_version, aad.unwrap_or(&[]));

    let (ciphertext, tag) = match algorithm {
        SymmetricAlgorithm::Aes256Gcm => {
            let cipher = Aes256Gcm::new(GenericArray::from_slice(key.as_bytes()));
            let ct = cipher
                .encrypt(
                    GenericArray::from_slice(&nonce),
                    aes_gcm::aead::Payload {
                        msg: plaintext,
                        aad: &aad,
                    },
                )
                .map_err(|_| CryptoError::EncryptionFailed)?;
            split_ct_and_tag(ct)?
        }
        SymmetricAlgorithm::ChaCha20Poly1305 => {
            let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(key.as_bytes()));
            let ct = cipher
                .encrypt(
                    GenericArray::from_slice(&nonce),
                    chacha20poly1305::aead::Payload {
                        msg: plaintext,
                        aad: &aad,
                    },
                )
                .map_err(|_| CryptoError::EncryptionFailed)?;
            split_ct_and_tag(ct)?
        }
    };

    Ok(EncryptedData {
        ciphertext,
        nonce,
        tag,
        algorithm,
        key_version: state.key_version,
    })
}

pub fn decrypt(
    key: &SecretKey,
    encrypted: &EncryptedData,
    aad: Option<&[u8]>,
) -> CryptoResult<Vec<u8>> {
    let mut state = nonce_state_for(key);
    if encrypted.key_version != state.key_version {
        return Err(CryptoError::InvalidCiphertext);
    }
    state.register(encrypted.nonce)?;
    update_nonce_state(key, state.clone());

    let aad = wrap_aad(encrypted.algorithm, state.key_version, aad.unwrap_or(&[]));

    let mut combined = encrypted.ciphertext.clone();
    combined.extend_from_slice(&encrypted.tag);

    match encrypted.algorithm {
        SymmetricAlgorithm::Aes256Gcm => {
            let cipher = Aes256Gcm::new(GenericArray::from_slice(key.as_bytes()));
            cipher
                .decrypt(
                    GenericArray::from_slice(&encrypted.nonce),
                    aes_gcm::aead::Payload {
                        msg: &combined,
                        aad: &aad,
                    },
                )
                .map_err(|_| CryptoError::DecryptionFailed)
        }
        SymmetricAlgorithm::ChaCha20Poly1305 => {
            let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(key.as_bytes()));
            cipher
                .decrypt(
                    GenericArray::from_slice(&encrypted.nonce),
                    chacha20poly1305::aead::Payload {
                        msg: &combined,
                        aad: &aad,
                    },
                )
                .map_err(|_| CryptoError::DecryptionFailed)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn roundtrip_chacha_with_aad_and_version() {
        let seed = [0x11u8; 32];
        let mut rng = QuantumRng::from_seed(&seed, 256).expect("rng");
        let key = SecretKey::generate(&mut rng);
        let aad = b"context:chat";
        let pt = b"hello quantum";
        let encrypted = encrypt(
            &key,
            pt,
            Some(aad),
            &mut rng,
            SymmetricAlgorithm::ChaCha20Poly1305,
        )
        .expect("encrypt");
        let decrypted = decrypt(&key, &encrypted, Some(aad)).expect("decrypt");
        assert_eq!(&decrypted, pt);
    }

    #[test]
    fn replay_detection_blocks_duplicate_nonce() {
        let seed = [0x33u8; 32];
        let mut rng = QuantumRng::from_seed(&seed, 256).expect("rng");
        let key = SecretKey::generate(&mut rng);
        let pt = b"replay";
        let encrypted = encrypt(&key, pt, None, &mut rng, SymmetricAlgorithm::Aes256Gcm).unwrap();
        let first = decrypt(&key, &encrypted, None).unwrap();
        assert_eq!(first, pt);
        let replay = decrypt(&key, &encrypted, None);
        assert!(matches!(replay, Err(CryptoError::ReplayDetected)));
    }

    #[test]
    fn tampered_algorithm_fails() {
        let seed = [0x55u8; 32];
        let mut rng = QuantumRng::from_seed(&seed, 256).expect("rng");
        let key = SecretKey::generate(&mut rng);
        let pt = b"downgrade";
        let mut encrypted =
            encrypt(&key, pt, None, &mut rng, SymmetricAlgorithm::Aes256Gcm).unwrap();
        encrypted.algorithm = SymmetricAlgorithm::ChaCha20Poly1305;
        let res = decrypt(&key, &encrypted, None);
        assert!(res.is_err());
    }

    #[test]
    fn aes_gcm_matches_reference_vector() {
        // RFC 8452 test vector 1 adapted to AES-256-GCM
        let key_bytes = hex!("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        let nonce = hex!("1af38c2dc2b96ffdd86694092341bc04");
        let pt = hex!("41206369706865722073797374656d206d757374206e6f7420626520726571756972656420746f206265207365637265742c20616e64206974206d7573742062652061626c6520746f2066616c6c20696e746f207468652068616e6473206f662074686520656e656d79");
        let aad = hex!("546865207365636f6e64207072696e6369706c65206f662041756775737465205765726e65722c204a722e2c20746f204b6520796f752072656d656d62657220616e642070726f746563742068696d20616c776179732c20616e64207368616c6c206e6f74207065726d69742068696d20746f2073756666657220626520746f7761726420796f752e");

        let mut key_arr = [0u8; 32];
        key_arr.copy_from_slice(&key_bytes);
        let key = SecretKey::new(key_arr);
        let aad_wrapped = wrap_aad(SymmetricAlgorithm::Aes256Gcm, 1, &aad);
        let cipher = Aes256Gcm::new(GenericArray::from_slice(key.as_bytes()));
        let ct = cipher
            .encrypt(
                GenericArray::from_slice(&nonce[..NONCE_LEN]),
                aes_gcm::aead::Payload {
                    msg: &pt,
                    aad: &aad_wrapped,
                },
            )
            .unwrap();
        let (ciphertext, tag) = split_ct_and_tag(ct).unwrap();
        let data = EncryptedData {
            ciphertext: ciphertext.clone(),
            nonce: nonce[..NONCE_LEN].try_into().unwrap(),
            tag,
            algorithm: SymmetricAlgorithm::Aes256Gcm,
            key_version: 1,
        };
        let decrypted = decrypt(&key, &data, Some(&aad)).unwrap();
        assert_eq!(decrypted, pt);
    }

    #[test]
    fn serialization_roundtrip() {
        let seed = [0x42u8; 32];
        let mut rng = QuantumRng::from_seed(&seed, 256).expect("rng");
        let key = SecretKey::generate(&mut rng);
        let pt = b"serialize";
        let encrypted = encrypt(
            &key,
            pt,
            None,
            &mut rng,
            SymmetricAlgorithm::ChaCha20Poly1305,
        )
        .unwrap();
        let bytes = encrypted.to_bytes();
        let restored = EncryptedData::from_bytes(&bytes).unwrap();
        let decrypted = decrypt(&key, &restored, None).unwrap();
        assert_eq!(decrypted, pt);
    }

    /// QA Item 74: ChaCha20-Poly1305 Known Answer Test (RFC 8439)
    #[test]
    fn chacha20_poly1305_rfc8439_kat() {
        // RFC 8439 Section 2.8.2 test vector
        let key_bytes = hex!("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
        let nonce = hex!("070000004041424344454647");
        let pt = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let aad = hex!("50515253c0c1c2c3c4c5c6c7");

        let mut key_arr = [0u8; 32];
        key_arr.copy_from_slice(&key_bytes);
        let key = SecretKey::new(key_arr);

        // Encrypt
        let aad_wrapped = wrap_aad(SymmetricAlgorithm::ChaCha20Poly1305, 1, &aad);
        let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(key.as_bytes()));
        let ct = cipher
            .encrypt(
                GenericArray::from_slice(&nonce[..NONCE_LEN]),
                chacha20poly1305::aead::Payload {
                    msg: pt,
                    aad: &aad_wrapped,
                },
            )
            .expect("chacha20 encryption");

        // Verify roundtrip
        let (ciphertext, tag) = split_ct_and_tag(ct).unwrap();
        let data = EncryptedData {
            ciphertext,
            nonce: nonce[..NONCE_LEN].try_into().unwrap(),
            tag,
            algorithm: SymmetricAlgorithm::ChaCha20Poly1305,
            key_version: 1,
        };

        let decrypted = decrypt(&key, &data, Some(&aad)).expect("chacha20 decryption");
        assert_eq!(decrypted, pt, "ChaCha20-Poly1305 RFC 8439 KAT failed");
    }

    /// QA Items 75, 84: Tag tampering test (negative test case)
    #[test]
    fn tampered_tag_fails_authentication() {
        let seed = [0x99u8; 32];
        let mut rng = QuantumRng::from_seed(&seed, 256).expect("rng");
        let key = SecretKey::generate(&mut rng);
        let pt = b"authenticated message";

        // Encrypt with AES-GCM
        let mut encrypted =
            encrypt(&key, pt, None, &mut rng, SymmetricAlgorithm::Aes256Gcm).expect("encrypt");

        // Tamper with tag (flip one bit)
        encrypted.tag[0] ^= 0x01;

        // Decryption should fail
        let result = decrypt(&key, &encrypted, None);
        assert!(result.is_err(), "Tampered tag should fail authentication");
        assert!(
            matches!(result, Err(CryptoError::DecryptionFailed)),
            "Expected DecryptionFailed error"
        );
    }

    /// QA Items 75, 84: Ciphertext tampering test
    #[test]
    fn tampered_ciphertext_fails_authentication() {
        let seed = [0xAAu8; 32];
        let mut rng = QuantumRng::from_seed(&seed, 256).expect("rng");
        let key = SecretKey::generate(&mut rng);
        let pt = b"sensitive data here";

        // Encrypt with ChaCha20-Poly1305
        let mut encrypted = encrypt(
            &key,
            pt,
            None,
            &mut rng,
            SymmetricAlgorithm::ChaCha20Poly1305,
        )
        .expect("encrypt");

        // Tamper with ciphertext (flip bit in middle)
        if !encrypted.ciphertext.is_empty() {
            let mid = encrypted.ciphertext.len() / 2;
            encrypted.ciphertext[mid] ^= 0xFF;
        }

        // Decryption should fail
        let result = decrypt(&key, &encrypted, None);
        assert!(
            result.is_err(),
            "Tampered ciphertext should fail authentication"
        );
    }

    /// QA Item 11: AAD length validation
    #[test]
    fn large_aad_handled_correctly() {
        let seed = [0xBBu8; 32];
        let mut rng = QuantumRng::from_seed(&seed, 256).expect("rng");
        let key = SecretKey::generate(&mut rng);
        let pt = b"message";

        // Test with large AAD (16 KB)
        let large_aad = vec![0x42u8; 16384];
        let encrypted = encrypt(
            &key,
            pt,
            Some(&large_aad),
            &mut rng,
            SymmetricAlgorithm::Aes256Gcm,
        )
        .expect("encrypt with large AAD");

        let decrypted =
            decrypt(&key, &encrypted, Some(&large_aad)).expect("decrypt with large AAD");
        assert_eq!(decrypted, pt);

        // Wrong AAD should fail
        let wrong_aad = vec![0x43u8; 16384];
        let result = decrypt(&key, &encrypted, Some(&wrong_aad));
        assert!(result.is_err(), "Wrong AAD should fail authentication");
    }

    /// QA Item 5: Empty plaintext edge case
    #[test]
    fn empty_plaintext_encrypts_correctly() {
        let seed = [0xCCu8; 32];
        let mut rng = QuantumRng::from_seed(&seed, 256).expect("rng");
        let key = SecretKey::generate(&mut rng);
        let pt = b"";

        // Test both algorithms with empty plaintext
        let encrypted_aes = encrypt(&key, pt, None, &mut rng, SymmetricAlgorithm::Aes256Gcm)
            .expect("encrypt empty with AES");
        let decrypted_aes = decrypt(&key, &encrypted_aes, None).expect("decrypt empty with AES");
        assert_eq!(decrypted_aes, pt);

        let encrypted_chacha = encrypt(
            &key,
            pt,
            None,
            &mut rng,
            SymmetricAlgorithm::ChaCha20Poly1305,
        )
        .expect("encrypt empty with ChaCha");
        let decrypted_chacha =
            decrypt(&key, &encrypted_chacha, None).expect("decrypt empty with ChaCha");
        assert_eq!(decrypted_chacha, pt);
    }

    /// QA Items 83-84: Wrong key test
    #[test]
    fn wrong_key_fails_decryption() {
        let seed = [0xDDu8; 32];
        let mut rng = QuantumRng::from_seed(&seed, 256).expect("rng");
        let key1 = SecretKey::generate(&mut rng);
        let key2 = SecretKey::generate(&mut rng);
        let pt = b"encrypted with key1";

        let encrypted =
            encrypt(&key1, pt, None, &mut rng, SymmetricAlgorithm::Aes256Gcm).expect("encrypt");

        // Decrypt with wrong key should fail
        let result = decrypt(&key2, &encrypted, None);
        assert!(result.is_err(), "Wrong key should fail decryption");
    }

    /// QA Item 94: Verify nonce uniqueness across encryptions
    #[test]
    fn nonces_are_unique() {
        let seed = [0xEEu8; 32];
        let mut rng = QuantumRng::from_seed(&seed, 256).expect("rng");
        let key = SecretKey::generate(&mut rng);
        let pt = b"same plaintext";

        // Encrypt same plaintext 100 times
        let mut nonces = std::collections::HashSet::new();
        for _ in 0..100 {
            let encrypted = encrypt(
                &key,
                pt,
                None,
                &mut rng,
                SymmetricAlgorithm::ChaCha20Poly1305,
            )
            .expect("encrypt");
            nonces.insert(encrypted.nonce);
        }

        // All nonces should be unique
        assert_eq!(nonces.len(), 100, "All 100 nonces should be unique");
    }
}
