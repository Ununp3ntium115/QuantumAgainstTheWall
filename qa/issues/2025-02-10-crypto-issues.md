# GitHub Issue Drafts – Crypto QA Remediations (2025-02-10)

These drafts convert the 2025-02-10 crypto QA findings into ready-to-file GitHub issues. Each entry links to the observed problem, proposes a fix with pseudocode, and lists acceptance criteria.

## Issue 1 — Replace custom AEADs with vetted crates
- **Problem**: Hand-rolled AES-GCM/ChaCha20-Poly1305 (`src/crypto/symmetric.rs`) lacks vetted side-channel protections and thorough vector coverage.
- **Fix outline**: Swap implementations for `aes-gcm` and `chacha20poly1305` crates; keep module API but wrap library types.
- **Pseudocode**:
  ```rust
  use aes_gcm::Aes256Gcm;
  use chacha20poly1305::ChaCha20Poly1305;

  pub enum Cipher { Aes(Aes256Gcm), ChaCha(ChaCha20Poly1305) }

  pub fn encrypt(&self, key: &[u8], nonce: &[u8], aad: &[u8], pt: &[u8]) -> Result<Vec<u8>> {
      match self {
          Cipher::Aes(c) => c.encrypt(nonce.into(), Payload { aad, msg: pt }),
          Cipher::ChaCha(c) => c.encrypt(nonce.into(), Payload { aad, msg: pt }),
      }.map_err(Error::Crypto)
  }
  ```
- **Acceptance**: Library-backed AEAD passes RFC/NIST KATs; custom code paths removed; CI exercises both modes.

## Issue 2 — Enforce nonce uniqueness and replay protection
- **Problem**: Nonce reuse is unchecked for AEAD and X25519 sealing flows, enabling tag forgery/replay.
- **Fix outline**: Store a 64-bit counter per key, mix with RNG entropy, and reject decrypts on seen nonces.
- **Pseudocode**:
  ```rust
  struct NonceState { counter: u64, seen: HashSet<[u8;12]> }

  fn next_nonce(state: &mut NonceState, rng: &mut RngCore) -> [u8; 12] {
      let mut nonce = [0u8; 12];
      nonce[..8].copy_from_slice(&state.counter.to_be_bytes());
      rng.fill_bytes(&mut nonce[8..]);
      state.counter = state.counter.checked_add(1).expect("nonce counter overflow");
      nonce
  }

  fn reject_replay(state: &mut NonceState, nonce: &[u8;12]) -> Result<()> {
      if !state.seen.insert(*nonce) { return Err(Error::Replay); }
      Ok(())
  }
  ```
- **Acceptance**: Nonce counters persisted with keys; decrypt rejects repeated nonces; rollover handled.

## Issue 3 — Harden RNG entropy and reseeding
- **Problem**: RNG initialization accepts low-entropy seeds and lacks reseed/zeroize hooks.
- **Fix outline**: Require ≥128 bits of entropy, add periodic reseed from OS RNG, and zeroize buffers on drop.
- **Pseudocode**:
  ```rust
  const MIN_ENTROPY_BITS: u32 = 128;

  fn init(seed: &[u8], entropy_bits: u32) -> Result<Self> {
      if entropy_bits < MIN_ENTROPY_BITS { return Err(Error::LowEntropy); }
      Ok(Self { state: chacha20(seed), counter: 0 })
  }

  fn reseed(&mut self) -> Result<()> {
      let fresh: [u8; 32] = getrandom()?;
      self.state = chacha20_mix(&self.state, &fresh);
      Ok(())
  }

  impl Drop for Rng {
      fn drop(&mut self) { self.state.zeroize(); }
  }
  ```
- **Acceptance**: RNG rejects weak seeds, supports reseed API, and zeroizes internal state.

## Issue 4 — Align Argon2id prehash with RFC 9106
- **Problem**: Custom Argon2id prehash uses SHA-256 instead of BLAKE2b and omits version/type tagging.
- **Fix outline**: Implement RFC 9106 H0 with BLAKE2b, domain-separate inputs, and validate via KATs.
- **Pseudocode**:
  ```rust
  fn h0(params: &Params, pwd: &[u8], salt: &[u8], secret: &[u8], ad: &[u8]) -> [u8; 64] {
      let mut h = blake2b_simd::Params::new().hash_length(64).to_state();
      h.update(&params.little_endian());
      h.update(pwd);
      h.update(salt);
      h.update(secret);
      h.update(ad);
      h.finalize().as_bytes().try_into().unwrap()
  }
  ```
- **Acceptance**: H0 matches RFC 9106 vectors; Argon2id outputs verified against official KATs.

## Issue 5 — Use constant-time X25519 primitives
- **Problem**: Custom field operations (`src/crypto/keys.rs`) risk timing leakage and lack zeroization guarantees.
- **Fix outline**: Replace arithmetic with `x25519-dalek`/`curve25519-dalek`, zeroize intermediates, and keep API stable.
- **Pseudocode**:
  ```rust
  use x25519_dalek::{EphemeralSecret, PublicKey};

  pub fn key_exchange(pk_bytes: &[u8;32], sk_bytes: &[u8;32]) -> Result<[u8;32]> {
      let sk = EphemeralSecret::from(*sk_bytes);
      let pk = PublicKey::from(*pk_bytes);
      let shared = sk.diffie_hellman(&pk);
      let mut out = shared.as_bytes().clone();
      out.zeroize(); // after HKDF extraction
      Ok(out)
  }
  ```
- **Acceptance**: Montgomery ladder removed from local code; zeroization added; KATs from RFC 7748 pass.

## Issue 6 — Validate GHASH/Poly1305 with vectors
- **Problem**: GHASH (`gf_mul`) and Poly1305 reductions are unproven against authoritative vectors.
- **Fix outline**: Add NIST SP 800-38D GHASH vectors and RFC 8439 Poly1305 tests; fail build on mismatch.
- **Pseudocode**:
  ```rust
  #[test]
  fn ghash_nist_kats() {
      for case in load_nist_vectors() {
          assert_eq!(ghash(case.h, &case.aad, &case.ct), case.tag);
      }
  }
  ```
- **Acceptance**: Test suite includes GHASH and Poly1305 KATs; CI blocks on failures.

## Issue 7 — Bind algorithm identifiers into AAD
- **Problem**: Serialized key/algorithm selection is not authenticated, allowing downgrade or misbind attacks.
- **Fix outline**: Include algorithm ID, key version, and context string in AEAD AAD; reject mismatches.
- **Pseudocode**:
  ```rust
  fn wrap_aad(algo_id: u8, key_version: u32, context: &[u8]) -> Vec<u8> {
      [algo_id.to_be_bytes().as_slice(), &key_version.to_be_bytes(), context]
          .concat()
  }

  let aad = wrap_aad(ALGO_AES_GCM, current_key_version, b"session:chat");
  let ct = cipher.encrypt(nonce, Payload { aad: &aad, msg: pt })?;
  ```
- **Acceptance**: All encrypt/decrypt paths require authenticated algorithm metadata; downgrade attempts fail tests.

## Issue 8 — Document misuse limits and rotation
- **Problem**: AES-GCM/ChaCha20 modes lack documented limits for nonce space, key rotation, and throughput.
- **Fix outline**: Add per-algorithm guidance to docs and enforce counters that refuse operation past safe limits.
- **Pseudocode**:
  ```rust
  const MAX_AES_GCM_MESSAGES: u64 = 1 << 32;
  if key_ctx.nonce_counter >= MAX_AES_GCM_MESSAGES {
      return Err(Error::NonceExhausted);
  }
  ```
- **Acceptance**: Limits are documented in SECURITY_ANALYSIS and enforced in code; exceeding them errors explicitly.

## Issue 9 — CI pipeline for crypto invariants
- **Problem**: No automated coverage for KATs, fuzzing, or property tests tied to the 100-item checklist.
- **Fix outline**: Add CI workflow running cargo tests, KAT suites, fuzzing smoke, and lint for `#![forbid(unsafe_code)]`.
- **Pseudocode**:
  ```yaml
  - run: cargo test --all --features "kat"
  - run: cargo fmt --check
  - run: cargo clippy -- -D warnings
  ```
- **Acceptance**: CI required on PRs; fails on missing vectors, lint errors, or unsafe code violations.
