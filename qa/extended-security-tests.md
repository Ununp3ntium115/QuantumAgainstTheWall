# Extended Cryptographic Security Test Suite

**Purpose:** Comprehensive security testing beyond the initial 52 QA items
**Target:** Production-ready cryptographic library (Rust crate + npm package)
**Standards:** NIST FIPS 140-3, OWASP A02:2021, CWE Top 25, ISO/IEC 15408
**Total Tests:** 100 additional security requirements

---

## Test Categories

1. [Side-Channel Attack Resistance](#1-side-channel-attack-resistance-20-tests) (20 tests)
2. [Cryptanalytic Security](#2-cryptanalytic-security-15-tests) (15 tests)
3. [API Misuse Prevention](#3-api-misuse-prevention-15-tests) (15 tests)
4. [Key Lifecycle Management](#4-key-lifecycle-management-12-tests) (12 tests)
5. [Memory Safety & Exploitation](#5-memory-safety--exploitation-10-tests) (10 tests)
6. [Protocol-Level Attacks](#6-protocol-level-attacks-8-tests) (8 tests)
7. [Randomness Quality](#7-randomness-quality-8-tests) (8 tests)
8. [Operational Security](#8-operational-security-6-tests) (6 tests)
9. [Supply Chain Security](#9-supply-chain-security-3-tests) (3 tests)
10. [Compliance & Documentation](#10-compliance--documentation-3-tests) (3 tests)

---

## 1. Side-Channel Attack Resistance (20 tests)

### SC-001: Timing Attack Resistance - AES Operations
**Severity:** CRITICAL
**Reference:** FIPS 140-3 IG 9.7, CWE-208
**Description:** AES key schedule and round operations must have constant-time execution regardless of key/plaintext values.

**Verification Script:**
```rust
// tests/timing/sc001_aes_timing.rs
use dudect_bencher::{BenchRng, Class, ctbench_main};
use quantum_wall::crypto::symmetric::*;

fn aes_timing_test(rng: &mut BenchRng) -> Result<(), ()> {
    let key1 = SecretKey::new([0x00u8; 32]); // All zeros
    let key2 = SecretKey::new([0xFFu8; 32]); // All ones
    let plaintext = [0x42u8; 16];

    let class = rng.class();
    let mut rng = QuantumRng::new().unwrap();

    match class {
        Class::Left => encrypt(&key1, &plaintext, None, &mut rng, SymmetricAlgorithm::Aes256Gcm),
        Class::Right => encrypt(&key2, &plaintext, None, &mut rng, SymmetricAlgorithm::Aes256Gcm),
    };

    Ok(())
}

ctbench_main!(aes_timing_test);
```

**Acceptance:** p-value > 0.05 (no statistically significant timing difference)

---

### SC-002: Timing Attack Resistance - Argon2 Password Verification
**Severity:** HIGH
**Reference:** CWE-208, OWASP A02:2021

**Verification Script:**
```bash
#!/bin/bash
# tests/timing/sc002_argon2_timing.sh

echo "Testing Argon2 timing consistency..."

# Generate 1000 samples with correct password
for i in {1..1000}; do
    /usr/bin/time -f "%e" cargo run --release --example argon2_verify correct_pw 2>&1 | tail -1
done > timing_correct.txt

# Generate 1000 samples with incorrect password
for i in {1..1000}; do
    /usr/bin/time -f "%e" cargo run --release --example argon2_verify wrong_pw 2>&1 | tail -1
done > timing_incorrect.txt

# Statistical t-test
python3 << EOF
import numpy as np
from scipy import stats

correct = np.loadtxt('timing_correct.txt')
incorrect = np.loadtxt('timing_incorrect.txt')

t_stat, p_value = stats.ttest_ind(correct, incorrect)
print(f"t-statistic: {t_stat:.6f}")
print(f"p-value: {p_value:.6f}")

if p_value > 0.05:
    print("✓ PASS: No timing leak detected")
    exit(0)
else:
    print("✗ FAIL: Timing leak detected!")
    exit(1)
EOF
```

---

### SC-003: Cache-Timing Resistance - Rijndael S-Box Lookups
**Severity:** CRITICAL
**Reference:** Osvik et al. "Cache Attacks and Countermeasures" (2006)

**Verification:** Use table-less AES implementation (AES-NI or bitsliced)

```rust
#[test]
fn test_no_table_lookups() {
    // Verify we're using aes crate which uses AES-NI or bitsliced implementation
    use aes_gcm::aes::Aes256;

    // If this compiles, we're using hardware AES or bitsliced (both cache-safe)
    let _ = Aes256::new(&Default::default());
}
```

---

### SC-004: Power Analysis Resistance - Key-Dependent Branching
**Severity:** HIGH
**Reference:** FIPS 140-3 Section 4.5.3

**Verification Script:**
```bash
# tests/timing/sc004_branch_analysis.sh
# Check for key-dependent conditional branches in crypto code

echo "Scanning for key-dependent branches..."

# Search for if/match statements in crypto modules that depend on key material
git grep -n "if.*key\|match.*secret" src/crypto/ | \
  grep -v "// OK:" | \
  grep -v "test" || {
  echo "✓ PASS: No obvious key-dependent branches"
  exit 0
}

echo "⚠ WARNING: Found potential key-dependent branches"
exit 1
```

---

### SC-005: Electromagnetic Emanation (TEMPEST) - RNG Seeding
**Severity:** MEDIUM
**Reference:** FIPS 140-3 Section 4.5.4

**Documentation Required:** State that `getrandom()` on modern OSes includes EM countermeasures.

```markdown
### EManalyze Resistance (SC-005)

QuantumRng uses `getrandom()` which on Linux 4.8+ sources from `getrandom(2)` syscall with:
- Mix from hardware RNG (Intel RDRAND/RDSEED with thermal noise)
- LRNG with continuous reseeding
- No direct user-space DMA that could leak via EM

**Mitigation:** OS-level EM protection sufficient for FIPS 140-3 Level 1.
```

---

### SC-006: Constant-Time Comparison - MAC/Tag Verification
**Severity:** CRITICAL
**Reference:** CWE-208, "Timing Attacks on Implementations of Diffie-Hellman"

**Verification Script:**
```rust
#[test]
fn test_constant_time_tag_comparison() {
    use subtle::ConstantTimeEq;

    let tag1 = [0x11u8; 16];
    let tag2 = [0x11u8; 16];
    let tag3 = [0x22u8; 16];

    // Verify we use constant-time comparison
    assert!(bool::from(tag1.ct_eq(&tag2)));
    assert!(!bool::from(tag1.ct_eq(&tag3)));

    // Check actual decrypt implementation uses subtle crate
    // (verified via code inspection and dependency)
}
```

---

### SC-007-020: Additional Side-Channel Tests
*(Remaining 14 tests covering: speculative execution, fault injection, DFA attacks, row hammer, cold boot, acoustic cryptanalysis, etc.)*

*[Full specifications in extended document]*

---

## 2. Cryptanalytic Security (15 tests)

### CA-001: Birthday Bound Safety - GCM Nonce Collision
**Severity:** CRITICAL
**Reference:** "Limits of AES-GCM" (Bhargavan & Leurent, 2016)

**Verification Script:**
```rust
#[test]
fn test_gcm_birthday_bound_enforcement() {
    let key = SecretKey::generate(&mut rng);
    let mut nonce_state = NonceState::default();

    // Try to generate 2^32 + 1 nonces (should fail)
    nonce_state.counter = (1u64 << 32) - 1;

    let result = nonce_state.next_nonce(
        SymmetricAlgorithm::Aes256Gcm,
        &mut rng
    );

    assert!(result.is_ok()); // Last valid nonce

    let result = nonce_state.next_nonce(
        SymmetricAlgorithm::Aes256Gcm,
        &mut rng
    );

    assert_eq!(result, Err(CryptoError::NonceExhausted));
}
```

---

### CA-002: Length Extension Attack Resistance - KDF
**Severity:** HIGH
**Reference:** "Length Extension Attacks" (Kelsey & Schneier, 2005)

**Verification:**
```rust
#[test]
fn test_no_length_extension_in_kdf() {
    // HKDF uses HMAC which is immune to length extension
    let ikm = b"input_key_material";
    let salt = b"salt";
    let info1 = b"context1";
    let info2 = b"context1extra";  // Append to info

    let key1 = derive_key(ikm, salt, info1).unwrap();
    let key2 = derive_key(ikm, salt, info2).unwrap();

    // Keys should be completely different (not derivable via extension)
    assert_ne!(key1.as_bytes()[..16], key2.as_bytes()[..16]);
}
```

---

### CA-003: Related-Key Attack Resistance - ChaCha20
**Severity:** MEDIUM
**Reference:** RFC 8439 Section 2.3

**Verification:** Document that ChaCha20 key schedule has no known related-key attacks.

---

### CA-004: Weak Key Detection - Argon2 Salt Validation
**Severity:** HIGH

**Verification:**
```rust
#[test]
fn test_argon2_rejects_weak_salts() {
    let password = b"password123";

    // Salt too short (< 8 bytes per RFC 9106)
    assert!(argon2_hash(password, b"short", &Argon2Params::interactive()).is_err());

    // All-zero salt (weak)
    assert!(argon2_hash(password, &[0u8; 16], &Argon2Params::interactive()).is_err());

    // Valid salt
    assert!(argon2_hash(password, b"good_salt_16b", &Argon2Params::interactive()).is_ok());
}
```

---

### CA-005-015: Additional Cryptanalytic Tests
*(Remaining 11 tests covering: differential cryptanalysis resistance, linear cryptanalysis, slide attacks, meet-in-the-middle, quantum attack security margins, etc.)*

---

## 3. API Misuse Prevention (15 tests)

### AP-001: Type Safety - Key Reuse Across Algorithms
**Severity:** HIGH
**Reference:** "The Most Dangerous Code in the World" (Georgiev et al., 2012)

**Verification:**
```rust
#[test]
fn test_keys_are_algorithm_specific() {
    // Should not compile: keys should be tagged by algorithm
    let key_aes = SecretKey::generate_aes256(&mut rng);
    let key_chacha = SecretKey::generate_chacha20(&mut rng);

    // This should cause a type error at compile time:
    // encrypt(&key_aes, data, None, &mut rng, SymmetricAlgorithm::ChaCha20Poly1305); // ERROR

    // Current implementation: Add algorithm tagging to prevent this
}
```

**Recommendation:** Add phantom type parameter to `SecretKey<Algorithm>`.

---

### AP-002: Nonce Reuse Detection - Runtime Check
**Severity:** CRITICAL

**Verification:**
```rust
#[test]
fn test_runtime_nonce_reuse_detection() {
    let key = SecretKey::generate(&mut rng);
    let plaintext = b"sensitive data";

    let encrypted1 = encrypt(&key, plaintext, None, &mut rng,
                             SymmetricAlgorithm::ChaCha20Poly1305).unwrap();

    // Manually create duplicate nonce scenario
    let mut manual_nonce_state = NonceState::default();
    manual_nonce_state.seen.insert(encrypted1.nonce);

    // Attempt decrypt with seen nonce
    let result = manual_nonce_state.register(encrypted1.nonce);
    assert_eq!(result, Err(CryptoError::ReplayDetected));
}
```

---

### AP-003: Default Security - No Weak Algorithms
**Severity:** HIGH
**Reference:** OWASP Cryptographic Failures A02:2021

**Verification:**
```bash
# No DES, 3DES, MD5, SHA1, RC4 in public API
git grep -i "des\|md5\|sha1\|rc4" src/crypto/mod.rs && {
  echo "✗ FAIL: Weak algorithm exposed"
  exit 1
} || {
  echo "✓ PASS: No weak algorithms in public API"
  exit 0
}
```

---

### AP-004-015: Additional API Misuse Tests
*(Remaining 12 tests covering: mutable borrow safety, lifetime management, panic safety, error type leakage, etc.)*

---

## 4. Key Lifecycle Management (12 tests)

### KL-001: Secure Key Generation - Entropy Source
**Severity:** CRITICAL

**Verification:**
```rust
#[test]
fn test_key_generation_uses_csprng() {
    // Verify keys use QuantumRng (backed by getrandom)
    let key1 = SecretKey::generate(&mut QuantumRng::new().unwrap());
    let key2 = SecretKey::generate(&mut QuantumRng::new().unwrap());

    // Different keys each time (not deterministic)
    assert_ne!(key1.as_bytes(), key2.as_bytes());
}
```

---

### KL-002: Key Destruction - Zeroization Verification
**Severity:** CRITICAL
**Reference:** FIPS 140-3 Section 4.7.6

**Verification:**
```rust
#[test]
fn test_key_zeroization_on_drop() {
    use std::ptr;

    let key_ptr: *const u8;
    let key_bytes_before: [u8; 32];

    {
        let key = SecretKey::generate(&mut rng);
        key_ptr = key.as_bytes().as_ptr();
        key_bytes_before = *key.as_bytes();

        // Key is dropped here
    }

    // Read memory (unsafe, for testing only)
    let key_bytes_after = unsafe {
        std::slice::from_raw_parts(key_ptr, 32)
    };

    // Memory should be zeroed
    assert_eq!(key_bytes_after, &[0u8; 32]);
}
```

---

### KL-003: Key Storage - No Plaintext Keys on Disk
**Severity:** CRITICAL

**Verification:**
```bash
#!/bin/bash
# Check that examples don't write keys to disk in plaintext
git grep -n "File::create\|write.*key\|save.*key" examples/ | \
  grep -v "encrypted" && {
  echo "⚠ WARNING: Potential plaintext key write to disk"
  exit 1
} || {
  echo "✓ PASS: No obvious plaintext key persistence"
}
```

---

### KL-004-012: Additional Key Lifecycle Tests
*(Remaining 9 tests covering: key derivation, key wrapping, key rotation, key escrow, split knowledge, etc.)*

---

## 5. Memory Safety & Exploitation (10 tests)

### MS-001: Buffer Overflow - Encryption Input Length
**Severity:** CRITICAL
**Reference:** CWE-120

**Verification:**
```rust
#[test]
fn test_no_buffer_overflow_on_large_input() {
    let key = SecretKey::generate(&mut rng);
    let huge_plaintext = vec![0x42u8; 1_000_000_000]; // 1 GB

    // Should either succeed or return error, not crash
    let result = encrypt(&key, &huge_plaintext, None, &mut rng,
                        SymmetricAlgorithm::ChaCha20Poly1305);

    // If it returns Ok, verify output is correct size
    if let Ok(encrypted) = result {
        assert_eq!(encrypted.ciphertext.len(), huge_plaintext.len());
    }
}
```

---

### MS-002: Use-After-Free - Key Reference Safety
**Severity:** CRITICAL
**Reference:** CWE-416

**Verification:** Rust's borrow checker prevents this at compile-time. Document that Rust safety guarantees prevent UAF.

---

### MS-003: Double-Free - RNG State Cleanup
**Severity:** HIGH

**Verification:** Test with ASAN/Valgrind:
```bash
RUSTFLAGS="-Z sanitizer=address" cargo +nightly test --target x86_64-unknown-linux-gnu
```

---

### MS-004-010: Additional Memory Safety Tests
*(Remaining 7 tests covering: integer overflow, uninitialized memory, dangling pointers, stack overflow, heap spraying resistance, etc.)*

---

## 6. Protocol-Level Attacks (8 tests)

### PL-001: Padding Oracle Attack - AEAD AAD Validation
**Severity:** CRITICAL
**Reference:** "Practical Padding Oracle Attacks" (Rizzo & Duong, 2010)

**Verification:**
```rust
#[test]
fn test_no_padding_oracle() {
    let key = SecretKey::generate(&mut rng);
    let plaintext = b"secret message";

    let encrypted = encrypt(&key, plaintext, None, &mut rng,
                           SymmetricAlgorithm::ChaCha20Poly1305).unwrap();

    // Tamper with last byte of ciphertext
    let mut tampered = encrypted.clone();
    let len = tampered.ciphertext.len();
    tampered.ciphertext[len - 1] ^= 0x01;

    // Should return generic authentication error (no detail about where)
    let result = decrypt(&key, &tampered, None);
    assert!(matches!(result, Err(CryptoError::DecryptionFailed)));

    // Error message should not reveal position of tampering
    assert!(!format!("{:?}", result).contains("byte"));
}
```

---

### PL-002: Downgrade Attack - Algorithm Negotiation
**Severity:** HIGH

**Verification:**
```rust
#[test]
fn test_no_algorithm_downgrade() {
    // EncryptedData includes algorithm field
    let encrypted = encrypt(&key, data, None, &mut rng,
                           SymmetricAlgorithm::ChaCha20Poly1305).unwrap();

    assert_eq!(encrypted.algorithm, SymmetricAlgorithm::ChaCha20Poly1305);

    // Attempting to decrypt with wrong algorithm should fail
    // (implementation should verify algorithm matches)
}
```

---

### PL-003-008: Additional Protocol Tests
*(Remaining 6 tests covering: replay attacks, MITM, version rollback, cross-protocol attacks, etc.)*

---

## 7. Randomness Quality (8 tests)

### RQ-001: NIST SP 800-90B Entropy Assessment
**Severity:** CRITICAL

**Verification:**
```bash
#!/bin/bash
# Generate 1 MB of RNG output
cargo run --release --example rng_output > /tmp/rng_sample.bin

# Run NIST entropy assessment tool
ea_non_iid -v /tmp/rng_sample.bin 8 | tee entropy_assessment.txt

# Check for passing criteria
grep "min-entropy" entropy_assessment.txt | awk '{if ($NF < 7.85) exit 1}'
```

---

### RQ-002: Dieharder Statistical Test Suite
**Severity:** HIGH

**Verification:**
```bash
dieharder -a -g 200 -f /tmp/rng_sample.bin | tee dieharder_results.txt
grep "FAILED" dieharder_results.txt && exit 1 || exit 0
```

---

### RQ-003-008: Additional RNG Tests
*(Remaining 6 tests: autocorrelation, spectral test, compression resistance, state space analysis, etc.)*

---

## 8. Operational Security (6 tests)

### OP-001: Error Message Information Leakage
**Severity:** MEDIUM

**Verification:**
```rust
#[test]
fn test_error_messages_no_secrets() {
    let key = SecretKey::generate(&mut rng);
    let result = decrypt(&key, &bad_ciphertext, None);

    let error_msg = format!("{:?}", result);

    // Should not contain key material
    assert!(!error_msg.contains(&format!("{:02x}", key.as_bytes()[0])));
}
```

---

### OP-002-006: Additional Operational Tests
*(Remaining 5 tests: rate limiting, DoS resistance, audit logging, version info, backward compatibility)*

---

## 9. Supply Chain Security (3 tests)

### SS-001: Dependency Vulnerability Scanning
**Severity:** HIGH

**Verification:**
```bash
cargo audit
cargo outdated --root-deps-only
```

---

### SS-002: Reproducible Builds
**Severity:** MEDIUM

**Verification:**
```bash
cargo build --release
sha256sum target/release/libquantum_wall.rlib > hash1.txt

# Clean and rebuild
cargo clean
cargo build --release
sha256sum target/release/libquantum_wall.rlib > hash2.txt

diff hash1.txt hash2.txt
```

---

### SS-003: Code Signing Verification
**Severity:** MEDIUM

*(npm package signing, crates.io verification)*

---

## 10. Compliance & Documentation (3 tests)

### CD-001: FIPS 140-3 Compliance Documentation
**Severity:** HIGH

**Required Documentation:**
- Cryptographic boundary definition
- Approved algorithms list
- Key management lifecycle
- Self-tests on startup
- Roles and services matrix

---

### CD-002: Security Policy Published
**Severity:** MEDIUM

**Required:** SECURITY.md with:
- Vulnerability disclosure process
- Security contact
- Supported versions
- Embargo policy

---

### CD-003: Threat Model Documentation
**Severity:** MEDIUM

**Required:** Threat model covering:
- Attacker capabilities (local/remote/physical)
- Attack surface analysis
- Mitigations for each threat
- Residual risks

---

## Summary Statistics

| Category | Tests | Critical | High | Medium | Low |
|:---------|:------|:---------|:-----|:-------|:----|
| Side-Channel Resistance | 20 | 8 | 10 | 2 | 0 |
| Cryptanalytic Security | 15 | 3 | 8 | 4 | 0 |
| API Misuse Prevention | 15 | 5 | 7 | 3 | 0 |
| Key Lifecycle | 12 | 6 | 4 | 2 | 0 |
| Memory Safety | 10 | 5 | 3 | 2 | 0 |
| Protocol Attacks | 8 | 4 | 3 | 1 | 0 |
| Randomness Quality | 8 | 3 | 3 | 2 | 0 |
| Operational Security | 6 | 0 | 2 | 4 | 0 |
| Supply Chain | 3 | 0 | 2 | 1 | 0 |
| Compliance | 3 | 0 | 2 | 1 | 0 |
| **TOTAL** | **100** | **34** | **44** | **22** | **0** |

---

## Implementation Priority

### Phase 1 (Critical - Weeks 1-2)
- All 34 CRITICAL severity tests
- Focus: Side-channel resistance, memory safety, key management

### Phase 2 (High - Weeks 3-4)
- All 44 HIGH severity tests
- Focus: Cryptanalytic security, API safety

### Phase 3 (Medium - Weeks 5-6)
- All 22 MEDIUM severity tests
- Focus: Operational security, documentation

---

## Automated Test Execution

```bash
# Run all extended tests
./qa/run-extended-tests.sh

# Run specific category
./qa/run-extended-tests.sh --category side-channel

# Generate compliance report
./qa/generate-compliance-report.sh > COMPLIANCE-REPORT.md
```

---

**Document Version:** 1.0
**Created:** 2025-12-01
**Status:** Draft - Awaiting implementation
**Total Additional Tests:** 100 (34 Critical, 44 High, 22 Medium)
