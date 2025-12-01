#!/bin/bash
# Generate GitHub issues for extended security tests
# Usage: ./qa/generate-issues.sh

set -e

ISSUE_DIR="qa/issues/extended"
mkdir -p "$ISSUE_DIR"

echo "Generating 100 extended security test issues..."

# Function to create issue file
create_issue() {
    local id="$1"
    local title="$2"
    local severity="$3"
    local category="$4"
    local description="$5"
    local verification="$6"
    local reference="$7"

    cat > "$ISSUE_DIR/$id.md" << EOF
---
id: $id
title: "$title"
severity: $severity
category: $category
labels: [security, crypto, $category]
reference: $reference
---

# $title

**ID:** \`$id\`
**Severity:** $severity
**Category:** $category
**Reference:** $reference

## Description

$description

## Verification Method

$verification

## Acceptance Criteria

- [ ] Test script created in \`tests/security/$id.rs\`
- [ ] Test passes locally
- [ ] Test integrated into CI pipeline
- [ ] Documentation updated
- [ ] Security review completed

## Related Issues

- Part of Extended Security Test Suite (100 tests)
- See \`qa/extended-security-tests.md\` for full context

## How to Verify Remediation

\`\`\`bash
# Run the specific test
cargo test $id --release

# Or run with verification script
./tests/security/verify_$id.sh

# Check for PASS output
# Exit code 0 = test passed
# Exit code 1 = test failed
\`\`\`

---
**Created:** $(date +%Y-%m-%d)
**Status:** Open
EOF

    echo "✓ Created issue: $id - $title"
}

# ============================================================================
# SIDE-CHANNEL ATTACK RESISTANCE (SC-001 to SC-020)
# ============================================================================

create_issue "SC-001" \
  "Timing Attack Resistance - AES Operations" \
  "CRITICAL" \
  "side-channel" \
  "AES key schedule and round operations must have constant-time execution regardless of key/plaintext values. This prevents attackers from recovering keys via statistical timing analysis." \
  "Use dudect statistical timing test suite. Run 1M iterations comparing execution time for all-zero keys vs all-one keys. p-value must be > 0.05 (no statistically significant difference)." \
  "FIPS 140-3 IG 9.7, CWE-208"

create_issue "SC-002" \
  "Timing Attack Resistance - Argon2 Password Verification" \
  "HIGH" \
  "side-channel" \
  "Password verification must take constant time regardless of whether the password is correct or incorrect. This prevents timing-based password enumeration attacks." \
  "Generate 1000 samples each for correct and incorrect passwords. Perform statistical t-test. p-value > 0.05 required." \
  "CWE-208, OWASP A02:2021"

create_issue "SC-003" \
  "Cache-Timing Resistance - Rijndael S-Box Lookups" \
  "CRITICAL" \
  "side-channel" \
  "AES implementation must not use table lookups that leak information via cache timing. Use AES-NI hardware acceleration or bitsliced software implementation." \
  "Verify dependency on aes crate which uses AES-NI when available, bitsliced otherwise. Run cache timing analysis with CacheGrind." \
  "Osvik et al. Cache Attacks (2006)"

create_issue "SC-004" \
  "Power Analysis Resistance - Key-Dependent Branching" \
  "HIGH" \
  "side-channel" \
  "Crypto operations must not contain conditional branches that depend on key material. This prevents differential power analysis (DPA) attacks." \
  "Static code analysis: grep for if/match statements on key variables in hot paths. No key-dependent branches allowed." \
  "FIPS 140-3 Section 4.5.3"

create_issue "SC-005" \
  "Electromagnetic Emanation (TEMPEST) - RNG Seeding" \
  "MEDIUM" \
  "side-channel" \
  "RNG must use sources that are resistant to electromagnetic (EM) emanation attacks. OS-provided entropy sources include EM countermeasures." \
  "Document that getrandom() on Linux/Windows includes hardware RNG with thermal noise and LRNG reseeding." \
  "FIPS 140-3 Section 4.5.4"

create_issue "SC-006" \
  "Constant-Time Comparison - MAC/Tag Verification" \
  "CRITICAL" \
  "side-channel" \
  "Authentication tag comparison must use constant-time comparison to prevent timing-based forgery attacks." \
  "Verify use of subtle::ConstantTimeEq for all tag/MAC comparisons. Add test that confirms no early-exit on mismatch." \
  "CWE-208"

create_issue "SC-007" \
  "Speculative Execution - Bounds Check Bypass" \
  "HIGH" \
  "side-channel" \
  "Array indexing in crypto code must not leak secrets via speculative execution (Spectre/Meltdown). Use bounds-checked access or constant-time indexing." \
  "Audit all array accesses in hot paths. Use .get() instead of [] for secret-dependent indices." \
  "CVE-2017-5753 (Spectre)"

create_issue "SC-008" \
  "Fault Injection - Glitch Attack Resistance" \
  "MEDIUM" \
  "side-channel" \
  "Critical checks (e.g., signature verification) must be redundant to prevent skip via voltage/clock glitching." \
  "Add duplicate verification with independent code paths. Test with fault injection simulator." \
  "FIPS 140-3 IG 9.8"

# Generate remaining 12 side-channel issues (SC-009 to SC-020)
for i in {9..20}; do
    create_issue "SC-$(printf '%03d' $i)" \
      "Side-Channel Test $(printf '%03d' $i)" \
      "MEDIUM" \
      "side-channel" \
      "Additional side-channel attack resistance test covering advanced attack vectors." \
      "See extended-security-tests.md for detailed specification." \
      "Various"
done

# ============================================================================
# CRYPTANALYTIC SECURITY (CA-001 to CA-015)
# ============================================================================

create_issue "CA-001" \
  "Birthday Bound Safety - GCM Nonce Collision" \
  "CRITICAL" \
  "cryptanalytic" \
  "AES-GCM must enforce nonce counter limit at 2^32 messages to prevent birthday bound collisions which allow authentication forgery." \
  "Test that NonceState returns NonceExhausted error at counter = 2^32. Verify no overflow wraps to zero." \
  "Bhargavan & Leurent (2016)"

create_issue "CA-002" \
  "Length Extension Attack Resistance - KDF" \
  "HIGH" \
  "cryptanalytic" \
  "Key derivation must use HMAC-based construction immune to length extension attacks. SHA-256 alone is vulnerable." \
  "Verify HKDF implementation. Test that extending info parameter produces completely different keys." \
  "Kelsey & Schneier (2005)"

create_issue "CA-003" \
  "Related-Key Attack Resistance - ChaCha20" \
  "MEDIUM" \
  "cryptanalytic" \
  "ChaCha20 key schedule must not allow related-key attacks where attacker can derive keys from related ones." \
  "Document that ChaCha20 has no known related-key attacks per RFC 8439." \
  "RFC 8439 Section 2.3"

create_issue "CA-004" \
  "Weak Key Detection - Argon2 Salt Validation" \
  "HIGH" \
  "cryptanalytic" \
  "Argon2 must reject weak salts (too short, all-zero, low entropy) that reduce password security." \
  "Test rejection of: salts < 8 bytes, all-zero salts, repeated salts. Accept crypto-random salts >= 8 bytes." \
  "RFC 9106"

# Generate remaining 11 cryptanalytic issues (CA-005 to CA-015)
for i in {5..15}; do
    create_issue "CA-$(printf '%03d' $i)" \
      "Cryptanalytic Security Test $(printf '%03d' $i)" \
      "MEDIUM" \
      "cryptanalytic" \
      "Advanced cryptanalytic attack resistance test." \
      "See extended-security-tests.md for specification." \
      "Various"
done

# ============================================================================
# API MISUSE PREVENTION (AP-001 to AP-015)
# ============================================================================

create_issue "AP-001" \
  "Type Safety - Key Reuse Across Algorithms" \
  "HIGH" \
  "api-misuse" \
  "Keys should be algorithmspecific types to prevent accidentally using AES key with ChaCha20 (and vice versa)." \
  "Add phantom type parameter SecretKey<Algorithm>. Verify compile-time type checking prevents cross-use." \
  "Georgiev et al. (2012)"

create_issue "AP-002" \
  "Nonce Reuse Detection - Runtime Check" \
  "CRITICAL" \
  "api-misuse" \
  "Runtime detection of nonce reuse attempts must trigger error, preventing catastrophic crypto failure." \
  "Test that NonceState.register() returns ReplayDetected for duplicate nonces." \
  "OWASP A02:2021"

create_issue "AP-003" \
  "Default Security - No Weak Algorithms" \
  "HIGH" \
  "api-misuse" \
  "Public API must not expose weak legacy algorithms (DES, 3DES, MD5, SHA1, RC4) even as options." \
  "Grep public API for weak algorithm names. Zero occurrences required." \
  "OWASP Crypto Failures"

# Generate remaining 12 API issues (AP-004 to AP-015)
for i in {4..15}; do
    create_issue "AP-$(printf '%03d' $i)" \
      "API Misuse Prevention Test $(printf '%03d' $i)" \
      "MEDIUM" \
      "api-misuse" \
      "API safety test preventing common developer mistakes." \
      "See extended-security-tests.md." \
      "Various"
done

# ============================================================================
# KEY LIFECYCLE MANAGEMENT (KL-001 to KL-012)
# ============================================================================

create_issue "KL-001" \
  "Secure Key Generation - Entropy Source" \
  "CRITICAL" \
  "key-lifecycle" \
  "Key generation must use cryptographically secure RNG (CSPRNG) backed by OS entropy, not predictable sources." \
  "Verify SecretKey::generate() uses QuantumRng backed by getrandom(). Test that sequential keys differ." \
  "FIPS 140-3 Section 4.7.1"

create_issue "KL-002" \
  "Key Destruction - Zeroization Verification" \
  "CRITICAL" \
  "key-lifecycle" \
  "Key memory must be explicitly zeroized on Drop to prevent key recovery from memory dumps." \
  "Test that memory location of dropped key contains all zeros. Use Drop implementation audit." \
  "FIPS 140-3 Section 4.7.6"

create_issue "KL-003" \
  "Key Storage - No Plaintext Keys on Disk" \
  "CRITICAL" \
  "key-lifecycle" \
  "Keys must never be written to disk in plaintext. Use encrypted key wrapping or OS keychain." \
  "Scan examples and docs for File::create with key variables. Zero plaintext writes allowed." \
  "PCI DSS Requirement 3.4"

# Generate remaining 9 key lifecycle issues (KL-004 to KL-012)
for i in {4..12}; do
    create_issue "KL-$(printf '%03d' $i)" \
      "Key Lifecycle Test $(printf '%03d' $i)" \
      "HIGH" \
      "key-lifecycle" \
      "Key management security test." \
      "See extended-security-tests.md." \
      "FIPS 140-3 Section 4.7"
done

# ============================================================================
# MEMORY SAFETY (MS-001 to MS-010)
# ============================================================================

create_issue "MS-001" \
  "Buffer Overflow - Encryption Input Length" \
  "CRITICAL" \
  "memory-safety" \
  "Encryption must handle arbitrarily large inputs without buffer overflow or OOM crashes." \
  "Test encryption of 1GB plaintext. Must return Ok or controlled error, never crash." \
  "CWE-120"

create_issue "MS-002" \
  "Use-After-Free - Key Reference Safety" \
  "CRITICAL" \
  "memory-safety" \
  "Rust borrow checker prevents UAF. Document that lifetime analysis guarantees no dangling key references." \
  "Confirm no unsafe blocks in key handling. Compile-time verification via rustc." \
  "CWE-416"

create_issue "MS-003" \
  "Double-Free - RNG State Cleanup" \
  "HIGH" \
  "memory-safety" \
  "RNG state must be freed exactly once. Test with ASAN to detect double-free bugs." \
  "Run test suite with AddressSanitizer: RUSTFLAGS=-Zsanitizer=address cargo test" \
  "CWE-415"

# Generate remaining 7 memory safety issues (MS-004 to MS-010)
for i in {4..10}; do
    create_issue "MS-$(printf '%03d' $i)" \
      "Memory Safety Test $(printf '%03d' $i)" \
      "HIGH" \
      "memory-safety" \
      "Memory corruption prevention test." \
      "See extended-security-tests.md." \
      "CWE-119"
done

# ============================================================================
# PROTOCOL-LEVEL ATTACKS (PL-001 to PL-008)
# ============================================================================

create_issue "PL-001" \
  "Padding Oracle Attack - AEAD AAD Validation" \
  "CRITICAL" \
  "protocol-attack" \
  "Decryption errors must not reveal which byte failed authentication, preventing adaptive chosen-ciphertext attacks." \
  "Tamper with different ciphertext bytes. All failures must return identical generic error." \
  "Rizzo & Duong (2010)"

create_issue "PL-002" \
  "Downgrade Attack - Algorithm Negotiation" \
  "HIGH" \
  "protocol-attack" \
  "Encrypted data must authenticate the algorithm used, preventing attacker from forcing use of weak algorithms." \
  "Verify EncryptedData includes algorithm field. Test that tampering with algorithm causes auth failure." \
  "BEAST, POODLE attacks"

# Generate remaining 6 protocol issues (PL-003 to PL-008)
for i in {3..8}; do
    create_issue "PL-$(printf '%03d' $i)" \
      "Protocol Attack Test $(printf '%03d' $i)" \
      "HIGH" \
      "protocol-attack" \
      "Protocol-level attack prevention." \
      "See extended-security-tests.md." \
      "Various"
done

# ============================================================================
# RANDOMNESS QUALITY (RQ-001 to RQ-008)
# ============================================================================

create_issue "RQ-001" \
  "NIST SP 800-90B Entropy Assessment" \
  "CRITICAL" \
  "randomness" \
  "RNG output must pass NIST entropy assessment with min-entropy >= 7.85 bits/byte." \
  "Generate 1MB sample. Run ea_non_iid tool. Verify min-entropy > 7.85." \
  "NIST SP 800-90B"

create_issue "RQ-002" \
  "Dieharder Statistical Test Suite" \
  "HIGH" \
  "randomness" \
  "RNG must pass all Dieharder tests with no FAILED results." \
  "Run dieharder -a -g 200 -f sample.bin. Zero failures required." \
  "Dieharder 3.31.1"

# Generate remaining 6 randomness issues (RQ-003 to RQ-008)
for i in {3..8}; do
    create_issue "RQ-$(printf '%03d' $i)" \
      "Randomness Quality Test $(printf '%03d' $i)" \
      "HIGH" \
      "randomness" \
      "Statistical randomness verification." \
      "See extended-security-tests.md." \
      "NIST SP 800-22"
done

# ============================================================================
# OPERATIONAL SECURITY (OP-001 to OP-006)
# ============================================================================

create_issue "OP-001" \
  "Error Message Information Leakage" \
  "MEDIUM" \
  "operational" \
  "Error messages must not contain secret key material or internal state that aids attacks." \
  "Trigger all error paths. Grep error output for key bytes. Zero leaks allowed." \
  "OWASP A04:2021"

# Generate remaining 5 operational issues (OP-002 to OP-006)
for i in {2..6}; do
    create_issue "OP-$(printf '%03d' $i)" \
      "Operational Security Test $(printf '%03d' $i)" \
      "MEDIUM" \
      "operational" \
      "Operational security hardening." \
      "See extended-security-tests.md." \
      "OWASP Top 10"
done

# ============================================================================
# SUPPLY CHAIN SECURITY (SS-001 to SS-003)
# ============================================================================

create_issue "SS-001" \
  "Dependency Vulnerability Scanning" \
  "HIGH" \
  "supply-chain" \
  "All dependencies must be scanned for known vulnerabilities with zero high/critical findings." \
  "Run cargo audit and cargo outdated. No high/critical vulnerabilities allowed." \
  "OWASP A06:2021"

create_issue "SS-002" \
  "Reproducible Builds" \
  "MEDIUM" \
  "supply-chain" \
  "Builds must be reproducible: same source produces same binary hash." \
  "Build twice from clean state. SHA256 hashes must match." \
  "Reproducible Builds"

create_issue "SS-003" \
  "Code Signing Verification" \
  "MEDIUM" \
  "supply-chain" \
  "Release artifacts must be cryptographically signed by maintainer." \
  "Verify npm package signature and crates.io checksum." \
  "SLSA Level 2"

# ============================================================================
# COMPLIANCE & DOCUMENTATION (CD-001 to CD-003)
# ============================================================================

create_issue "CD-001" \
  "FIPS 140-3 Compliance Documentation" \
  "HIGH" \
  "compliance" \
  "Document FIPS 140-3 compliance aspects: cryptographic boundary, approved algorithms, key management, self-tests." \
  "Create FIPS-COMPLIANCE.md with all required sections." \
  "FIPS 140-3"

create_issue "CD-002" \
  "Security Policy Published" \
  "MEDIUM" \
  "compliance" \
  "Publish SECURITY.md with vulnerability disclosure process, contacts, and embargo policy." \
  "Create SECURITY.md per GitHub security best practices." \
  "OSS Security"

create_issue "CD-003" \
  "Threat Model Documentation" \
  "MEDIUM" \
  "compliance" \
  "Document threat model: attacker capabilities, attack surfaces, mitigations, residual risks." \
  "Create THREAT-MODEL.md covering all attack vectors." \
  "STRIDE/PASTA"

echo ""
echo "✅ Generated 100 security test issues in $ISSUE_DIR/"
echo ""
echo "Next steps:"
echo "1. Review generated issues: ls -l $ISSUE_DIR/"
echo "2. Create GitHub issues: gh issue create --title \"\$(cat qa/issues/extended/SC-001.md | grep title: | cut -d' ' -f2-)\""
echo "3. Or bulk import: ./qa/bulk-create-issues.sh"
echo ""
echo "Summary:"
echo "  - Side-Channel: 20 issues (SC-001 to SC-020)"
echo "  - Cryptanalytic: 15 issues (CA-001 to CA-015)"
echo "  - API Misuse: 15 issues (AP-001 to AP-015)"
echo "  - Key Lifecycle: 12 issues (KL-001 to KL-012)"
echo "  - Memory Safety: 10 issues (MS-001 to MS-010)"
echo "  - Protocol Attacks: 8 issues (PL-001 to PL-008)"
echo "  - Randomness: 8 issues (RQ-001 to RQ-008)"
echo "  - Operational: 6 issues (OP-001 to OP-006)"
echo "  - Supply Chain: 3 issues (SS-001 to SS-003)"
echo "  - Compliance: 3 issues (CD-001 to CD-003)"
echo "  TOTAL: 100 issues"
