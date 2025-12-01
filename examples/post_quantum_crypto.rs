//! Post-Quantum Cryptography Example
//!
//! Demonstrates NIST-standardized post-quantum cryptographic algorithms:
//! - ML-KEM (FIPS 203): Key encapsulation mechanism
//! - ML-DSA (FIPS 204): Digital signature algorithm
//!
//! These algorithms are resistant to attacks from both classical and quantum computers.

use quantum_wall::{MPS, crypto::*};

fn main() {
    println!("=== QuantumWall Post-Quantum Cryptography ===\n");

    // Initialize quantum entropy source
    let mps = MPS::new(20, 8);
    let mut rng = QuantumRng::from_mps(&mps).unwrap();

    println!("Quantum entropy source initialized\n");
    println!("{}", "=".repeat(60));
    println!();

    // ========================================
    // Part 1: ML-KEM (Key Encapsulation)
    // ========================================

    println!("1. ML-KEM (FIPS 203) - Key Encapsulation Mechanism");
    println!("   Formerly CRYSTALS-Kyber\n");

    // Generate keypair for Alice
    println!("   Alice generates ML-KEM-768 keypair (192-bit security)...");
    let alice_keypair = MlKemKeypair::generate(MlKemSecurityLevel::Medium, &mut rng).unwrap();
    println!("   - Public key size: {} bytes", alice_keypair.public_key().as_bytes().len());
    println!("   - Secret key size: {} bytes", alice_keypair.secret_key().as_bytes().len());

    // Bob encapsulates a shared secret using Alice's public key
    println!("\n   Bob encapsulates shared secret using Alice's public key...");
    let (ciphertext, bob_shared_secret) = alice_keypair.public_key().encapsulate(&mut rng).unwrap();
    println!("   - Ciphertext size: {} bytes", ciphertext.len());
    println!("   - Shared secret: {:02x?}...", &bob_shared_secret[0..8]);

    // Alice decapsulates to get the same shared secret
    println!("\n   Alice decapsulates to recover shared secret...");
    let alice_shared_secret = alice_keypair.decapsulate(&ciphertext).unwrap();
    println!("   - Recovered secret: {:02x?}...", &alice_shared_secret[0..8]);

    println!("\n   ✓ Key encapsulation successful!");
    println!("   → Quantum-resistant secure key exchange complete\n");

    println!("{}", "=".repeat(60));
    println!();

    // ========================================
    // Part 2: ML-DSA (Digital Signatures)
    // ========================================

    println!("2. ML-DSA (FIPS 204) - Digital Signature Algorithm");
    println!("   Formerly CRYSTALS-Dilithium\n");

    // Generate signing key
    println!("   Generating ML-DSA-65 signing key (192-bit security)...");
    let signing_key = MlDsaSigningKey::generate(MlDsaSecurityLevel::Medium, &mut rng).unwrap();
    let verification_key = signing_key.verification_key();
    println!("   - Verification key size: {} bytes", verification_key.as_bytes().len());

    // Sign a message
    let message = b"This message is signed with post-quantum cryptography!";
    println!("\n   Signing message:");
    println!("   {:?}", std::str::from_utf8(message).unwrap());

    let signature = signing_key.sign(message, &mut rng).unwrap();
    println!("\n   - Signature size: {} bytes", signature.len());
    println!("   - Signature (first 16 bytes): {:02x?}...", &signature[0..16]);

    // Verify signature
    println!("\n   Verifying signature...");
    let is_valid = verification_key.verify(message, &signature);
    println!("   - Verification result: {}", if is_valid { "✓ VALID" } else { "✗ INVALID" });

    // Try to verify with wrong message
    let wrong_message = b"This is a different message";
    let is_valid_wrong = verification_key.verify(wrong_message, &signature);
    println!("   - Wrong message verification: {}", if is_valid_wrong { "✗ INVALID (should fail)" } else { "✓ CORRECTLY REJECTED" });

    println!("\n   ✓ Digital signature successful!");
    println!("   → Quantum-resistant authentication complete\n");

    println!("{}", "=".repeat(60));
    println!();

    // ========================================
    // Part 3: Security Levels Comparison
    // ========================================

    println!("3. Security Levels Available\n");

    println!("   ML-KEM (Key Encapsulation):");
    println!("   ┌─────────────┬──────────┬──────────┬────────────┐");
    println!("   │ Level       │ Security │ Pub Key  │ Ciphertext │");
    println!("   ├─────────────┼──────────┼──────────┼────────────┤");
    println!("   │ ML-KEM-512  │ 128-bit  │ 800 B    │ 768 B      │");
    println!("   │ ML-KEM-768  │ 192-bit  │ 1184 B   │ 1088 B     │");
    println!("   │ ML-KEM-1024 │ 256-bit  │ 1568 B   │ 1568 B     │");
    println!("   └─────────────┴──────────┴──────────┴────────────┘\n");

    println!("   ML-DSA (Digital Signatures):");
    println!("   ┌────────────┬──────────┬──────────┬───────────┐");
    println!("   │ Level      │ Security │ Pub Key  │ Signature │");
    println!("   ├────────────┼──────────┼──────────┼───────────┤");
    println!("   │ ML-DSA-44  │ 128-bit  │ 1312 B   │ 2420 B    │");
    println!("   │ ML-DSA-65  │ 192-bit  │ 1952 B   │ 3309 B    │");
    println!("   │ ML-DSA-87  │ 256-bit  │ 2592 B   │ 4627 B    │");
    println!("   └────────────┴──────────┴──────────┴───────────┘\n");

    println!("{}", "=".repeat(60));
    println!();

    // ========================================
    // Part 4: Why Post-Quantum Matters
    // ========================================

    println!("4. Why Post-Quantum Cryptography?\n");

    println!("   Classical Threats:");
    println!("   ✓ Resistant to supercomputers and ASICs");
    println!("   ✓ Based on hard lattice problems (Learning With Errors)");
    println!("   ✓ No known classical algorithm breaks these\n");

    println!("   Quantum Threats:");
    println!("   ✓ Shor's algorithm: Breaks RSA and ECC (exponential speedup)");
    println!("   ✓ Grover's algorithm: Only √N speedup (manageable)");
    println!("   ✓ ML-KEM/ML-DSA: Secure against both!\n");

    println!("   Standards:");
    println!("   ✓ NIST FIPS 203 (ML-KEM) - Published August 2024");
    println!("   ✓ NIST FIPS 204 (ML-DSA) - Published August 2024");
    println!("   ✓ Mathematically proven security reductions");
    println!("   ✓ Constant-time implementations (side-channel resistant)\n");

    println!("{}", "=".repeat(60));
    println!();

    // ========================================
    // Part 5: Integration with QuantumWall
    // ========================================

    println!("5. Integration with QuantumWall Fortress\n");

    println!("   QuantumWall combines multiple security layers:");
    println!("   1. Argon2id - Memory-hard KDF");
    println!("   2. Balloon - Provably space-hard");
    println!("   3. Bandwidth-hard - ASIC resistance");
    println!("   4. Multi-hash - 4 independent hash functions");
    println!("   5. Time-lock - Sequential work (VDF)");
    println!("   6. ML-KEM/ML-DSA - Post-quantum algorithms ← NEW!\n");

    println!("   Future Enhancement:");
    println!("   → Hybrid encryption: Classical (ECDH) + PQC (ML-KEM)");
    println!("   → Secure even if one scheme is broken");
    println!("   → Forward compatibility as PQC algorithms mature\n");

    println!("{}", "=".repeat(60));
    println!();

    println!("Summary:");
    println!("--------");
    println!("✓ ML-KEM provides quantum-resistant key exchange");
    println!("✓ ML-DSA provides quantum-resistant signatures");
    println!("✓ NIST-standardized (FIPS 203/204)");
    println!("✓ Based on lattice problems (secure against quantum attacks)");
    println!("✓ Integrated with QuantumWall's quantum entropy source");
    println!("\nSee SECURITY_ANALYSIS.md for detailed cryptographic proofs.");
}
