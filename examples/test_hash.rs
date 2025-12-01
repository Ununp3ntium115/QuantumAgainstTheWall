//! Test script to generate hash for "quantumhashingisimpossible"

use quantum_wall::crypto::argon2::{argon2_hash, Argon2Params};
use quantum_wall::crypto::balloon::{balloon_hash, BalloonParams};
use quantum_wall::crypto::kdf::hash_sha256;
use quantum_wall::crypto::timelock::hash_chain_lock;

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut acc, b| {
        use std::fmt::Write;
        let _ = write!(acc, "{:02x}", b);
        acc
    })
}

fn main() {
    let password = "quantumhashingisimpossible";
    let salt = "quantumwall_salt_2024";

    println!("=== QuantumWall Hash Test ===");
    println!("Password: {}", password);
    println!("Salt: {}", salt);
    println!();

    // Prepare salt
    let salt_hash = hash_sha256(salt.as_bytes());

    // Stage 1: Argon2id (Interactive for quick test)
    println!("Stage 1: Argon2id...");
    let params = Argon2Params::interactive();
    let argon2_result = argon2_hash(password.as_bytes(), &salt_hash, &params).unwrap();
    println!("  Argon2 hash: {}", hex_encode(&argon2_result));

    // Stage 2: Balloon hashing
    println!("Stage 2: Balloon...");
    let balloon_params = BalloonParams {
        space_cost: 16384,
        time_cost: 1,
        delta: 3,
        output_len: 32,
    };
    let balloon_result = balloon_hash(&argon2_result, &salt_hash, &balloon_params).unwrap();
    println!("  Balloon hash: {}", hex_encode(&balloon_result));

    // Stage 3: Time-lock
    println!("Stage 3: Time-lock (10K iterations)...");
    let input = [&balloon_result[..], &salt_hash].concat();
    let final_result = hash_chain_lock(&input, 10_000);
    println!("  Time-lock hash: {}", hex_encode(&final_result));

    println!();
    println!("=== FINAL FORTRESS HASH ===");
    println!("{}", hex_encode(&final_result));
}
