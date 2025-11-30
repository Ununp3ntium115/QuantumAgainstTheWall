<p align="center">
  <img src="https://img.shields.io/badge/Rust-000000?style=for-the-badge&logo=rust&logoColor=white" alt="Rust"/>
  <img src="https://img.shields.io/badge/WebAssembly-654FF0?style=for-the-badge&logo=webassembly&logoColor=white" alt="WASM"/>
  <img src="https://img.shields.io/badge/npm-CB3837?style=for-the-badge&logo=npm&logoColor=white" alt="npm"/>
</p>

<h1 align="center">QuantumWall</h1>

<p align="center">
  <strong>Quantum entropy computation and cryptography at scale using tensor networks.</strong>
</p>

<p align="center">
  Compute von Neumann entropy for systems with <b>millions of qubits</b> using Matrix Product States (MPS).<br/>
  Features quantum-seeded cryptographic primitives for secure data encryption.
</p>

---

## The Problem We Solve

```
                    THE EXPONENTIAL WALL

    Traditional Approach          QuantumWall (MPS)
    ══════════════════════        ══════════════════════

    20 qubits  = 17.6 TB          20 qubits  = 320 KB
    30 qubits  = 10^7 TB          10K qubits = 160 MB
    1M qubits  = 10^600000 TB     1M qubits  = 16 GB

         IMPOSSIBLE                    POSSIBLE
```

---

## Features

| Feature | Description |
|:--------|:------------|
| **Scalable Quantum States** | Handle millions of qubits with polynomial memory |
| **Entanglement Entropy** | Compute von Neumann entropy without density matrices |
| **Quantum Gates** | Hadamard, Pauli, rotations, and more |
| **Quantum RNG** | Cryptographic RNG seeded by entanglement entropy |
| **AES-256-GCM** | Military-grade encryption for data at rest |
| **ChaCha20-Poly1305** | Side-channel resistant encryption for data in transit |
| **HKDF Key Derivation** | Derive multiple keys from shared secrets |
| **WebAssembly** | Use from JavaScript, TypeScript, or any WASM host |

---

## Installation

**npm / JavaScript / TypeScript**
```bash
npm install quantumwall
```

**Rust / Cargo**
```toml
[dependencies]
quantum-wall = "0.1"
```

---

## Quick Start

### JavaScript

```javascript
import init, { QuantumState, SymmetricCrypto } from 'quantumwall';

await init();

// Create a million-qubit quantum state
const state = new QuantumState(1_000_000, 64);
console.log(`Memory: ${state.memoryString}`);  // ~16 GB

// Apply quantum gates
state.hadamardAll();

// Compute entropy
console.log(`Entropy: ${state.totalEntropy()} bits`);

// Use quantum entropy for cryptography
const crypto = SymmetricCrypto.fromQuantumState(state);
const encrypted = crypto.encryptAesGcm(
    new TextEncoder().encode("Secret message")
);
```

### Rust

```rust
use quantum_wall::{MPS, QuantumRng, SecretKey, encrypt, decrypt};
use quantum_wall::crypto::symmetric::SymmetricAlgorithm;

// Create quantum state
let mps = MPS::new(1_000_000, 64);
let mut rng = QuantumRng::from_mps(&mps).unwrap();

// Quantum-seeded encryption
let key = SecretKey::generate(&mut rng);
let encrypted = encrypt(&key, b"Secret", None, &mut rng,
    SymmetricAlgorithm::ChaCha20Poly1305).unwrap();
```

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        QUANTUMWALL                               │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   ┌──────────────┐    ┌──────────────┐    ┌──────────────┐     │
│   │   QUANTUM    │    │   ENTROPY    │    │    CRYPTO    │     │
│   │    LAYER     │───▶│    LAYER     │───▶│    LAYER     │     │
│   └──────────────┘    └──────────────┘    └──────────────┘     │
│         │                    │                    │             │
│   ┌─────▼─────┐        ┌─────▼─────┐        ┌─────▼─────┐      │
│   │    MPS    │        │ von Neumann│        │  AES-GCM  │      │
│   │  Tensors  │        │  Entropy   │        │  ChaCha20 │      │
│   │   O(nχ²)  │        │  S(ρ)      │        │   HKDF    │      │
│   └───────────┘        └───────────┘        └───────────┘      │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## API Reference

### Quantum State

```javascript
const state = new QuantumState(n_qubits, bond_dim);

// Properties
state.nQubits       // Number of qubits
state.bondDim       // Bond dimension (χ)
state.memoryBytes   // Memory usage
state.memoryString  // Human-readable memory

// Entropy
state.totalEntropy()      // Sum over all bonds
state.entropyAtBond(i)    // Entropy at bond i
state.entropyProfile()    // Array of all bond entropies
state.augmentedEntropy()  // S + π·n²

// Gates
state.hadamard(site)      // H gate
state.pauliX(site)        // X gate
state.pauliY(site)        // Y gate
state.pauliZ(site)        // Z gate
state.rx(site, θ)         // Rx(θ)
state.ry(site, θ)         // Ry(θ)
state.rz(site, θ)         // Rz(θ)
state.hadamardAll()       // H on all qubits
```

### Cryptography

```javascript
// Random Number Generation
const rng = CryptoRng.fromQuantumState(state);
const bytes = rng.randomBytes(32);

// Symmetric Encryption
const crypto = SymmetricCrypto.fromQuantumState(state);
const encrypted = crypto.encryptAesGcm(plaintext);
const encrypted = crypto.encryptChaCha20(plaintext);
const decrypted = crypto.decrypt(encrypted);

// With Additional Authenticated Data
const encrypted = crypto.encryptWithAad(plaintext, aad, "aes-256-gcm");
const decrypted = crypto.decryptWithAad(encrypted, aad);

// Key Derivation
const derivedKey = deriveKey(inputKey, salt, info);
const hash = sha256(data);
```

### Supported Algorithms

| Algorithm | Key | Nonce | Tag | Best For |
|:----------|:----|:------|:----|:---------|
| **AES-256-GCM** | 256-bit | 96-bit | 128-bit | Data at rest |
| **ChaCha20-Poly1305** | 256-bit | 96-bit | 128-bit | Data in transit |
| **HKDF-SHA256** | Variable | - | - | Key derivation |
| **SHA-256** | - | - | 256-bit | Hashing |

---

## Memory Scaling

```
Memory Usage vs Qubits (log scale)

Full State Vector:     MPS (χ=64):           MPS (χ=256):

    ∞  ─┐              16 GB ─┐              262 GB ─┐
       │                      │ 1M qubits           │
       │               1.6 GB ─┤ 100K               │
       │                      │                     │
       │               160 MB ─┤ 10K          2.6 GB─┤
       │                      │                     │
17.6TB ─┤ 20 qubits    16 MB ─┤ 1K           260 MB─┤
       │                      │                     │
       ▼               320 KB ─┤ 20            5 MB ─┤
  IMPOSSIBLE                  ▼                     ▼
                          FEASIBLE             FEASIBLE
```

---

## How It Works

### Matrix Product States

Instead of storing 2^n amplitudes, MPS stores n tensors:

```
|ψ⟩ = Σ A[1]^{s₁} · A[2]^{s₂} · ... · A[n]^{sₙ} |s₁s₂...sₙ⟩

Memory: O(n · χ²)  instead of  O(2ⁿ)
```

### Entropy from Singular Values

```
S = -Σⱼ λⱼ² log₂(λⱼ²)

No density matrix needed - computed directly from MPS bonds.
```

---

## Project Structure

```
quantumwall/
├── src/
│   ├── lib.rs           # Public API
│   ├── mps.rs           # Matrix Product States
│   ├── entropy.rs       # Entropy calculations
│   ├── gates.rs         # Quantum gates
│   ├── wasm.rs          # WebAssembly bindings
│   └── crypto/
│       ├── mod.rs       # Crypto module
│       ├── rng.rs       # Quantum CSPRNG
│       ├── keys.rs      # Key management
│       ├── symmetric.rs # AES-GCM, ChaCha20
│       └── kdf.rs       # HKDF-SHA256
├── pkg/                 # npm package
├── Cargo.toml
└── package.json
```

---

## Building from Source

```bash
# Prerequisites
rustup update stable
cargo install wasm-pack

# Build and test
cargo build --release
cargo test

# Build WebAssembly
wasm-pack build --target web
```

---

## Use Cases

| Domain | Application |
|:-------|:------------|
| **Quantum Research** | Entropy dynamics in large systems |
| **Error Correction** | Analyze entanglement in QEC codes |
| **Condensed Matter** | Many-body entanglement studies |
| **Quantum ML** | Entropy-based feature engineering |
| **Cryptography** | Quantum-seeded key generation |
| **Secure Storage** | AES-256-GCM encrypted databases |
| **Secure Comms** | ChaCha20-Poly1305 message encryption |

---

## Security

- Keys zeroed from memory on drop
- Nonces generated securely, never reused
- Authenticated encryption (AEAD) only
- Quantum entropy provides high-quality RNG seeding

---

## Limitations

- MPS is optimal for **area-law** entangled states
- Volume-law states require exponentially large χ
- Distant two-qubit gates are computationally expensive

---

## License

**UNLICENSED** - All rights reserved.

Copyright (c) 2024 QuantumAgainstTheWall Contributors

---

<p align="center">
  <sub>Built with Rust + WebAssembly</sub>
</p>
