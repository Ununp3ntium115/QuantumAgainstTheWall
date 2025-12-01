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
| **Quantum Fortress** | Argon2id + Balloon + Time-lock password hardening |
| **WebAssembly** | Use from JavaScript, TypeScript, or any WASM host |

---

## Core Entropy Equations

Our entanglement calculations are built around the von Neumann entropy of a density matrix \(\rho\):

\[\boxed{\;S(\rho) = -\,\operatorname{Tr}\!\big(\rho\,\log_2 \rho\big) = -\sum_{i} \lambda_i \log_2 \lambda_i\; }\]

Here \(\{\lambda_i\}\) are the eigenvalues of \(\rho\), and the base-2 logarithm measures entropy in bits. This equation underpins the reliability and regression tests in the suite, including degenerate cases where \(\rho\) may be empty or have zero bond dimension.

For finite-order reliability sweeps we also track the Rényi entropy family, which collapses to the von Neumann limit as \(\alpha \to 1\):

\[\boxed{\;S_\alpha(\rho) = \tfrac{1}{1-\alpha} \log_2 \!\Big( \sum_i \lambda_i^{\,\alpha} \Big),\quad \lim_{\alpha \to 1} S_\alpha(\rho) = S(\rho)\; }\]

And because tensor networks admit a hard ceiling on entanglement, we validate the maximum bond entropy used in tests with

\[\boxed{\;S_{\max}(\chi, n) = (n-1)\,\log_2 \chi\; }\]

where \(\chi\) is the bond dimension and \(n\) is the number of lattice sites. These formulas make the numerical expectations explicit for the reliability suite.

### How These Quantities Are Built

For a pure state \(|\psi\rangle\) on bipartition \(A|B\), the reduced density matrix entering each equation is constructed via

\[\rho_A = \operatorname{Tr}_B |\psi\rangle\!\langle\psi|.\]

Matrix Product States give \(|\psi\rangle\) a Schmidt decomposition at every bond, \(|\psi\rangle = \sum_{i} s_i\,|i_A\rangle \otimes |i_B\rangle\), where the squared Schmidt coefficients \(\lambda_i = s_i^2\) form the spectrum of \(\rho_A\). This makes the bond entropy identical to the eigenvalue-based expression above:

\[S(\rho_A) = -\sum_i s_i^2 \log_2 s_i^2.\]

The Rényi family recovers the von Neumann case through l’Hôpital’s rule:

\[\lim_{\alpha\to 1} S_\alpha(\rho_A) = -\left.\frac{\partial}{\partial \alpha} \log_2\!\Big( \sum_i s_i^{2\alpha} \Big)\right|_{\alpha=1} = S(\rho_A).\]

Finally, the hard cap on entanglement follows from counting the \(\chi\)-dimensional bond Hilbert spaces. The reduced state on either side of a bond is supported on at most \(\chi\) singular values, so its entropy satisfies \(S(\rho_A) \le \log_2 \chi\); summing over the \(n-1\) interior bonds yields the network-wide limit \(S_{\max}(\chi, n)\).

Because the reliability suite is fed raw Schmidt coefficients, all entropy helpers first normalize the squared singular values,

\[ p_i = \frac{s_i^{\,2}}{\sum_j s_j^{\,2}}. \]

This keeps each entropy invariant under overall rescaling of \(\{s_i\}\) and prevents degenerate inputs (zero norm or empty spectra) from surfacing as NaN/∞ during the stress tests.
Because the normalization happens independently at every bond, the profile and its aggregate summaries (total, average, and augmented entropy) also remain unchanged when every singular value across the lattice is scaled by the same constant—locking the helpers to the underlying probability simplex instead of raw magnitudes. Zeros are explicitly ignored in the \(p_i \log p_i\) and Rényi sums so they never inject NaN/∞ and cannot break scaling invariance; the helper functions only ever see the probabilities supported on the non-zero spectrum.

### Aggregate entanglement measures used in tests

We evaluate several aggregate quantities derived from the per-bond spectrum \(\{\lambda^{(b)}_i\}\) that are referenced throughout the reliability suite:

* **Total entanglement entropy** sums the von Neumann entropy over bonds \(b\) to capture the network-wide entanglement budget,

  \[\boxed{\;S_\text{total} = \sum_{b=1}^{n-1} S\big(\rho_A^{(b)}\big) = \sum_{b=1}^{n-1} \Big(-\sum_i \lambda^{(b)}_i \log_2 \lambda^{(b)}_i\Big)\; }\]

* **Average entanglement entropy** normalizes the total by the number of bonds,

  \[\boxed{\;\bar{S} = \frac{1}{n-1} \, S_\text{total}\; }\]

* **Entropy profile** is the ordered list \([S(\rho_A^{(1)}), \ldots, S(\rho_A^{(n-1)})]\), allowing local spikes or drops to be detected.

* **Augmented entropy** adds the polynomial scaling term used in regression checks,

  \[\boxed{\;S_\text{aug}(n) = S_\text{total} + \pi n^2\; }\]

These expressions tie the implemented helpers (`total_entanglement_entropy`, `average_entanglement_entropy`, `entropy_profile`, and `augmented_entropy`) directly to the matrix-based definitions above, ensuring every test expectation is grounded in a closed-form equation.

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

## Packaging and Publishing

The repository ships first-class builds for browsers, Node.js, and bundlers. All packaging commands produce optimized release artifacts and are wired into `prepublishOnly` to avoid shipping debug WASM.

### npm (WASM)
1. Build every target so `pkg/`, `pkg-node/`, and `pkg-bundler/` stay in sync:
   ```bash
   npm run clean
   npm run build:all
   ```
2. Sanity-check what will be uploaded with an npm pack dry-run:
   ```bash
   npm pack --dry-run
   ```
3. Publish the release artifacts (uses the web build by default and exposes `./node` and `./bundler` exports for Node and modern bundlers):
   ```bash
   npm publish
   ```

### crates.io (Rust library)
1. Confirm the crate compiles in release mode and that documentation renders:
   ```bash
   cargo test --release
   cargo doc --no-deps
   ```
2. Validate the manifest and package contents:
   ```bash
   cargo publish --dry-run
   ```
3. Push the crate to crates.io once checks are clean:
   ```bash
   cargo publish
   ```

Both publishing workflows assume a clean git state and that `wasm-pack` (pinned in `devDependencies`) is available on your PATH.

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
| **Argon2id** | Variable | - | - | Memory-hard KDF |
| **Balloon** | Variable | - | - | Space-hard KDF |
| **Time-lock** | Variable | - | - | Sequential hashing |

---

## Quantum Fortress

Quantum Fortress combines three cryptographic hardening techniques designed to make password cracking computationally infeasible - even for quantum computers.

```
┌─────────────────────────────────────────────────────────────────┐
│                     QUANTUM FORTRESS                             │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Password ─▶ [Argon2id] ─▶ [Balloon] ─▶ [Time-lock] ─▶ Hash    │
│                  │             │             │                   │
│              Memory-hard   Space-hard   Sequential               │
│              (1GB+ RAM)    (Provable)   (Can't parallelize)     │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Why Quantum Computers Can't Help

| Technique | Quantum Resistance |
|:----------|:-------------------|
| **Argon2id** | Requires 1GB+ RAM per guess. Quantum computers have ~125KB coherent memory |
| **Balloon** | Provably space-hard. No quantum speedup for memory-bound algorithms |
| **Time-lock** | Sequential hash chains cannot be parallelized by any means |

### JavaScript Usage

```javascript
import { Fortress, quickHash, fortressHash } from 'quantumwall';

// Quick hash (Argon2id only - fast)
const hash = quickHash("password", "salt");

// Full fortress (Argon2 + Balloon + Time-lock)
const fortress = Fortress.standard();
const hash = fortress.hashPassword("password", "salt");

// Maximum security
const fortress = Fortress.quantum();
const hash = fortress.hashPassword("password", "salt");
```

### Test Hash Challenge

Can you crack this hash? Find the password that produces:

```
ea7e8318ce39b09ebdd58b28be5b9caddbe18f25d7b677ddedc538535a35d694
```

**Parameters:**
- Salt: `quantumwall_salt_2024`
- Pipeline: Argon2id (interactive) -> Balloon (16KB) -> Time-lock (10K iterations)

---

### For Quantum Computing Researchers

We invite researchers with access to quantum hardware (IBM, Google, IonQ, Rigetti, etc.) to attempt breaking this hash. Here's your roadmap:

#### Step 1: Understand What You're Up Against

```
Your Quantum Computer          vs          This Hash
═══════════════════════                    ═══════════════════
~1,000 qubits (2024)                       16 MB RAM required (Argon2)
~100 μs coherence time                     10,000 sequential hashes
~125 KB usable memory                      16 KB buffer (Balloon)
```

#### Step 2: The Attack Vectors (All Blocked)

| Attack | Why It Fails |
|:-------|:-------------|
| **Grover's Algorithm** | Provides √N speedup, but memory-hardness negates this. You'd need 16MB of quantum RAM per guess. Current quantum computers have ~125KB. |
| **Parallel Guessing** | Time-lock requires 10,000 *sequential* SHA-256 hashes. Quantum parallelism doesn't help sequential operations. |
| **Shor's Algorithm** | Only breaks RSA/ECC. SHA-256 and Argon2 have no algebraic structure to exploit. |
| **Quantum RAM (qRAM)** | Theoretical only. No working qRAM exists. Even if it did, Balloon hashing requires classical memory access patterns. |

#### Step 3: Try It Anyway (Seriously, Please Try)

```python
# Qiskit example - encode a password guess
from qiskit import QuantumCircuit, transpile
from qiskit_ibm_runtime import QiskitRuntimeService

# Your quantum circuit to somehow compute:
# SHA256(SHA256(SHA256(...10000x...(Balloon(Argon2(guess, salt))))))
#
# Spoiler: You can't. But prove us wrong.

qc = QuantumCircuit(256)  # You'll need way more qubits
# ... your breakthrough algorithm here ...
```

#### Step 4: What Would Actually Work

To crack this hash on a quantum computer, you would need:

| Requirement | Current State | Gap |
|:------------|:--------------|:----|
| Qubits | ~1,000 | Need ~1,000,000+ |
| Coherence | ~100 μs | Need ~10 seconds |
| Quantum RAM | 0 bytes | Need 16+ MB |
| Error Rate | ~0.1% | Need ~0.0001% |

#### Step 5: Claim Your Victory

If you crack it, the password will be a recognizable English phrase. Submit proof to our GitHub issues with:
1. The password
2. Your quantum hardware specs
3. The algorithm you used
4. We'll mass congratulate you (and update this README)

**Current Status: UNCRACKED**

*Last updated: 2025*

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
│       ├── kdf.rs       # HKDF-SHA256
│       ├── argon2.rs    # Argon2id memory-hard KDF
│       ├── balloon.rs   # Balloon space-hard hashing
│       ├── timelock.rs  # Time-lock puzzles
│       └── fortress.rs  # Quantum Fortress API
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
