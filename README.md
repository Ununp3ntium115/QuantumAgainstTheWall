# QuantumWall

**Quantum entropy computation and cryptography at scale using tensor networks.**

Compute von Neumann entropy for systems with millions of qubits using Matrix Product States (MPS) - something impossible with traditional density matrix approaches. Features quantum-seeded cryptographic primitives for secure data encryption.

---

## Why QuantumWall?

### The Exponential Wall Problem

Traditional quantum computing libraries hit a hard wall:

| Qubits | Full State Memory | Feasible? |
|--------|-------------------|-----------|
| 20 | 17.6 TB | No |
| 30 | 10^7 TB | No |
| 1,000,000 | 10^600000 TB | Impossible |

### Our Solution: Tensor Networks

QuantumWall uses **Matrix Product States** to break through:

| Qubits | MPS Memory (chi=64) | Feasible? |
|--------|---------------------|-----------|
| 20 | 320 KB | Yes |
| 10,000 | 160 MB | Yes |
| 1,000,000 | 16 GB | Yes |

---

## Installation

### npm (JavaScript/TypeScript)

```bash
npm install quantumwall
```

### Rust

```toml
[dependencies]
quantum-wall = "0.1"
```

---

## Quick Start

### JavaScript/TypeScript

```javascript
import init, { QuantumState } from 'quantumwall';

async function main() {
    await init();

    // Create a quantum state with 1 million qubits
    const state = new QuantumState(1_000_000, 64);

    console.log(`Qubits: ${state.nQubits}`);
    console.log(`Memory: ${state.memoryString}`);

    // Apply quantum gates
    state.hadamard(0);
    state.pauliX(100);
    state.ry(500_000, Math.PI / 4);

    // Compute entropy
    console.log(`Total entropy: ${state.totalEntropy()} bits`);
    console.log(`Augmented entropy (S + pi*n^2): ${state.augmentedEntropy()}`);

    // Get entropy profile across all bonds
    const profile = state.entropyProfile();
}

main();
```

### Rust

```rust
use quantum_wall::{MPS, total_entanglement_entropy, augmented_entropy};
use quantum_wall::gates::{apply_single_gate, standard_gates};

fn main() {
    // Create a million-qubit state with bond dimension 64
    let mut mps = MPS::new(1_000_000, 64);

    // Apply gates
    apply_single_gate(&mut mps, 0, &standard_gates::hadamard());

    // Compute entropy
    println!("Memory: {} bytes", mps.memory_usage());
    println!("Total entropy: {} bits", total_entanglement_entropy(&mps));
    println!("Augmented entropy: {}", augmented_entropy(&mps));
}
```

---

## API Reference

### QuantumState (JavaScript)

#### Constructor

```javascript
new QuantumState(n_qubits, bond_dim)
```

- `n_qubits`: Number of qubits (can be millions)
- `bond_dim`: Bond dimension (controls accuracy vs memory, typically 32-256)

#### Properties

| Property | Type | Description |
|----------|------|-------------|
| `nQubits` | number | Number of qubits |
| `bondDim` | number | Bond dimension |
| `memoryBytes` | number | Memory usage in bytes |
| `memoryString` | string | Human-readable memory (e.g., "16.5 GB") |

#### Entropy Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `totalEntropy()` | number | Sum of entanglement entropy at all bonds (bits) |
| `averageEntropy()` | number | Average entropy per bond (bits) |
| `maxEntropy()` | number | Maximum entropy at any bond (bits) |
| `augmentedEntropy()` | number | S + pi * n^2 |
| `entropyAtBond(i)` | number | Entropy at specific bond i |
| `entropyProfile()` | number[] | Array of entropy values at each bond |
| `maxEntropyBound()` | number | Theoretical max entropy for this bond dimension |

#### Quantum Gates

| Method | Description |
|--------|-------------|
| `hadamard(site)` | Hadamard gate |
| `pauliX(site)` | Pauli-X (NOT) gate |
| `pauliY(site)` | Pauli-Y gate |
| `pauliZ(site)` | Pauli-Z gate |
| `sGate(site)` | S (phase) gate |
| `tGate(site)` | T gate |
| `rx(site, theta)` | X-rotation by theta |
| `ry(site, theta)` | Y-rotation by theta |
| `rz(site, theta)` | Z-rotation by theta |
| `hadamardAll()` | Apply Hadamard to all qubits |

---

## Cryptography API

QuantumWall includes production-grade cryptographic primitives seeded by quantum entropy.

### CryptoRng (JavaScript)

A cryptographically secure random number generator seeded by quantum entropy.

```javascript
import { QuantumState, CryptoRng } from 'quantumwall';

// Create RNG seeded from quantum state
const state = new QuantumState(100, 32);
state.hadamardAll(); // Create entanglement for entropy
const rng = CryptoRng.fromQuantumState(state);

// Or from a 32-byte seed
const rng2 = CryptoRng.fromSeed(new Uint8Array(32));

// Generate random bytes
const bytes = rng.randomBytes(64);
console.log(`Entropy: ${rng.entropyBits} bits`);
```

### SymmetricCrypto (JavaScript)

Symmetric encryption with AES-256-GCM or ChaCha20-Poly1305.

```javascript
import { QuantumState, SymmetricCrypto } from 'quantumwall';

// Create crypto context seeded from quantum state
const state = new QuantumState(100, 32);
state.hadamardAll();
const crypto = SymmetricCrypto.fromQuantumState(state);

// Or from explicit key and seed
const key = new Uint8Array(32); // Your 256-bit key
const seed = new Uint8Array(32); // Nonce generation seed
const crypto2 = SymmetricCrypto.fromKey(key, seed);

// Encrypt with AES-256-GCM
const message = new TextEncoder().encode("Secret message");
const encrypted = crypto.encryptAesGcm(message);

// Or with ChaCha20-Poly1305
const encrypted2 = crypto.encryptChaCha20(message);

// Encrypt with Additional Authenticated Data (AAD)
const aad = new TextEncoder().encode("metadata");
const encrypted3 = crypto.encryptWithAad(message, aad, "aes-256-gcm");

// Decrypt
const decrypted = crypto.decrypt(encrypted);
const decryptedWithAad = crypto.decryptWithAad(encrypted3, aad);

// Serialize for storage/transmission
const bytes = encrypted.toBytes();
const restored = EncryptedPayload.fromBytes(bytes);
```

### Key Derivation (JavaScript)

Derive keys using HKDF with SHA-256.

```javascript
import { deriveKey, sha256 } from 'quantumwall';

// Derive a 256-bit key
const inputKey = new Uint8Array([...]); // Input keying material
const salt = new Uint8Array([...]);     // Optional salt
const info = new TextEncoder().encode("app-context");
const derivedKey = deriveKey(inputKey, salt, info);

// SHA-256 hash
const hash = sha256(new TextEncoder().encode("data"));
```

### Rust Crypto API

```rust
use quantum_wall::{MPS, QuantumRng, SecretKey, encrypt, decrypt};
use quantum_wall::crypto::symmetric::SymmetricAlgorithm;

fn main() {
    // Create RNG from quantum state
    let mut mps = MPS::new(100, 32);
    let mut rng = QuantumRng::from_mps(&mps).unwrap();

    // Generate encryption key
    let key = SecretKey::generate(&mut rng);

    // Encrypt data
    let plaintext = b"Hello, quantum world!";
    let encrypted = encrypt(
        &key,
        plaintext,
        None, // No AAD
        &mut rng,
        SymmetricAlgorithm::ChaCha20Poly1305,
    ).unwrap();

    // Decrypt data
    let decrypted = decrypt(&key, &encrypted, None).unwrap();
    assert_eq!(plaintext.to_vec(), decrypted);
}
```

### Supported Algorithms

| Algorithm | Key Size | Nonce | Tag | Use Case |
|-----------|----------|-------|-----|----------|
| AES-256-GCM | 256-bit | 96-bit | 128-bit | Data at rest, high-performance |
| ChaCha20-Poly1305 | 256-bit | 96-bit | 128-bit | Data in transit, side-channel resistant |
| HKDF-SHA256 | Variable | Variable | N/A | Key derivation |
| SHA-256 | N/A | N/A | 256-bit | Hashing |

### Security Notes

- Keys are automatically zeroed from memory on drop
- Nonces are generated securely and never reused
- All encryption uses authenticated modes (GCM, Poly1305)
- Quantum entropy provides high-quality seeding for the CSPRNG

---

## How It Works

### Matrix Product States (MPS)

Instead of storing the full quantum state |psi> in C^(2^n), we represent it as a product of matrices:

```
|psi> = sum_{s1...sn} A[1]^{s1} * A[2]^{s2} * ... * A[n]^{sn} |s1 s2 ... sn>
```

Each A[i] is a chi x chi matrix, giving O(n * chi^2) memory instead of O(2^n).

### Entanglement Entropy from Bond Singular Values

For a bipartition at bond i, the von Neumann entropy is computed directly from singular values:

```
S = -sum_j lambda_j^2 * log2(lambda_j^2)
```

No need to construct or diagonalize exponentially large density matrices.

### Augmented Entropy Measure

The augmented entropy combines quantum entanglement with system size:

```
E = S + pi * n^2
```

This provides a scale-aware entropy measure for large quantum systems.

---

## Memory Scaling

| Qubits | Full State | MPS (chi=64) | MPS (chi=256) |
|--------|------------|--------------|---------------|
| 20 | 17.6 TB | 320 KB | 5 MB |
| 100 | infinity | 1.6 MB | 26 MB |
| 1,000 | infinity | 16 MB | 260 MB |
| 10,000 | infinity | 160 MB | 2.6 GB |
| 100,000 | infinity | 1.6 GB | 26 GB |
| 1,000,000 | infinity | 16 GB | 262 GB |

---

## Building from Source

### Prerequisites

- Rust (latest stable)
- wasm-pack (`cargo install wasm-pack`)
- Node.js 16+

### Build Commands

```bash
# Rust library
cargo build --release
cargo test

# WebAssembly package
wasm-pack build --target web --out-dir pkg

# Or use npm script
npm run build
```

---

## Project Structure

```
quantumwall/
├── src/
│   ├── lib.rs          # Public API
│   ├── mps.rs          # Matrix Product State implementation
│   ├── entropy.rs      # Entropy calculations
│   ├── gates.rs        # Quantum gate operations
│   ├── wasm.rs         # WebAssembly bindings
│   └── crypto/
│       ├── mod.rs      # Crypto module structure
│       ├── rng.rs      # Quantum-seeded CSPRNG
│       ├── keys.rs     # Key types and X25519
│       ├── symmetric.rs # AES-GCM, ChaCha20-Poly1305
│       └── kdf.rs      # HKDF key derivation
├── pkg/                # Built npm package
├── Cargo.toml          # Rust config
└── package.json        # npm config
```

---

## Use Cases

- **Quantum Algorithm Research**: Study entropy dynamics in large quantum systems
- **Quantum Error Correction**: Analyze entanglement in error-correcting codes
- **Many-Body Physics**: Compute entanglement in condensed matter systems
- **Quantum Machine Learning**: Entropy-based features for quantum ML models
- **Quantum Cryptography**: Use MPS entropy to seed cryptographically secure RNGs
- **Secure Data Storage**: Encrypt data at rest with quantum-seeded AES-256-GCM
- **Secure Communications**: Encrypt data in transit with ChaCha20-Poly1305

---

## Limitations

- MPS best represents states with **bounded entanglement** (area-law states)
- Highly entangled states may require large bond dimensions
- Two-qubit gates between distant qubits are more expensive than nearest-neighbor

---

## License

UNLICENSED - All rights reserved.

Copyright (c) 2024 QuantumAgainstTheWall Contributors
