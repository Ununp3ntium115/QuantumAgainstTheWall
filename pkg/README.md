# QuantumWall

Quantum entropy computation at scale using tensor networks.

## The Problem

Traditional quantum state representations require exponential memory:
- Full density matrix: O(4^n) complex numbers
- For n=30 qubits: ~10^18 entries (~10^7 TB)
- For millions of qubits: impossible

## The Solution

This library uses **Matrix Product States (MPS)** to represent quantum states with polynomial memory:
- Memory: O(n * chi^2) where chi is bond dimension
- For n=1,000,000 qubits with chi=64: ~16 GB (actually computable!)
- Entanglement entropy computed directly from bond singular values

## Installation

### Rust

```toml
[dependencies]
quantum-wall = "0.1"
```

### JavaScript/TypeScript (via npm)

```bash
npm install quantumwall
```

## Usage

### Rust

```rust
use quantum_wall::{MPS, total_entanglement_entropy, augmented_entropy};

fn main() {
    // Create a million-qubit state with bond dimension 64
    let mps = MPS::new(1_000_000, 64);

    println!("Memory: {} bytes", mps.memory_usage());
    println!("Total entropy: {} bits", total_entanglement_entropy(&mps));
    println!("Augmented entropy: {}", augmented_entropy(&mps));
}
```

### JavaScript

```javascript
import init, { QuantumState } from 'quantumwall';

async function main() {
    await init();

    // Create a million-qubit state
    const state = new QuantumState(1_000_000, 64);

    console.log(`Qubits: ${state.nQubits}`);
    console.log(`Memory: ${state.memoryString}`);

    // Apply gates
    state.hadamard(0);
    state.hadamard(500_000);

    // Compute entropy
    console.log(`Total entropy: ${state.totalEntropy()} bits`);
    console.log(`Augmented entropy: ${state.augmentedEntropy()}`);
}

main();
```

## Features

- **Matrix Product States**: Efficient quantum state representation
- **Entanglement Entropy**: Von Neumann entropy from bond SVD
- **Quantum Gates**: H, X, Y, Z, S, T, Rx, Ry, Rz, CNOT, CZ, SWAP
- **WebAssembly**: Use from JavaScript/TypeScript
- **Scalable**: Millions of qubits on commodity hardware

## Scaling

| n (qubits) | Full State | MPS (chi=64) | MPS (chi=256) |
|------------|------------|--------------|---------------|
| 20         | 17.6 TB    | 320 KB       | 5 MB          |
| 100        | infinity   | 1.6 MB       | 26 MB         |
| 10,000     | infinity   | 160 MB       | 2.6 GB        |
| 1,000,000  | infinity   | 16 GB        | 262 GB        |

## Building

### Rust library

```bash
cargo build --release
cargo test
```

### WebAssembly package

```bash
# Install wasm-pack first: cargo install wasm-pack
wasm-pack build --target web
```

### npm package

```bash
npm run build
```

## Theory

### Matrix Product States

Instead of storing |psi> in C^(2^n), represent as:

```
|psi> = sum A[1]^{s1} * A[2]^{s2} * ... * A[n]^{sn} |s1 s2 ... sn>
```

where each A[i] is a chi x chi matrix.

### Entanglement Entropy from MPS

For bipartition at bond i, entropy is:

```
S = -sum_j lambda_j^2 * log2(lambda_j^2)
```

where lambda_j are the singular values at that bond.

### Augmented Entropy

```
E = S + pi * n^2
```

Combines quantum entropy with polynomial scaling term.

## License

UNLICENSED - All rights reserved.
