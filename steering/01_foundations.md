# Mathematical Foundations

## 1. Notation and Definitions

### 1.1 Basic Notation

- **ℕ**: Natural numbers {0, 1, 2, ...}
- **ℤ**: Integers {..., -2, -1, 0, 1, 2, ...}
- **ℝ**: Real numbers
- **{0,1}ⁿ**: Binary strings of length n
- **{0,1}***: All finite binary strings
- **|x|**: Bit length of x
- **x ← S**: Sample x uniformly from set S
- **x ∥ y**: Concatenation of x and y
- **⊕**: XOR (exclusive OR) operation

### 1.2 Functions

**Definition 1.1** (Hash Function)
A hash function H: {0,1}* → {0,1}ⁿ maps arbitrary-length inputs to fixed-length outputs.

**Definition 1.2** (Collision Resistance)
A hash function H is (t, ε)-collision resistant if no algorithm running in time t can find x ≠ y with H(x) = H(y) with probability > ε.

**Definition 1.3** (Preimage Resistance)
A hash function H is (t, ε)-preimage resistant if given y = H(x) for random x, no algorithm running in time t can find x' with H(x') = y with probability > ε.

### 1.3 Computational Complexity

**Definition 1.4** (Time Complexity)
- **O(f(n))**: Upper bound - grows at most as fast as f(n)
- **Ω(f(n))**: Lower bound - grows at least as fast as f(n)
- **Θ(f(n))**: Tight bound - grows exactly as fast as f(n)

**Definition 1.5** (Polynomial Time)
An algorithm runs in polynomial time if its time complexity is O(nᶜ) for some constant c.

**Definition 1.6** (Exponential Time)
An algorithm runs in exponential time if its time complexity is Ω(2^(nᵃ)) for some constant a > 0.

### 1.4 Probability Theory

**Definition 1.7** (Probability Space)
A probability space (Ω, F, ℙ) consists of:
- Ω: Sample space (set of all outcomes)
- F: Event space (σ-algebra of subsets of Ω)
- ℙ: Probability measure ℙ: F → [0,1]

**Definition 1.8** (Expected Value)
For discrete random variable X:
```
𝔼[X] = Σ xᵢ · ℙ[X = xᵢ]
```

**Definition 1.9** (Independence)
Events A and B are independent if:
```
ℙ[A ∩ B] = ℙ[A] · ℙ[B]
```

## 2. Cryptographic Primitives

### 2.1 One-Way Functions

**Definition 2.1** (One-Way Function)
A function f: {0,1}* → {0,1}* is (t, ε)-one-way if:
1. f is efficiently computable (polynomial time)
2. For all algorithms A running in time t:
   ```
   ℙ[f(A(f(x), 1ⁿ)) = f(x)] < ε
   ```
   where x ← {0,1}ⁿ

**Theorem 2.1** (OWF Existence)
If one-way functions exist, then ℙ ≠ NP.

*Proof sketch*: If ℙ = NP, then inverting f(x) is in ℙ (finding preimage), contradicting one-wayness. ∎

### 2.2 Pseudorandom Functions

**Definition 2.2** (PRF)
A function family F = {fₖ: {0,1}ⁿ → {0,1}ⁿ}ₖ∈𝒦 is a (t, q, ε)-pseudorandom function if for all algorithms A making at most q queries in time t:
```
|ℙ[A^(fₖ)(1ⁿ) = 1] - ℙ[A^R(1ⁿ) = 1]| < ε
```
where k ← 𝒦 and R is a truly random function.

### 2.3 Random Oracle Model

**Definition 2.3** (Random Oracle)
A random oracle H: {0,1}* → {0,1}ⁿ is a truly random function accessible to all parties (including adversaries) via oracle queries.

**Assumption 2.1** (Random Oracle Assumption)
For security analysis, we model hash functions (SHA-256, SHA-3, etc.) as random oracles.

## 3. Memory-Hard Functions

### 3.1 Time-Space Tradeoffs

**Definition 3.1** (Time-Space Complexity)
A function f has time-space complexity T·S if:
- Fastest algorithm requires time T with space S
- Cannot be computed in time T' < T with space S' < S without T'·S' ≥ T·S

**Definition 3.2** (Memory-Hard Function)
A function f: {0,1}* → {0,1}ⁿ is (S, T)-memory-hard if:
1. The intended algorithm uses space S and time T
2. Any algorithm using space S' < S requires time T' with T'·S' ≥ T·S

### 3.2 Pebbling Complexity

**Definition 3.3** (Pebbling Game)
Given a directed acyclic graph (DAG) G = (V, E):
- Place pebbles on vertices (represents memory usage)
- Rules:
  - Can place pebble on v if all parents pebbled
  - Can remove pebble from any vertex
  - Goal: Pebble target vertex t
- Space complexity: Maximum pebbles used simultaneously
- Time complexity: Number of pebbling steps

**Theorem 3.1** (Pebbling Lower Bound - Paul-Tarjan-Celoni)
For depth-robust graphs with n vertices, any pebbling strategy requires either:
- Space Ω(n), or
- Time·Space Ω(n²)

*Proof*: See Paul, Tarjan, Celoni (1977) "Space bounds for a game on graphs" ∎

## 4. Lattice-Based Cryptography

### 4.1 Lattices

**Definition 4.1** (Lattice)
Given linearly independent vectors ***b***₁, ..., ***b***ₙ ∈ ℝᵐ, the lattice Λ is:
```
Λ = {Σᵢ zᵢ***b***ᵢ : zᵢ ∈ ℤ}
```

The vectors {***b***ᵢ} form a basis of Λ.

**Definition 4.2** (Shortest Vector Problem - SVP)
Given a lattice basis, find the shortest non-zero vector in the lattice:
```
SVP(Λ) = min{||***v***|| : ***v*** ∈ Λ \ {0}}
```

**Theorem 4.1** (SVP Hardness)
SVP is NP-hard for ℓ_∞ norm (Ajtai 1998) and NP-hard to approximate within certain factors for ℓ₂ norm.

### 4.2 Learning With Errors (LWE)

**Definition 4.3** (LWE Distribution)
Given security parameter n, modulus q, and error distribution χ over ℤ_q:
- Secret: ***s*** ← ℤ_qⁿ
- Sample: (***a***, b = ⟨***a***, ***s***⟩ + e mod q)
  where ***a*** ← ℤ_qⁿ and e ← χ

**Problem 4.1** (LWE Decision Problem)
Distinguish between:
- (***a***ᵢ, bᵢ = ⟨***a***ᵢ, ***s***⟩ + eᵢ mod q) for fixed secret ***s***
- (***a***ᵢ, uᵢ) where uᵢ ← ℤ_q are uniform

**Theorem 4.2** (LWE Hardness - Regev 2005)
For appropriate parameters, LWE is at least as hard as quantumly solving worst-case lattice problems (GapSVP, SIVP) with approximation factor Õ(n/α) where α is the error rate.

*Implications*: Breaking LWE-based schemes requires breaking worst-case hard lattice problems.

### 4.3 Module-LWE (ML-KEM/ML-DSA)

**Definition 4.4** (Module-LWE)
Generalization of LWE over polynomial rings R_q = ℤ_q[X]/(X^n + 1):
- Secret: ***s*** ∈ R_q^k (module of rank k)
- Sample: (***a***, b = ***a***^T · ***s*** + e mod q)
  where ***a*** ← R_q^k and e ← χ^k

**Theorem 4.3** (MLWE Hardness)
MLWE reduces to Ring-LWE, which reduces to worst-case ideal lattice problems.

## 5. Quantum Computing Basics

### 5.1 Quantum States

**Definition 5.1** (Qubit)
A qubit is a unit vector in ℂ²:
```
|ψ⟩ = α|0⟩ + β|1⟩
where |α|² + |β|² = 1
```

**Definition 5.2** (Quantum Register)
An n-qubit register is a unit vector in (ℂ²)^⊗n ≅ ℂ^(2ⁿ):
```
|ψ⟩ = Σᵢ αᵢ|i⟩
where Σᵢ |αᵢ|² = 1
```

### 5.2 Quantum Algorithms

**Theorem 5.1** (Shor's Algorithm - 1994)
Quantum computers can factor n-bit integers in time O(n² log n log log n) using O(n) qubits.

**Theorem 5.2** (Grover's Algorithm - 1996)
Quantum computers can search an unsorted database of N items in time O(√N) using O(log N) qubits.

**Corollary 5.1** (Hash Function Security)
If a hash function has n-bit output and 2^n classical security:
- Shor's algorithm: No advantage (no structure to exploit)
- Grover's algorithm: Reduces security to 2^(n/2)

*Conclusion*: Double the output length to maintain n-bit quantum security.

### 5.3 Quantum Limitations

**Theorem 5.3** (Decoherence Time Bound)
A quantum computer with error rate ε requires error correction overhead:
```
O(poly(1/ε))
```

**Fact 5.1** (Current Quantum Computers - 2025)
- Coherent qubits: ~1000 (Google, IBM)
- Coherence time: ~100 μs
- Error rate: ~0.1% per gate
- Effective quantum RAM: ~125 KB

**Theorem 5.4** (Quantum RAM Requirements - Grassl et al.)
To apply Grover's algorithm to break a cryptographic hash with work factor W:
```
Quantum RAM needed: Ω(log² W)
Quantum coherence time: Ω(√W)
```

For W = 2^128:
- Quantum RAM: Ω(16 KB) for algorithm state
- Additional RAM for target data
- Coherence time: Ω(2^64) operations at gate time ~1 μs = 10^13 years

**Corollary 5.2** (Quantum Computer Impossibility for QuantumWall)
QuantumWall's memory requirements (1 GB) exceed quantum RAM capabilities by factor of:
```
1 GB / 125 KB ≈ 8,000×
```

Even with perfect quantum computers, the memory wall remains.

## 6. Information-Theoretic Security

### 6.1 Entropy

**Definition 6.1** (Shannon Entropy)
For discrete random variable X:
```
H(X) = -Σ ℙ[X = x] · log₂ ℙ[X = x]
```

**Definition 6.2** (Min-Entropy)
```
H_∞(X) = -log₂(max ℙ[X = x])
```

**Definition 6.3** (Conditional Entropy)
```
H(X|Y) = Σ ℙ[Y = y] · H(X|Y = y)
```

### 6.2 Perfect Secrecy

**Definition 6.4** (Perfect Secrecy - Shannon)
An encryption scheme (E, D) has perfect secrecy if for all messages m, m' and ciphertext c:
```
ℙ[M = m | C = c] = ℙ[M = m]
```

**Theorem 6.1** (Shannon's Theorem)
Perfect secrecy requires |𝒦| ≥ |ℳ| (key space ≥ message space).

**Corollary 6.1** (One-Time Pad)
XOR with random key achieves perfect secrecy:
```
c = m ⊕ k where k ← {0,1}ⁿ
```

## 7. Thermodynamic Limits

### 7.1 Landauer's Principle

**Theorem 7.1** (Landauer 1961)
Erasing one bit of information at temperature T requires minimum energy:
```
E ≥ kᵦT ln 2
```
where kᵦ ≈ 1.38×10^(-23) J/K (Boltzmann constant).

**Corollary 7.1** (Computational Energy Bound)
At room temperature (T = 300K):
```
E_bit ≥ 2.87×10^(-21) J per bit erased
```

**Application 7.1** (Brute-Force Attack Energy)
To try all 2^128 keys:
```
E ≥ 2^128 · 2.87×10^(-21) J
  ≈ 9.75×10^17 J
  ≈ 2.7×10^11 kWh
  ≈ 30 years of global energy production
```

**Conclusion**: Even with perfect efficiency, brute-force attacks are physically impossible for large key spaces.

## 8. Reduction Proofs

### 8.1 Security Reductions

**Definition 8.1** (Security Reduction)
To prove scheme S is secure assuming problem P is hard:
1. Assume adversary A breaks S with probability ε in time t
2. Construct algorithm B that uses A to solve P
3. Show B solves P with probability ε' in time t'
4. If ε' and t' contradict hardness of P, then A cannot exist

**Theorem 8.1** (Reduction Tightness)
A reduction is tight if:
```
ε' ≈ ε (same success probability)
t' ≈ t (same running time)
```

Loose reductions require stronger assumptions.

### 8.2 Black-Box Reductions

**Definition 8.2** (Black-Box Reduction)
Algorithm B uses adversary A as a black box (oracle) without knowledge of A's internals.

**Theorem 8.2** (Black-Box Impossibility - Impagliazzo-Rudich)
Certain reductions cannot be proven black-box (e.g., one-way functions from complexity assumptions alone).

## 9. Provable Security Models

### 9.1 Standard Model

Security holds under standard computational assumptions (no idealized components).

### 9.2 Random Oracle Model (ROM)

Hash functions modeled as random oracles (accessible via queries only).

**Advantages**:
- Enables simpler proofs
- Captures intuition about hash functions

**Disadvantages**:
- Real hash functions are not random oracles
- ROM-secure schemes can be insecure in reality (though rare)

### 9.3 Generic Group Model

Adversary has no special knowledge of group structure (only black-box group operations).

## 10. References

1. **Goldreich, O.** (2001). "Foundations of Cryptography: Volume 1, Basic Tools"
2. **Katz, J. & Lindell, Y.** (2020). "Introduction to Modern Cryptography, 3rd Edition"
3. **Regev, O.** (2005). "On Lattices, Learning with Errors, Random Linear Codes, and Cryptography"
4. **Shor, P.** (1997). "Polynomial-Time Algorithms for Prime Factorization and Discrete Logarithms on a Quantum Computer"
5. **Grover, L.** (1996). "A Fast Quantum Mechanical Algorithm for Database Search"
6. **Landauer, R.** (1961). "Irreversibility and Heat Generation in the Computing Process"
7. **Shannon, C.** (1949). "Communication Theory of Secrecy Systems"
8. **Paul, W., Tarjan, R., & Celoni, J.** (1977). "Space Bounds for a Game on Graphs"

---

**Next**: [02_bandwidth_hard.md](02_bandwidth_hard.md) - Bandwidth-Hard Functions
