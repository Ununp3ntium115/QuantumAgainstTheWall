/* tslint:disable */
/* eslint-disable */

export class CryptoRng {
  private constructor();
  free(): void;
  [Symbol.dispose](): void;
  /**
   * Generate random bytes.
   */
  randomBytes(len: number): Uint8Array;
  /**
   * Create a new RNG seeded from a quantum state.
   *
   * The entropy from the MPS entanglement structure is used to seed
   * a ChaCha20-based CSPRNG.
   */
  static fromQuantumState(state: QuantumState): CryptoRng;
  /**
   * Create a new RNG from a 32-byte seed.
   */
  static fromSeed(seed: Uint8Array): CryptoRng;
  /**
   * Get the entropy bits used to seed this RNG.
   */
  readonly entropyBits: number;
}

export class EncryptedPayload {
  private constructor();
  free(): void;
  [Symbol.dispose](): void;
  /**
   * Deserialize from bytes.
   */
  static fromBytes(bytes: Uint8Array): EncryptedPayload;
  /**
   * Serialize to bytes for storage/transmission.
   */
  toBytes(): Uint8Array;
  /**
   * Get the ciphertext bytes.
   */
  readonly ciphertext: Uint8Array;
  /**
   * Get the authentication tag bytes.
   */
  readonly tag: Uint8Array;
  /**
   * Get the nonce bytes.
   */
  readonly nonce: Uint8Array;
  /**
   * Get the algorithm name.
   */
  readonly algorithm: string;
}

export class Fortress {
  free(): void;
  [Symbol.dispose](): void;
  /**
   * Hash a password using the Fortress pipeline
   * Returns hex-encoded hash
   */
  hashPassword(password: string, salt: string): string;
  /**
   * Verify a password against a hash
   */
  verifyPassword(password: string, salt: string, expected_hash: string): boolean;
  /**
   * Create a new Fortress with interactive settings (fast)
   */
  constructor();
  /**
   * Create with maximum quantum resistance
   */
  static quantum(): Fortress;
  /**
   * Create with standard security
   */
  static standard(): Fortress;
  /**
   * Get estimated time in seconds
   */
  readonly estimatedTime: number;
  /**
   * Get memory required in bytes
   */
  readonly memoryRequired: number;
}

export class QuantumState {
  free(): void;
  [Symbol.dispose](): void;
  /**
   * Compute maximum entropy at any bond
   */
  maxEntropy(): number;
  /**
   * Apply Hadamard gates to all qubits
   */
  hadamardAll(): void;
  /**
   * Compute total entanglement entropy (sum over all bonds)
   */
  totalEntropy(): number;
  /**
   * Create a state initialized to |++...+⟩ (uniform superposition)
   */
  static newPlusState(n_qubits: number, bond_dim: number): QuantumState;
  /**
   * Compute average entanglement entropy per bond
   */
  averageEntropy(): number;
  /**
   * Compute entanglement entropy at a specific bond
   *
   * # Arguments
   * * `bond` - Bond index (0 to n_qubits - 2)
   *
   * # Returns
   * Entropy in bits
   */
  entropyAtBond(bond: number): number;
  /**
   * Get the entropy profile as an array
   */
  entropyProfile(): Float64Array;
  /**
   * Compute augmented entropy: S + π n²
   */
  augmentedEntropy(): number;
  /**
   * Get the maximum possible entropy for this bond dimension
   */
  maxEntropyBound(): number;
  /**
   * Apply Rx rotation gate
   */
  rx(site: number, theta: number): void;
  /**
   * Apply Ry rotation gate
   */
  ry(site: number, theta: number): void;
  /**
   * Apply Rz rotation gate
   */
  rz(site: number, theta: number): void;
  /**
   * Create a new quantum state initialized to |00...0⟩
   *
   * # Arguments
   * * `n_qubits` - Number of qubits in the system
   * * `bond_dim` - Bond dimension (controls accuracy vs memory)
   *
   * # Example (JavaScript)
   * ```js
   * const state = new QuantumState(1000, 64);
   * ```
   */
  constructor(n_qubits: number, bond_dim: number);
  /**
   * Apply an S (phase) gate to a qubit
   */
  sGate(site: number): void;
  /**
   * Apply a T gate to a qubit
   */
  tGate(site: number): void;
  /**
   * Apply a Pauli-X (NOT) gate to a qubit
   */
  pauliX(site: number): void;
  /**
   * Apply a Pauli-Y gate to a qubit
   */
  pauliY(site: number): void;
  /**
   * Apply a Pauli-Z gate to a qubit
   */
  pauliZ(site: number): void;
  /**
   * Apply a Hadamard gate to a qubit
   */
  hadamard(site: number): void;
  /**
   * Get a string representation of the state
   */
  toString(): string;
  /**
   * Get memory usage in bytes
   */
  readonly memoryBytes: number;
  /**
   * Get memory usage in a human-readable format
   */
  readonly memoryString: string;
  /**
   * Get the bond dimension
   */
  readonly bondDim: number;
  /**
   * Get the number of qubits
   */
  readonly nQubits: number;
}

export class SymmetricCrypto {
  private constructor();
  free(): void;
  [Symbol.dispose](): void;
  /**
   * Encrypt data using AES-256-GCM.
   */
  encryptAesGcm(plaintext: Uint8Array): EncryptedPayload;
  /**
   * Decrypt data with additional authenticated data (AAD).
   */
  decryptWithAad(encrypted: EncryptedPayload, aad: Uint8Array): Uint8Array;
  /**
   * Encrypt data using ChaCha20-Poly1305.
   */
  encryptChaCha20(plaintext: Uint8Array): EncryptedPayload;
  /**
   * Encrypt data with additional authenticated data (AAD).
   */
  encryptWithAad(plaintext: Uint8Array, aad: Uint8Array, algorithm: string): EncryptedPayload;
  /**
   * Create a new symmetric encryption context with a quantum-seeded key.
   */
  static fromQuantumState(state: QuantumState): SymmetricCrypto;
  /**
   * Decrypt data.
   */
  decrypt(encrypted: EncryptedPayload): Uint8Array;
  /**
   * Create a new symmetric encryption context from a 32-byte key.
   */
  static fromKey(key_bytes: Uint8Array, seed: Uint8Array): SymmetricCrypto;
  /**
   * Get the encryption key bytes.
   *
   * WARNING: Handle with care - this exposes the raw key material.
   */
  keyBytes(): Uint8Array;
}

/**
 * Derive a key using HKDF.
 *
 * # Arguments
 * * `input_key` - Input keying material
 * * `salt` - Optional salt (can be empty)
 * * `info` - Context/application-specific info
 *
 * # Returns
 * A 32-byte derived key
 */
export function deriveKey(input_key: Uint8Array, salt: Uint8Array, info: Uint8Array): Uint8Array;

/**
 * Calculate memory requirements for a given system size
 *
 * # Arguments
 * * `n_qubits` - Number of qubits
 * * `bond_dim` - Bond dimension
 *
 * # Returns
 * Approximate memory in bytes
 */
export function estimateMemory(n_qubits: number, bond_dim: number): number;

/**
 * Full fortress hash (Argon2 + Balloon + Time-lock)
 */
export function fortressHash(password: string, salt: string): string;

/**
 * Get the library version
 */
export function getVersion(): string;

/**
 * Initialize panic hook for better error messages in WASM
 */
export function init(): void;

/**
 * Quick hash using Argon2id only (for testing)
 */
export function quickHash(password: string, salt: string): string;

/**
 * Hash data with SHA-256.
 */
export function sha256(data: Uint8Array): Uint8Array;

/**
 * Compute entropy from a histogram of counts.
 *
 * This is useful for classical entropy calculations.
 *
 * # Arguments
 * * `counts` - Array of counts for each bin
 *
 * # Returns
 * Shannon entropy in bits
 */
export function shannonEntropyFromCounts(counts: BigUint64Array): number;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
  readonly memory: WebAssembly.Memory;
  readonly __wbg_cryptorng_free: (a: number, b: number) => void;
  readonly __wbg_encryptedpayload_free: (a: number, b: number) => void;
  readonly __wbg_fortress_free: (a: number, b: number) => void;
  readonly __wbg_quantumstate_free: (a: number, b: number) => void;
  readonly __wbg_symmetriccrypto_free: (a: number, b: number) => void;
  readonly cryptorng_entropyBits: (a: number) => number;
  readonly cryptorng_fromQuantumState: (a: number) => [number, number, number];
  readonly cryptorng_fromSeed: (a: number, b: number) => [number, number, number];
  readonly cryptorng_randomBytes: (a: number, b: number) => [number, number];
  readonly deriveKey: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number, number];
  readonly encryptedpayload_algorithm: (a: number) => [number, number];
  readonly encryptedpayload_ciphertext: (a: number) => [number, number];
  readonly encryptedpayload_fromBytes: (a: number, b: number) => [number, number, number];
  readonly encryptedpayload_nonce: (a: number) => [number, number];
  readonly encryptedpayload_tag: (a: number) => [number, number];
  readonly encryptedpayload_toBytes: (a: number) => [number, number];
  readonly estimateMemory: (a: number, b: number) => number;
  readonly fortressHash: (a: number, b: number, c: number, d: number) => [number, number, number, number];
  readonly fortress_estimatedTime: (a: number) => number;
  readonly fortress_hashPassword: (a: number, b: number, c: number, d: number, e: number) => [number, number, number, number];
  readonly fortress_memoryRequired: (a: number) => number;
  readonly fortress_new: () => number;
  readonly fortress_quantum: () => number;
  readonly fortress_standard: () => number;
  readonly fortress_verifyPassword: (a: number, b: number, c: number, d: number, e: number, f: number, g: number) => [number, number, number];
  readonly getVersion: () => [number, number];
  readonly quantumstate_augmentedEntropy: (a: number) => number;
  readonly quantumstate_averageEntropy: (a: number) => number;
  readonly quantumstate_bondDim: (a: number) => number;
  readonly quantumstate_entropyAtBond: (a: number, b: number) => number;
  readonly quantumstate_entropyProfile: (a: number) => [number, number];
  readonly quantumstate_hadamard: (a: number, b: number) => [number, number];
  readonly quantumstate_hadamardAll: (a: number) => void;
  readonly quantumstate_maxEntropy: (a: number) => number;
  readonly quantumstate_maxEntropyBound: (a: number) => number;
  readonly quantumstate_memoryBytes: (a: number) => number;
  readonly quantumstate_memoryString: (a: number) => [number, number];
  readonly quantumstate_nQubits: (a: number) => number;
  readonly quantumstate_new: (a: number, b: number) => [number, number, number];
  readonly quantumstate_newPlusState: (a: number, b: number) => [number, number, number];
  readonly quantumstate_pauliX: (a: number, b: number) => [number, number];
  readonly quantumstate_pauliY: (a: number, b: number) => [number, number];
  readonly quantumstate_pauliZ: (a: number, b: number) => [number, number];
  readonly quantumstate_rx: (a: number, b: number, c: number) => [number, number];
  readonly quantumstate_ry: (a: number, b: number, c: number) => [number, number];
  readonly quantumstate_rz: (a: number, b: number, c: number) => [number, number];
  readonly quantumstate_sGate: (a: number, b: number) => [number, number];
  readonly quantumstate_tGate: (a: number, b: number) => [number, number];
  readonly quantumstate_toString: (a: number) => [number, number];
  readonly quantumstate_totalEntropy: (a: number) => number;
  readonly quickHash: (a: number, b: number, c: number, d: number) => [number, number, number, number];
  readonly sha256: (a: number, b: number) => [number, number];
  readonly shannonEntropyFromCounts: (a: number, b: number) => number;
  readonly symmetriccrypto_decrypt: (a: number, b: number) => [number, number, number, number];
  readonly symmetriccrypto_decryptWithAad: (a: number, b: number, c: number, d: number) => [number, number, number, number];
  readonly symmetriccrypto_encryptAesGcm: (a: number, b: number, c: number) => [number, number, number];
  readonly symmetriccrypto_encryptChaCha20: (a: number, b: number, c: number) => [number, number, number];
  readonly symmetriccrypto_encryptWithAad: (a: number, b: number, c: number, d: number, e: number, f: number, g: number) => [number, number, number];
  readonly symmetriccrypto_fromKey: (a: number, b: number, c: number, d: number) => [number, number, number];
  readonly symmetriccrypto_fromQuantumState: (a: number) => [number, number, number];
  readonly symmetriccrypto_keyBytes: (a: number) => [number, number];
  readonly init: () => void;
  readonly __wbindgen_free: (a: number, b: number, c: number) => void;
  readonly __wbindgen_malloc: (a: number, b: number) => number;
  readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
  readonly __wbindgen_externrefs: WebAssembly.Table;
  readonly __externref_table_dealloc: (a: number) => void;
  readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
* Instantiates the given `module`, which can either be bytes or
* a precompiled `WebAssembly.Module`.
*
* @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
*
* @returns {InitOutput}
*/
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
* If `module_or_path` is {RequestInfo} or {URL}, makes a request and
* for everything else, calls `WebAssembly.instantiate` directly.
*
* @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
*
* @returns {Promise<InitOutput>}
*/
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
