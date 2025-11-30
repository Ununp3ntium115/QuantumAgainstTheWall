let wasm;

function _assertClass(instance, klass) {
    if (!(instance instanceof klass)) {
        throw new Error(`expected instance of ${klass.name}`);
    }
}

function getArrayF64FromWasm0(ptr, len) {
    ptr = ptr >>> 0;
    return getFloat64ArrayMemory0().subarray(ptr / 8, ptr / 8 + len);
}

function getArrayU8FromWasm0(ptr, len) {
    ptr = ptr >>> 0;
    return getUint8ArrayMemory0().subarray(ptr / 1, ptr / 1 + len);
}

let cachedBigUint64ArrayMemory0 = null;
function getBigUint64ArrayMemory0() {
    if (cachedBigUint64ArrayMemory0 === null || cachedBigUint64ArrayMemory0.byteLength === 0) {
        cachedBigUint64ArrayMemory0 = new BigUint64Array(wasm.memory.buffer);
    }
    return cachedBigUint64ArrayMemory0;
}

let cachedDataViewMemory0 = null;
function getDataViewMemory0() {
    if (cachedDataViewMemory0 === null || cachedDataViewMemory0.buffer.detached === true || (cachedDataViewMemory0.buffer.detached === undefined && cachedDataViewMemory0.buffer !== wasm.memory.buffer)) {
        cachedDataViewMemory0 = new DataView(wasm.memory.buffer);
    }
    return cachedDataViewMemory0;
}

let cachedFloat64ArrayMemory0 = null;
function getFloat64ArrayMemory0() {
    if (cachedFloat64ArrayMemory0 === null || cachedFloat64ArrayMemory0.byteLength === 0) {
        cachedFloat64ArrayMemory0 = new Float64Array(wasm.memory.buffer);
    }
    return cachedFloat64ArrayMemory0;
}

function getStringFromWasm0(ptr, len) {
    ptr = ptr >>> 0;
    return decodeText(ptr, len);
}

let cachedUint8ArrayMemory0 = null;
function getUint8ArrayMemory0() {
    if (cachedUint8ArrayMemory0 === null || cachedUint8ArrayMemory0.byteLength === 0) {
        cachedUint8ArrayMemory0 = new Uint8Array(wasm.memory.buffer);
    }
    return cachedUint8ArrayMemory0;
}

function passArray64ToWasm0(arg, malloc) {
    const ptr = malloc(arg.length * 8, 8) >>> 0;
    getBigUint64ArrayMemory0().set(arg, ptr / 8);
    WASM_VECTOR_LEN = arg.length;
    return ptr;
}

function passArray8ToWasm0(arg, malloc) {
    const ptr = malloc(arg.length * 1, 1) >>> 0;
    getUint8ArrayMemory0().set(arg, ptr / 1);
    WASM_VECTOR_LEN = arg.length;
    return ptr;
}

function passStringToWasm0(arg, malloc, realloc) {
    if (realloc === undefined) {
        const buf = cachedTextEncoder.encode(arg);
        const ptr = malloc(buf.length, 1) >>> 0;
        getUint8ArrayMemory0().subarray(ptr, ptr + buf.length).set(buf);
        WASM_VECTOR_LEN = buf.length;
        return ptr;
    }

    let len = arg.length;
    let ptr = malloc(len, 1) >>> 0;

    const mem = getUint8ArrayMemory0();

    let offset = 0;

    for (; offset < len; offset++) {
        const code = arg.charCodeAt(offset);
        if (code > 0x7F) break;
        mem[ptr + offset] = code;
    }
    if (offset !== len) {
        if (offset !== 0) {
            arg = arg.slice(offset);
        }
        ptr = realloc(ptr, len, len = offset + arg.length * 3, 1) >>> 0;
        const view = getUint8ArrayMemory0().subarray(ptr + offset, ptr + len);
        const ret = cachedTextEncoder.encodeInto(arg, view);

        offset += ret.written;
        ptr = realloc(ptr, len, offset, 1) >>> 0;
    }

    WASM_VECTOR_LEN = offset;
    return ptr;
}

function takeFromExternrefTable0(idx) {
    const value = wasm.__wbindgen_externrefs.get(idx);
    wasm.__externref_table_dealloc(idx);
    return value;
}

let cachedTextDecoder = new TextDecoder('utf-8', { ignoreBOM: true, fatal: true });
cachedTextDecoder.decode();
const MAX_SAFARI_DECODE_BYTES = 2146435072;
let numBytesDecoded = 0;
function decodeText(ptr, len) {
    numBytesDecoded += len;
    if (numBytesDecoded >= MAX_SAFARI_DECODE_BYTES) {
        cachedTextDecoder = new TextDecoder('utf-8', { ignoreBOM: true, fatal: true });
        cachedTextDecoder.decode();
        numBytesDecoded = len;
    }
    return cachedTextDecoder.decode(getUint8ArrayMemory0().subarray(ptr, ptr + len));
}

const cachedTextEncoder = new TextEncoder();

if (!('encodeInto' in cachedTextEncoder)) {
    cachedTextEncoder.encodeInto = function (arg, view) {
        const buf = cachedTextEncoder.encode(arg);
        view.set(buf);
        return {
            read: arg.length,
            written: buf.length
        };
    }
}

let WASM_VECTOR_LEN = 0;

const CryptoRngFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_cryptorng_free(ptr >>> 0, 1));

const EncryptedPayloadFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_encryptedpayload_free(ptr >>> 0, 1));

const FortressFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_fortress_free(ptr >>> 0, 1));

const QuantumStateFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_quantumstate_free(ptr >>> 0, 1));

const SymmetricCryptoFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_symmetriccrypto_free(ptr >>> 0, 1));

/**
 * A quantum-seeded cryptographically secure RNG.
 */
export class CryptoRng {
    static __wrap(ptr) {
        ptr = ptr >>> 0;
        const obj = Object.create(CryptoRng.prototype);
        obj.__wbg_ptr = ptr;
        CryptoRngFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        CryptoRngFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_cryptorng_free(ptr, 0);
    }
    /**
     * Get the entropy bits used to seed this RNG.
     * @returns {number}
     */
    get entropyBits() {
        const ret = wasm.cryptorng_entropyBits(this.__wbg_ptr);
        return ret;
    }
    /**
     * Generate random bytes.
     * @param {number} len
     * @returns {Uint8Array}
     */
    randomBytes(len) {
        const ret = wasm.cryptorng_randomBytes(this.__wbg_ptr, len);
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
    /**
     * Create a new RNG seeded from a quantum state.
     *
     * The entropy from the MPS entanglement structure is used to seed
     * a ChaCha20-based CSPRNG.
     * @param {QuantumState} state
     * @returns {CryptoRng}
     */
    static fromQuantumState(state) {
        _assertClass(state, QuantumState);
        const ret = wasm.cryptorng_fromQuantumState(state.__wbg_ptr);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return CryptoRng.__wrap(ret[0]);
    }
    /**
     * Create a new RNG from a 32-byte seed.
     * @param {Uint8Array} seed
     * @returns {CryptoRng}
     */
    static fromSeed(seed) {
        const ptr0 = passArray8ToWasm0(seed, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.cryptorng_fromSeed(ptr0, len0);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return CryptoRng.__wrap(ret[0]);
    }
}
if (Symbol.dispose) CryptoRng.prototype[Symbol.dispose] = CryptoRng.prototype.free;

/**
 * Encrypted data container for WASM.
 */
export class EncryptedPayload {
    static __wrap(ptr) {
        ptr = ptr >>> 0;
        const obj = Object.create(EncryptedPayload.prototype);
        obj.__wbg_ptr = ptr;
        EncryptedPayloadFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        EncryptedPayloadFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_encryptedpayload_free(ptr, 0);
    }
    /**
     * Get the ciphertext bytes.
     * @returns {Uint8Array}
     */
    get ciphertext() {
        const ret = wasm.encryptedpayload_ciphertext(this.__wbg_ptr);
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
    /**
     * Deserialize from bytes.
     * @param {Uint8Array} bytes
     * @returns {EncryptedPayload}
     */
    static fromBytes(bytes) {
        const ptr0 = passArray8ToWasm0(bytes, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.encryptedpayload_fromBytes(ptr0, len0);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return EncryptedPayload.__wrap(ret[0]);
    }
    /**
     * Get the authentication tag bytes.
     * @returns {Uint8Array}
     */
    get tag() {
        const ret = wasm.encryptedpayload_tag(this.__wbg_ptr);
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
    /**
     * Get the nonce bytes.
     * @returns {Uint8Array}
     */
    get nonce() {
        const ret = wasm.encryptedpayload_nonce(this.__wbg_ptr);
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
    /**
     * Serialize to bytes for storage/transmission.
     * @returns {Uint8Array}
     */
    toBytes() {
        const ret = wasm.encryptedpayload_toBytes(this.__wbg_ptr);
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
    /**
     * Get the algorithm name.
     * @returns {string}
     */
    get algorithm() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.encryptedpayload_algorithm(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
}
if (Symbol.dispose) EncryptedPayload.prototype[Symbol.dispose] = EncryptedPayload.prototype.free;

/**
 * Quantum Fortress - maximum cryptographic hardening
 */
export class Fortress {
    static __wrap(ptr) {
        ptr = ptr >>> 0;
        const obj = Object.create(Fortress.prototype);
        obj.__wbg_ptr = ptr;
        FortressFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        FortressFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_fortress_free(ptr, 0);
    }
    /**
     * Hash a password using the Fortress pipeline
     * Returns hex-encoded hash
     * @param {string} password
     * @param {string} salt
     * @returns {string}
     */
    hashPassword(password, salt) {
        let deferred4_0;
        let deferred4_1;
        try {
            const ptr0 = passStringToWasm0(password, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len0 = WASM_VECTOR_LEN;
            const ptr1 = passStringToWasm0(salt, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len1 = WASM_VECTOR_LEN;
            const ret = wasm.fortress_hashPassword(this.__wbg_ptr, ptr0, len0, ptr1, len1);
            var ptr3 = ret[0];
            var len3 = ret[1];
            if (ret[3]) {
                ptr3 = 0; len3 = 0;
                throw takeFromExternrefTable0(ret[2]);
            }
            deferred4_0 = ptr3;
            deferred4_1 = len3;
            return getStringFromWasm0(ptr3, len3);
        } finally {
            wasm.__wbindgen_free(deferred4_0, deferred4_1, 1);
        }
    }
    /**
     * Get estimated time in seconds
     * @returns {number}
     */
    get estimatedTime() {
        const ret = wasm.fortress_estimatedTime(this.__wbg_ptr);
        return ret;
    }
    /**
     * Get memory required in bytes
     * @returns {number}
     */
    get memoryRequired() {
        const ret = wasm.fortress_memoryRequired(this.__wbg_ptr);
        return ret >>> 0;
    }
    /**
     * Verify a password against a hash
     * @param {string} password
     * @param {string} salt
     * @param {string} expected_hash
     * @returns {boolean}
     */
    verifyPassword(password, salt, expected_hash) {
        const ptr0 = passStringToWasm0(password, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(salt, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(expected_hash, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ret = wasm.fortress_verifyPassword(this.__wbg_ptr, ptr0, len0, ptr1, len1, ptr2, len2);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return ret[0] !== 0;
    }
    /**
     * Create a new Fortress with interactive settings (fast)
     */
    constructor() {
        const ret = wasm.fortress_new();
        this.__wbg_ptr = ret >>> 0;
        FortressFinalization.register(this, this.__wbg_ptr, this);
        return this;
    }
    /**
     * Create with maximum quantum resistance
     * @returns {Fortress}
     */
    static quantum() {
        const ret = wasm.fortress_quantum();
        return Fortress.__wrap(ret);
    }
    /**
     * Create with standard security
     * @returns {Fortress}
     */
    static standard() {
        const ret = wasm.fortress_standard();
        return Fortress.__wrap(ret);
    }
}
if (Symbol.dispose) Fortress.prototype[Symbol.dispose] = Fortress.prototype.free;

/**
 * A quantum state represented as a Matrix Product State.
 *
 * This is the main interface for working with quantum states from JavaScript.
 */
export class QuantumState {
    static __wrap(ptr) {
        ptr = ptr >>> 0;
        const obj = Object.create(QuantumState.prototype);
        obj.__wbg_ptr = ptr;
        QuantumStateFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        QuantumStateFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_quantumstate_free(ptr, 0);
    }
    /**
     * Compute maximum entropy at any bond
     * @returns {number}
     */
    maxEntropy() {
        const ret = wasm.quantumstate_maxEntropy(this.__wbg_ptr);
        return ret;
    }
    /**
     * Apply Hadamard gates to all qubits
     */
    hadamardAll() {
        wasm.quantumstate_hadamardAll(this.__wbg_ptr);
    }
    /**
     * Get memory usage in bytes
     * @returns {number}
     */
    get memoryBytes() {
        const ret = wasm.quantumstate_memoryBytes(this.__wbg_ptr);
        return ret >>> 0;
    }
    /**
     * Get memory usage in a human-readable format
     * @returns {string}
     */
    get memoryString() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.quantumstate_memoryString(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * Compute total entanglement entropy (sum over all bonds)
     * @returns {number}
     */
    totalEntropy() {
        const ret = wasm.quantumstate_totalEntropy(this.__wbg_ptr);
        return ret;
    }
    /**
     * Create a state initialized to |++...+⟩ (uniform superposition)
     * @param {number} n_qubits
     * @param {number} bond_dim
     * @returns {QuantumState}
     */
    static newPlusState(n_qubits, bond_dim) {
        const ret = wasm.quantumstate_newPlusState(n_qubits, bond_dim);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return QuantumState.__wrap(ret[0]);
    }
    /**
     * Compute average entanglement entropy per bond
     * @returns {number}
     */
    averageEntropy() {
        const ret = wasm.quantumstate_averageEntropy(this.__wbg_ptr);
        return ret;
    }
    /**
     * Compute entanglement entropy at a specific bond
     *
     * # Arguments
     * * `bond` - Bond index (0 to n_qubits - 2)
     *
     * # Returns
     * Entropy in bits
     * @param {number} bond
     * @returns {number}
     */
    entropyAtBond(bond) {
        const ret = wasm.quantumstate_entropyAtBond(this.__wbg_ptr, bond);
        return ret;
    }
    /**
     * Get the entropy profile as an array
     * @returns {Float64Array}
     */
    entropyProfile() {
        const ret = wasm.quantumstate_entropyProfile(this.__wbg_ptr);
        var v1 = getArrayF64FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 8, 8);
        return v1;
    }
    /**
     * Compute augmented entropy: S + π n²
     * @returns {number}
     */
    augmentedEntropy() {
        const ret = wasm.quantumstate_augmentedEntropy(this.__wbg_ptr);
        return ret;
    }
    /**
     * Get the maximum possible entropy for this bond dimension
     * @returns {number}
     */
    maxEntropyBound() {
        const ret = wasm.quantumstate_maxEntropyBound(this.__wbg_ptr);
        return ret;
    }
    /**
     * Apply Rx rotation gate
     * @param {number} site
     * @param {number} theta
     */
    rx(site, theta) {
        const ret = wasm.quantumstate_rx(this.__wbg_ptr, site, theta);
        if (ret[1]) {
            throw takeFromExternrefTable0(ret[0]);
        }
    }
    /**
     * Apply Ry rotation gate
     * @param {number} site
     * @param {number} theta
     */
    ry(site, theta) {
        const ret = wasm.quantumstate_ry(this.__wbg_ptr, site, theta);
        if (ret[1]) {
            throw takeFromExternrefTable0(ret[0]);
        }
    }
    /**
     * Apply Rz rotation gate
     * @param {number} site
     * @param {number} theta
     */
    rz(site, theta) {
        const ret = wasm.quantumstate_rz(this.__wbg_ptr, site, theta);
        if (ret[1]) {
            throw takeFromExternrefTable0(ret[0]);
        }
    }
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
     * @param {number} n_qubits
     * @param {number} bond_dim
     */
    constructor(n_qubits, bond_dim) {
        const ret = wasm.quantumstate_new(n_qubits, bond_dim);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        this.__wbg_ptr = ret[0] >>> 0;
        QuantumStateFinalization.register(this, this.__wbg_ptr, this);
        return this;
    }
    /**
     * Apply an S (phase) gate to a qubit
     * @param {number} site
     */
    sGate(site) {
        const ret = wasm.quantumstate_sGate(this.__wbg_ptr, site);
        if (ret[1]) {
            throw takeFromExternrefTable0(ret[0]);
        }
    }
    /**
     * Apply a T gate to a qubit
     * @param {number} site
     */
    tGate(site) {
        const ret = wasm.quantumstate_tGate(this.__wbg_ptr, site);
        if (ret[1]) {
            throw takeFromExternrefTable0(ret[0]);
        }
    }
    /**
     * Apply a Pauli-X (NOT) gate to a qubit
     * @param {number} site
     */
    pauliX(site) {
        const ret = wasm.quantumstate_pauliX(this.__wbg_ptr, site);
        if (ret[1]) {
            throw takeFromExternrefTable0(ret[0]);
        }
    }
    /**
     * Apply a Pauli-Y gate to a qubit
     * @param {number} site
     */
    pauliY(site) {
        const ret = wasm.quantumstate_pauliY(this.__wbg_ptr, site);
        if (ret[1]) {
            throw takeFromExternrefTable0(ret[0]);
        }
    }
    /**
     * Apply a Pauli-Z gate to a qubit
     * @param {number} site
     */
    pauliZ(site) {
        const ret = wasm.quantumstate_pauliZ(this.__wbg_ptr, site);
        if (ret[1]) {
            throw takeFromExternrefTable0(ret[0]);
        }
    }
    /**
     * Get the bond dimension
     * @returns {number}
     */
    get bondDim() {
        const ret = wasm.quantumstate_bondDim(this.__wbg_ptr);
        return ret >>> 0;
    }
    /**
     * Apply a Hadamard gate to a qubit
     * @param {number} site
     */
    hadamard(site) {
        const ret = wasm.quantumstate_hadamard(this.__wbg_ptr, site);
        if (ret[1]) {
            throw takeFromExternrefTable0(ret[0]);
        }
    }
    /**
     * Get the number of qubits
     * @returns {number}
     */
    get nQubits() {
        const ret = wasm.quantumstate_nQubits(this.__wbg_ptr);
        return ret >>> 0;
    }
    /**
     * Get a string representation of the state
     * @returns {string}
     */
    toString() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.quantumstate_toString(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
}
if (Symbol.dispose) QuantumState.prototype[Symbol.dispose] = QuantumState.prototype.free;

/**
 * Symmetric encryption interface for WASM.
 */
export class SymmetricCrypto {
    static __wrap(ptr) {
        ptr = ptr >>> 0;
        const obj = Object.create(SymmetricCrypto.prototype);
        obj.__wbg_ptr = ptr;
        SymmetricCryptoFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        SymmetricCryptoFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_symmetriccrypto_free(ptr, 0);
    }
    /**
     * Encrypt data using AES-256-GCM.
     * @param {Uint8Array} plaintext
     * @returns {EncryptedPayload}
     */
    encryptAesGcm(plaintext) {
        const ptr0 = passArray8ToWasm0(plaintext, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.symmetriccrypto_encryptAesGcm(this.__wbg_ptr, ptr0, len0);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return EncryptedPayload.__wrap(ret[0]);
    }
    /**
     * Decrypt data with additional authenticated data (AAD).
     * @param {EncryptedPayload} encrypted
     * @param {Uint8Array} aad
     * @returns {Uint8Array}
     */
    decryptWithAad(encrypted, aad) {
        _assertClass(encrypted, EncryptedPayload);
        const ptr0 = passArray8ToWasm0(aad, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.symmetriccrypto_decryptWithAad(this.__wbg_ptr, encrypted.__wbg_ptr, ptr0, len0);
        if (ret[3]) {
            throw takeFromExternrefTable0(ret[2]);
        }
        var v2 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v2;
    }
    /**
     * Encrypt data using ChaCha20-Poly1305.
     * @param {Uint8Array} plaintext
     * @returns {EncryptedPayload}
     */
    encryptChaCha20(plaintext) {
        const ptr0 = passArray8ToWasm0(plaintext, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.symmetriccrypto_encryptChaCha20(this.__wbg_ptr, ptr0, len0);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return EncryptedPayload.__wrap(ret[0]);
    }
    /**
     * Encrypt data with additional authenticated data (AAD).
     * @param {Uint8Array} plaintext
     * @param {Uint8Array} aad
     * @param {string} algorithm
     * @returns {EncryptedPayload}
     */
    encryptWithAad(plaintext, aad, algorithm) {
        const ptr0 = passArray8ToWasm0(plaintext, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passArray8ToWasm0(aad, wasm.__wbindgen_malloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(algorithm, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ret = wasm.symmetriccrypto_encryptWithAad(this.__wbg_ptr, ptr0, len0, ptr1, len1, ptr2, len2);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return EncryptedPayload.__wrap(ret[0]);
    }
    /**
     * Create a new symmetric encryption context with a quantum-seeded key.
     * @param {QuantumState} state
     * @returns {SymmetricCrypto}
     */
    static fromQuantumState(state) {
        _assertClass(state, QuantumState);
        const ret = wasm.symmetriccrypto_fromQuantumState(state.__wbg_ptr);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return SymmetricCrypto.__wrap(ret[0]);
    }
    /**
     * Decrypt data.
     * @param {EncryptedPayload} encrypted
     * @returns {Uint8Array}
     */
    decrypt(encrypted) {
        _assertClass(encrypted, EncryptedPayload);
        const ret = wasm.symmetriccrypto_decrypt(this.__wbg_ptr, encrypted.__wbg_ptr);
        if (ret[3]) {
            throw takeFromExternrefTable0(ret[2]);
        }
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
    /**
     * Create a new symmetric encryption context from a 32-byte key.
     * @param {Uint8Array} key_bytes
     * @param {Uint8Array} seed
     * @returns {SymmetricCrypto}
     */
    static fromKey(key_bytes, seed) {
        const ptr0 = passArray8ToWasm0(key_bytes, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passArray8ToWasm0(seed, wasm.__wbindgen_malloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.symmetriccrypto_fromKey(ptr0, len0, ptr1, len1);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return SymmetricCrypto.__wrap(ret[0]);
    }
    /**
     * Get the encryption key bytes.
     *
     * WARNING: Handle with care - this exposes the raw key material.
     * @returns {Uint8Array}
     */
    keyBytes() {
        const ret = wasm.symmetriccrypto_keyBytes(this.__wbg_ptr);
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
}
if (Symbol.dispose) SymmetricCrypto.prototype[Symbol.dispose] = SymmetricCrypto.prototype.free;

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
 * @param {Uint8Array} input_key
 * @param {Uint8Array} salt
 * @param {Uint8Array} info
 * @returns {Uint8Array}
 */
export function deriveKey(input_key, salt, info) {
    const ptr0 = passArray8ToWasm0(input_key, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passArray8ToWasm0(salt, wasm.__wbindgen_malloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passArray8ToWasm0(info, wasm.__wbindgen_malloc);
    const len2 = WASM_VECTOR_LEN;
    const ret = wasm.deriveKey(ptr0, len0, ptr1, len1, ptr2, len2);
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    var v4 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v4;
}

/**
 * Calculate memory requirements for a given system size
 *
 * # Arguments
 * * `n_qubits` - Number of qubits
 * * `bond_dim` - Bond dimension
 *
 * # Returns
 * Approximate memory in bytes
 * @param {number} n_qubits
 * @param {number} bond_dim
 * @returns {number}
 */
export function estimateMemory(n_qubits, bond_dim) {
    const ret = wasm.estimateMemory(n_qubits, bond_dim);
    return ret >>> 0;
}

/**
 * Full fortress hash (Argon2 + Balloon + Time-lock)
 * @param {string} password
 * @param {string} salt
 * @returns {string}
 */
export function fortressHash(password, salt) {
    let deferred4_0;
    let deferred4_1;
    try {
        const ptr0 = passStringToWasm0(password, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(salt, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.fortressHash(ptr0, len0, ptr1, len1);
        var ptr3 = ret[0];
        var len3 = ret[1];
        if (ret[3]) {
            ptr3 = 0; len3 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred4_0 = ptr3;
        deferred4_1 = len3;
        return getStringFromWasm0(ptr3, len3);
    } finally {
        wasm.__wbindgen_free(deferred4_0, deferred4_1, 1);
    }
}

/**
 * Get the library version
 * @returns {string}
 */
export function getVersion() {
    let deferred1_0;
    let deferred1_1;
    try {
        const ret = wasm.getVersion();
        deferred1_0 = ret[0];
        deferred1_1 = ret[1];
        return getStringFromWasm0(ret[0], ret[1]);
    } finally {
        wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
    }
}

/**
 * Initialize panic hook for better error messages in WASM
 */
export function init() {
    wasm.init();
}

/**
 * Quick hash using Argon2id only (for testing)
 * @param {string} password
 * @param {string} salt
 * @returns {string}
 */
export function quickHash(password, salt) {
    let deferred4_0;
    let deferred4_1;
    try {
        const ptr0 = passStringToWasm0(password, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(salt, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.quickHash(ptr0, len0, ptr1, len1);
        var ptr3 = ret[0];
        var len3 = ret[1];
        if (ret[3]) {
            ptr3 = 0; len3 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred4_0 = ptr3;
        deferred4_1 = len3;
        return getStringFromWasm0(ptr3, len3);
    } finally {
        wasm.__wbindgen_free(deferred4_0, deferred4_1, 1);
    }
}

/**
 * Hash data with SHA-256.
 * @param {Uint8Array} data
 * @returns {Uint8Array}
 */
export function sha256(data) {
    const ptr0 = passArray8ToWasm0(data, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.sha256(ptr0, len0);
    var v2 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v2;
}

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
 * @param {BigUint64Array} counts
 * @returns {number}
 */
export function shannonEntropyFromCounts(counts) {
    const ptr0 = passArray64ToWasm0(counts, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.shannonEntropyFromCounts(ptr0, len0);
    return ret;
}

const EXPECTED_RESPONSE_TYPES = new Set(['basic', 'cors', 'default']);

async function __wbg_load(module, imports) {
    if (typeof Response === 'function' && module instanceof Response) {
        if (typeof WebAssembly.instantiateStreaming === 'function') {
            try {
                return await WebAssembly.instantiateStreaming(module, imports);
            } catch (e) {
                const validResponse = module.ok && EXPECTED_RESPONSE_TYPES.has(module.type);

                if (validResponse && module.headers.get('Content-Type') !== 'application/wasm') {
                    console.warn("`WebAssembly.instantiateStreaming` failed because your server does not serve Wasm with `application/wasm` MIME type. Falling back to `WebAssembly.instantiate` which is slower. Original error:\n", e);

                } else {
                    throw e;
                }
            }
        }

        const bytes = await module.arrayBuffer();
        return await WebAssembly.instantiate(bytes, imports);
    } else {
        const instance = await WebAssembly.instantiate(module, imports);

        if (instance instanceof WebAssembly.Instance) {
            return { instance, module };
        } else {
            return instance;
        }
    }
}

function __wbg_get_imports() {
    const imports = {};
    imports.wbg = {};
    imports.wbg.__wbg_Error_52673b7de5a0ca89 = function(arg0, arg1) {
        const ret = Error(getStringFromWasm0(arg0, arg1));
        return ret;
    };
    imports.wbg.__wbg___wbindgen_throw_dd24417ed36fc46e = function(arg0, arg1) {
        throw new Error(getStringFromWasm0(arg0, arg1));
    };
    imports.wbg.__wbg_error_7534b8e9a36f1ab4 = function(arg0, arg1) {
        let deferred0_0;
        let deferred0_1;
        try {
            deferred0_0 = arg0;
            deferred0_1 = arg1;
            console.error(getStringFromWasm0(arg0, arg1));
        } finally {
            wasm.__wbindgen_free(deferred0_0, deferred0_1, 1);
        }
    };
    imports.wbg.__wbg_new_8a6f238a6ece86ea = function() {
        const ret = new Error();
        return ret;
    };
    imports.wbg.__wbg_stack_0ed75d68575b0f3c = function(arg0, arg1) {
        const ret = arg1.stack;
        const ptr1 = passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
        getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
    };
    imports.wbg.__wbindgen_init_externref_table = function() {
        const table = wasm.__wbindgen_externrefs;
        const offset = table.grow(4);
        table.set(0, undefined);
        table.set(offset + 0, undefined);
        table.set(offset + 1, null);
        table.set(offset + 2, true);
        table.set(offset + 3, false);
    };

    return imports;
}

function __wbg_finalize_init(instance, module) {
    wasm = instance.exports;
    __wbg_init.__wbindgen_wasm_module = module;
    cachedBigUint64ArrayMemory0 = null;
    cachedDataViewMemory0 = null;
    cachedFloat64ArrayMemory0 = null;
    cachedUint8ArrayMemory0 = null;


    wasm.__wbindgen_start();
    return wasm;
}

function initSync(module) {
    if (wasm !== undefined) return wasm;


    if (typeof module !== 'undefined') {
        if (Object.getPrototypeOf(module) === Object.prototype) {
            ({module} = module)
        } else {
            console.warn('using deprecated parameters for `initSync()`; pass a single object instead')
        }
    }

    const imports = __wbg_get_imports();
    if (!(module instanceof WebAssembly.Module)) {
        module = new WebAssembly.Module(module);
    }
    const instance = new WebAssembly.Instance(module, imports);
    return __wbg_finalize_init(instance, module);
}

async function __wbg_init(module_or_path) {
    if (wasm !== undefined) return wasm;


    if (typeof module_or_path !== 'undefined') {
        if (Object.getPrototypeOf(module_or_path) === Object.prototype) {
            ({module_or_path} = module_or_path)
        } else {
            console.warn('using deprecated parameters for the initialization function; pass a single object instead')
        }
    }

    if (typeof module_or_path === 'undefined') {
        module_or_path = new URL('quantum_wall_bg.wasm', import.meta.url);
    }
    const imports = __wbg_get_imports();

    if (typeof module_or_path === 'string' || (typeof Request === 'function' && module_or_path instanceof Request) || (typeof URL === 'function' && module_or_path instanceof URL)) {
        module_or_path = fetch(module_or_path);
    }

    const { instance, module } = await __wbg_load(await module_or_path, imports);

    return __wbg_finalize_init(instance, module);
}

export { initSync };
export default __wbg_init;
