//! WebAssembly bindings for the quantum entropy library.
//!
//! This module provides JavaScript-friendly wrappers around the core
//! Rust functionality, enabling use from web browsers and Node.js.

use wasm_bindgen::prelude::*;

use crate::entropy;
use crate::gates::{apply_single_gate, standard_gates};
use crate::mps::MPS;

/// Initialize panic hook for better error messages in WASM
#[wasm_bindgen(start)]
pub fn init() {
    #[cfg(feature = "console_error_panic_hook")]
    console_error_panic_hook::set_once();
}

/// A quantum state represented as a Matrix Product State.
///
/// This is the main interface for working with quantum states from JavaScript.
#[wasm_bindgen]
pub struct QuantumState {
    mps: MPS,
}

#[wasm_bindgen]
impl QuantumState {
    /// Create a new quantum state initialized to |00...0⟩
    ///
    /// # Arguments
    /// * `n_qubits` - Number of qubits in the system
    /// * `bond_dim` - Bond dimension (controls accuracy vs memory)
    ///
    /// # Example (JavaScript)
    /// ```js
    /// const state = new QuantumState(1000, 64);
    /// ```
    #[wasm_bindgen(constructor)]
    pub fn new(n_qubits: usize, bond_dim: usize) -> Result<QuantumState, JsError> {
        if n_qubits == 0 {
            return Err(JsError::new("Number of qubits must be positive"));
        }
        if bond_dim == 0 {
            return Err(JsError::new("Bond dimension must be positive"));
        }

        Ok(QuantumState {
            mps: MPS::new(n_qubits, bond_dim),
        })
    }

    /// Create a state initialized to |++...+⟩ (uniform superposition)
    #[wasm_bindgen(js_name = newPlusState)]
    pub fn new_plus_state(n_qubits: usize, bond_dim: usize) -> Result<QuantumState, JsError> {
        if n_qubits == 0 {
            return Err(JsError::new("Number of qubits must be positive"));
        }
        if bond_dim == 0 {
            return Err(JsError::new("Bond dimension must be positive"));
        }

        Ok(QuantumState {
            mps: MPS::new_plus_state(n_qubits, bond_dim),
        })
    }

    /// Get the number of qubits
    #[wasm_bindgen(getter, js_name = nQubits)]
    pub fn n_qubits(&self) -> usize {
        self.mps.n_sites()
    }

    /// Get the bond dimension
    #[wasm_bindgen(getter, js_name = bondDim)]
    pub fn bond_dim(&self) -> usize {
        self.mps.bond_dim()
    }

    /// Get memory usage in bytes
    #[wasm_bindgen(getter, js_name = memoryBytes)]
    pub fn memory_bytes(&self) -> usize {
        self.mps.memory_usage()
    }

    /// Get memory usage in a human-readable format
    #[wasm_bindgen(getter, js_name = memoryString)]
    pub fn memory_string(&self) -> String {
        let bytes = self.mps.memory_usage();
        if bytes < 1024 {
            format!("{} B", bytes)
        } else if bytes < 1024 * 1024 {
            format!("{:.2} KB", bytes as f64 / 1024.0)
        } else if bytes < 1024 * 1024 * 1024 {
            format!("{:.2} MB", bytes as f64 / (1024.0 * 1024.0))
        } else {
            format!("{:.2} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
        }
    }

    /// Compute entanglement entropy at a specific bond
    ///
    /// # Arguments
    /// * `bond` - Bond index (0 to n_qubits - 2)
    ///
    /// # Returns
    /// Entropy in bits
    #[wasm_bindgen(js_name = entropyAtBond)]
    pub fn entropy_at_bond(&self, bond: usize) -> f64 {
        entropy::entanglement_entropy(&self.mps, bond)
    }

    /// Compute total entanglement entropy (sum over all bonds)
    #[wasm_bindgen(js_name = totalEntropy)]
    pub fn total_entropy(&self) -> f64 {
        entropy::total_entanglement_entropy(&self.mps)
    }

    /// Compute average entanglement entropy per bond
    #[wasm_bindgen(js_name = averageEntropy)]
    pub fn average_entropy(&self) -> f64 {
        entropy::average_entanglement_entropy(&self.mps)
    }

    /// Compute maximum entropy at any bond
    #[wasm_bindgen(js_name = maxEntropy)]
    pub fn max_entropy(&self) -> f64 {
        entropy::max_bond_entropy(&self.mps)
    }

    /// Compute augmented entropy: S + π n²
    #[wasm_bindgen(js_name = augmentedEntropy)]
    pub fn augmented_entropy(&self) -> f64 {
        entropy::augmented_entropy(&self.mps)
    }

    /// Get the entropy profile as an array
    #[wasm_bindgen(js_name = entropyProfile)]
    pub fn entropy_profile(&self) -> Vec<f64> {
        entropy::entropy_profile(&self.mps)
    }

    /// Get the maximum possible entropy for this bond dimension
    #[wasm_bindgen(js_name = maxEntropyBound)]
    pub fn max_entropy_bound(&self) -> f64 {
        entropy::max_entropy_bound(self.mps.bond_dim(), self.mps.n_sites())
    }

    /// Apply a Hadamard gate to a qubit
    #[wasm_bindgen]
    pub fn hadamard(&mut self, site: usize) -> Result<(), JsError> {
        if site >= self.mps.n_sites() {
            return Err(JsError::new(&format!(
                "Site {} out of bounds (max {})",
                site,
                self.mps.n_sites() - 1
            )));
        }
        apply_single_gate(&mut self.mps, site, &standard_gates::hadamard());
        Ok(())
    }

    /// Apply a Pauli-X (NOT) gate to a qubit
    #[wasm_bindgen(js_name = pauliX)]
    pub fn pauli_x(&mut self, site: usize) -> Result<(), JsError> {
        if site >= self.mps.n_sites() {
            return Err(JsError::new(&format!(
                "Site {} out of bounds (max {})",
                site,
                self.mps.n_sites() - 1
            )));
        }
        apply_single_gate(&mut self.mps, site, &standard_gates::pauli_x());
        Ok(())
    }

    /// Apply a Pauli-Y gate to a qubit
    #[wasm_bindgen(js_name = pauliY)]
    pub fn pauli_y(&mut self, site: usize) -> Result<(), JsError> {
        if site >= self.mps.n_sites() {
            return Err(JsError::new(&format!(
                "Site {} out of bounds (max {})",
                site,
                self.mps.n_sites() - 1
            )));
        }
        apply_single_gate(&mut self.mps, site, &standard_gates::pauli_y());
        Ok(())
    }

    /// Apply a Pauli-Z gate to a qubit
    #[wasm_bindgen(js_name = pauliZ)]
    pub fn pauli_z(&mut self, site: usize) -> Result<(), JsError> {
        if site >= self.mps.n_sites() {
            return Err(JsError::new(&format!(
                "Site {} out of bounds (max {})",
                site,
                self.mps.n_sites() - 1
            )));
        }
        apply_single_gate(&mut self.mps, site, &standard_gates::pauli_z());
        Ok(())
    }

    /// Apply an S (phase) gate to a qubit
    #[wasm_bindgen(js_name = sGate)]
    pub fn s_gate(&mut self, site: usize) -> Result<(), JsError> {
        if site >= self.mps.n_sites() {
            return Err(JsError::new(&format!(
                "Site {} out of bounds (max {})",
                site,
                self.mps.n_sites() - 1
            )));
        }
        apply_single_gate(&mut self.mps, site, &standard_gates::s_gate());
        Ok(())
    }

    /// Apply a T gate to a qubit
    #[wasm_bindgen(js_name = tGate)]
    pub fn t_gate(&mut self, site: usize) -> Result<(), JsError> {
        if site >= self.mps.n_sites() {
            return Err(JsError::new(&format!(
                "Site {} out of bounds (max {})",
                site,
                self.mps.n_sites() - 1
            )));
        }
        apply_single_gate(&mut self.mps, site, &standard_gates::t_gate());
        Ok(())
    }

    /// Apply Rx rotation gate
    #[wasm_bindgen]
    pub fn rx(&mut self, site: usize, theta: f64) -> Result<(), JsError> {
        if site >= self.mps.n_sites() {
            return Err(JsError::new(&format!(
                "Site {} out of bounds (max {})",
                site,
                self.mps.n_sites() - 1
            )));
        }
        apply_single_gate(&mut self.mps, site, &standard_gates::rx(theta));
        Ok(())
    }

    /// Apply Ry rotation gate
    #[wasm_bindgen]
    pub fn ry(&mut self, site: usize, theta: f64) -> Result<(), JsError> {
        if site >= self.mps.n_sites() {
            return Err(JsError::new(&format!(
                "Site {} out of bounds (max {})",
                site,
                self.mps.n_sites() - 1
            )));
        }
        apply_single_gate(&mut self.mps, site, &standard_gates::ry(theta));
        Ok(())
    }

    /// Apply Rz rotation gate
    #[wasm_bindgen]
    pub fn rz(&mut self, site: usize, theta: f64) -> Result<(), JsError> {
        if site >= self.mps.n_sites() {
            return Err(JsError::new(&format!(
                "Site {} out of bounds (max {})",
                site,
                self.mps.n_sites() - 1
            )));
        }
        apply_single_gate(&mut self.mps, site, &standard_gates::rz(theta));
        Ok(())
    }

    /// Apply Hadamard gates to all qubits
    #[wasm_bindgen(js_name = hadamardAll)]
    pub fn hadamard_all(&mut self) {
        let h = standard_gates::hadamard();
        for site in 0..self.mps.n_sites() {
            apply_single_gate(&mut self.mps, site, &h);
        }
    }

    /// Get a string representation of the state
    #[wasm_bindgen(js_name = toString)]
    pub fn to_string(&self) -> String {
        format!(
            "QuantumState(n={}, χ={}, mem={})",
            self.mps.n_sites(),
            self.mps.bond_dim(),
            self.memory_string()
        )
    }
}

/// Compute entropy from a histogram of counts.
///
/// This is useful for classical entropy calculations.
///
/// # Arguments
/// * `counts` - Array of counts for each bin
///
/// # Returns
/// Shannon entropy in bits
#[wasm_bindgen(js_name = shannonEntropyFromCounts)]
pub fn shannon_entropy_from_counts(counts: &[u64]) -> f64 {
    let total: u64 = counts.iter().sum();
    if total == 0 {
        return 0.0;
    }

    let total_f64 = total as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / total_f64;
            -p * p.log2()
        })
        .sum()
}

/// Get the library version
#[wasm_bindgen(js_name = getVersion)]
pub fn get_version() -> String {
    crate::VERSION.to_string()
}

/// Calculate memory requirements for a given system size
///
/// # Arguments
/// * `n_qubits` - Number of qubits
/// * `bond_dim` - Bond dimension
///
/// # Returns
/// Approximate memory in bytes
#[wasm_bindgen(js_name = estimateMemory)]
pub fn estimate_memory(n_qubits: usize, bond_dim: usize) -> usize {
    // Each tensor is roughly bond_dim * 2 * bond_dim * 16 bytes
    // Plus some overhead for singular values
    let tensor_size = bond_dim * 2 * bond_dim * 16;
    let sv_size = bond_dim * 8;
    n_qubits * tensor_size + (n_qubits - 1) * sv_size
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_quantum_state_creation() {
        let state = QuantumState::new(100, 32).unwrap();
        assert_eq!(state.n_qubits(), 100);
        assert_eq!(state.bond_dim(), 32);
    }

    #[test]
    fn test_entropy_calculation() {
        let state = QuantumState::new(10, 16).unwrap();
        let entropy = state.total_entropy();
        // Product state should have ~0 entropy
        assert!(entropy.abs() < 1e-10);
    }

    #[test]
    fn test_gate_application() {
        let mut state = QuantumState::new(5, 8).unwrap();
        state.hadamard(0).unwrap();
        state.pauli_x(1).unwrap();
        // Should not panic
    }

    #[test]
    fn test_shannon_entropy() {
        // Uniform distribution over 4 bins: entropy = 2 bits
        let counts = vec![100, 100, 100, 100];
        let entropy = shannon_entropy_from_counts(&counts);
        assert!((entropy - 2.0).abs() < 1e-10);
    }
}
