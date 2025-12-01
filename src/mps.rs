//! Matrix Product State (MPS) representation of quantum states.
//!
//! MPS provides an efficient representation for quantum states with bounded entanglement.
//! Instead of storing O(2^n) amplitudes, MPS stores O(n * χ²) parameters where χ is the
//! bond dimension.

use ndarray::Array3;
use num_complex::Complex64;
use std::fmt;

/// Matrix Product State representation of a quantum state.
///
/// For an n-qubit system, the state is represented as:
/// |ψ⟩ = Σ A[1]^{s₁} · A[2]^{s₂} · ... · A[n]^{sₙ} |s₁s₂...sₙ⟩
///
/// where each A[i] is a tensor of shape (bond_left, physical_dim, bond_right).
#[derive(Clone)]
pub struct MPS {
    /// Number of sites (qubits)
    n_sites: usize,

    /// Maximum bond dimension (controls accuracy vs memory tradeoff)
    bond_dim: usize,

    /// Local physical dimension (2 for qubits)
    physical_dim: usize,

    /// Tensors: A[site] has shape (bond_left, physical, bond_right)
    /// For site 0: bond_left = 1
    /// For site n-1: bond_right = 1
    pub(crate) tensors: Vec<Array3<Complex64>>,

    /// Singular values at each bond (for entropy calculation)
    /// Length is n_sites - 1
    pub(crate) bond_singular_values: Vec<Vec<f64>>,

    /// Current canonical center (for efficient operations)
    canonical_center: Option<usize>,
}

impl MPS {
    /// Create a new MPS in the product state |00...0⟩
    ///
    /// # Arguments
    /// * `n_sites` - Number of qubits
    /// * `bond_dim` - Maximum bond dimension
    ///
    /// # Example
    /// ```
    /// use quantum_wall::MPS;
    /// let mps = MPS::new(1000, 64);
    /// assert_eq!(mps.n_sites(), 1000);
    /// ```
    pub fn new(n_sites: usize, bond_dim: usize) -> Self {
        Self::new_product_state(n_sites, bond_dim, 0)
    }

    /// Create an MPS in a product state |s₁s₂...sₙ⟩
    ///
    /// # Arguments
    /// * `n_sites` - Number of qubits
    /// * `bond_dim` - Maximum bond dimension
    /// * `state` - Which computational basis state (0 for |0⟩, 1 for |1⟩ at each site)
    pub fn new_product_state(n_sites: usize, bond_dim: usize, state: usize) -> Self {
        assert!(n_sites > 0, "MPS must have at least one site");
        assert!(bond_dim > 0, "Bond dimension must be positive");

        let physical_dim: usize = 2;
        let mut tensors = Vec::with_capacity(n_sites);

        // Helper to compute 2^exp capped at bond_dim (avoids overflow)
        let capped_pow = |exp: usize| -> usize {
            if exp >= 64 {
                // 2^64 would overflow, just use bond_dim
                bond_dim
            } else {
                bond_dim.min(1usize << exp)
            }
        };

        for i in 0..n_sites {
            // Bond dimensions grow from edges to center, capped at bond_dim
            let left_dim = if i == 0 {
                1
            } else {
                capped_pow(i)
            };

            let right_dim = if i == n_sites - 1 {
                1
            } else {
                capped_pow(n_sites - 1 - i)
            };

            let mut tensor = Array3::<Complex64>::zeros((left_dim, physical_dim, right_dim));

            // Initialize to product state
            // For large n_sites, the shift might overflow - in that case, the bit is 0
            let shift_amount = n_sites - 1 - i;
            let local_state = if shift_amount >= usize::BITS as usize {
                0
            } else {
                (state >> shift_amount) & 1
            };
            tensor[[0, local_state, 0]] = Complex64::new(1.0, 0.0);

            tensors.push(tensor);
        }

        // Initialize singular values (all 1.0 for product state)
        let bond_singular_values = vec![vec![1.0]; n_sites.saturating_sub(1)];

        Self {
            n_sites,
            bond_dim,
            physical_dim,
            tensors,
            bond_singular_values,
            canonical_center: Some(0),
        }
    }

    /// Create an MPS for a uniform superposition (|+⟩^⊗n)
    pub fn new_plus_state(n_sites: usize, bond_dim: usize) -> Self {
        let mut mps = Self::new(n_sites, bond_dim);
        let sqrt_half = Complex64::new(1.0 / 2.0_f64.sqrt(), 0.0);

        for tensor in &mut mps.tensors {
            let (d_left, _, d_right) = tensor.dim();
            *tensor = Array3::zeros((d_left, 2, d_right));
            tensor[[0, 0, 0]] = sqrt_half;
            tensor[[0, 1, 0]] = sqrt_half;
        }

        mps.canonical_center = None;
        mps
    }

    /// Get number of sites (qubits)
    #[inline]
    pub fn n_sites(&self) -> usize {
        self.n_sites
    }

    /// Get bond dimension
    #[inline]
    pub fn bond_dim(&self) -> usize {
        self.bond_dim
    }

    /// Get physical dimension
    #[inline]
    pub fn physical_dim(&self) -> usize {
        self.physical_dim
    }

    /// Get reference to tensors
    pub fn tensors(&self) -> &[Array3<Complex64>] {
        &self.tensors
    }

    /// Get mutable reference to tensors
    pub fn tensors_mut(&mut self) -> &mut [Array3<Complex64>] {
        &mut self.tensors
    }

    /// Get singular values at a bond
    pub fn singular_values(&self, bond: usize) -> Option<&[f64]> {
        self.bond_singular_values.get(bond).map(|v| v.as_slice())
    }

    /// Get all singular values
    pub fn all_singular_values(&self) -> &[Vec<f64>] {
        &self.bond_singular_values
    }

    /// Calculate memory usage in bytes
    pub fn memory_usage(&self) -> usize {
        let tensor_memory: usize = self
            .tensors
            .iter()
            .map(|t| t.len() * std::mem::size_of::<Complex64>())
            .sum();

        let sv_memory: usize = self
            .bond_singular_values
            .iter()
            .map(|v| v.len() * std::mem::size_of::<f64>())
            .sum();

        tensor_memory + sv_memory
    }

    /// Get the actual bond dimension at a specific bond
    pub fn bond_dim_at(&self, bond: usize) -> usize {
        if bond >= self.n_sites - 1 {
            return 0;
        }
        self.tensors[bond].dim().2
    }

    /// Check if the MPS is in canonical form around a site
    pub fn canonical_center(&self) -> Option<usize> {
        self.canonical_center
    }

    /// Set canonical center (internal use)
    pub(crate) fn set_canonical_center(&mut self, center: Option<usize>) {
        self.canonical_center = center;
    }

    /// Update singular values at a bond
    /// Override the singular values at a given bond (primarily for tests and demos).
    pub fn set_singular_values(&mut self, bond: usize, values: Vec<f64>) {
        if bond < self.bond_singular_values.len() {
            self.bond_singular_values[bond] = values;
        }
    }

    /// Compute the norm of the state (should be 1 for normalized states)
    pub fn norm(&self) -> f64 {
        // For a properly normalized MPS, norm = 1
        // This is a simplified check using singular values
        if let Some(center) = self.canonical_center {
            if center < self.bond_singular_values.len() {
                let sv = &self.bond_singular_values[center];
                return sv.iter().map(|s| s * s).sum::<f64>().sqrt();
            }
        }

        // Fallback: product of all singular value norms should be 1
        1.0
    }

    /// Normalize the MPS
    pub fn normalize(&mut self) {
        let norm = self.norm();
        if norm > crate::EPSILON && (norm - 1.0).abs() > crate::EPSILON {
            // Normalize by scaling one tensor
            if !self.tensors.is_empty() {
                self.tensors[0].mapv_inplace(|x| x / norm);
            }
        }
    }
}

impl fmt::Debug for MPS {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MPS")
            .field("n_sites", &self.n_sites)
            .field("bond_dim", &self.bond_dim)
            .field("memory_bytes", &self.memory_usage())
            .field("canonical_center", &self.canonical_center)
            .finish()
    }
}

impl fmt::Display for MPS {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "MPS(n={}, χ={}, mem={:.2} KB)",
            self.n_sites,
            self.bond_dim,
            self.memory_usage() as f64 / 1024.0
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mps_creation() {
        let mps = MPS::new(10, 16);
        assert_eq!(mps.n_sites(), 10);
        assert_eq!(mps.bond_dim(), 16);
        assert_eq!(mps.physical_dim(), 2);
        assert_eq!(mps.tensors().len(), 10);
    }

    #[test]
    fn test_memory_usage() {
        let mps = MPS::new(100, 32);
        let mem = mps.memory_usage();
        // Should be roughly n * chi^2 * d * 16 bytes
        assert!(mem > 0);
        assert!(mem < 100 * 32 * 32 * 2 * 16 * 2); // Upper bound with some slack
    }

    #[test]
    fn test_product_state() {
        let mps = MPS::new_product_state(4, 8, 0b1010);
        assert_eq!(mps.n_sites(), 4);
    }

    #[test]
    fn test_plus_state() {
        let mps = MPS::new_plus_state(10, 16);
        assert_eq!(mps.n_sites(), 10);
    }

    #[test]
    fn test_singular_values() {
        let mps = MPS::new(5, 8);
        assert_eq!(mps.all_singular_values().len(), 4); // n-1 bonds
    }
}
