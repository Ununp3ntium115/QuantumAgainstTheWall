//! Entropy calculations for Matrix Product States.
//!
//! This module provides functions to compute various entropy measures from MPS representations.
//! The key insight is that entanglement entropy can be computed directly from the singular
//! values at each bond, without needing to construct the full density matrix.

use crate::mps::MPS;
use crate::EPSILON;
use std::f64::consts::PI;

/// Compute von Neumann entropy from singular values.
///
/// For a bipartition of a pure state, the von Neumann entropy is:
/// S = -Σ λ² log₂(λ²)
///
/// where λ are the singular values (Schmidt coefficients).
///
/// # Arguments
/// * `singular_values` - The singular values at a bond
///
/// # Returns
/// The entropy in bits
///
/// # Example
/// ```
/// use quantum_wall::bond_entropy;
///
/// // Maximally entangled state of 2 qubits: λ = [1/√2, 1/√2]
/// let sv = vec![0.7071067811865476, 0.7071067811865476];
/// let entropy = bond_entropy(&sv);
/// assert!((entropy - 1.0).abs() < 1e-10); // 1 bit of entropy
/// ```
pub fn bond_entropy(singular_values: &[f64]) -> f64 {
    if singular_values.is_empty() {
        return 0.0;
    }

    // Compute normalization (sum of squares)
    let norm_sq: f64 = singular_values.iter().map(|&s| s * s).sum();

    if norm_sq < EPSILON {
        return 0.0;
    }

    // Compute entropy: S = -Σ p log₂(p) where p = λ²/norm_sq
    singular_values
        .iter()
        .map(|&s| {
            let p = (s * s) / norm_sq;
            if p > EPSILON {
                -p * p.log2()
            } else {
                0.0
            }
        })
        .sum()
}

/// Compute entanglement entropy for a bipartition at a specific bond.
///
/// This gives the von Neumann entropy S(ρ_A) where ρ_A is the reduced
/// density matrix of sites [0, bond].
///
/// # Arguments
/// * `mps` - The MPS state
/// * `bond_index` - The bond to compute entropy at (0 to n-2)
///
/// # Returns
/// The entanglement entropy in bits
pub fn entanglement_entropy(mps: &MPS, bond_index: usize) -> f64 {
    match mps.singular_values(bond_index) {
        Some(sv) => bond_entropy(sv),
        None => 0.0,
    }
}

/// Compute the total entanglement entropy (sum over all bonds).
///
/// This is useful as an overall measure of how much entanglement
/// is present in the state.
///
/// # Arguments
/// * `mps` - The MPS state
///
/// # Returns
/// Sum of entanglement entropies at all bonds
pub fn total_entanglement_entropy(mps: &MPS) -> f64 {
    mps.all_singular_values()
        .iter()
        .map(|sv| bond_entropy(sv))
        .sum()
}

/// Compute the average entanglement entropy per bond.
///
/// # Arguments
/// * `mps` - The MPS state
///
/// # Returns
/// Average entropy per bond in bits
pub fn average_entanglement_entropy(mps: &MPS) -> f64 {
    let n_bonds = mps.n_sites().saturating_sub(1);
    if n_bonds == 0 {
        return 0.0;
    }
    total_entanglement_entropy(mps) / n_bonds as f64
}

/// Compute the maximum entanglement entropy at any bond.
///
/// # Arguments
/// * `mps` - The MPS state
///
/// # Returns
/// Maximum entropy across all bonds
pub fn max_bond_entropy(mps: &MPS) -> f64 {
    mps.all_singular_values()
        .iter()
        .map(|sv| bond_entropy(sv))
        .fold(0.0, f64::max)
}

/// Compute the augmented entropy measure: S + π n²
///
/// This combines the quantum entanglement entropy with a polynomial
/// scaling term based on system size.
///
/// # Arguments
/// * `mps` - The MPS state
///
/// # Returns
/// The augmented entropy measure
pub fn augmented_entropy(mps: &MPS) -> f64 {
    let s = total_entanglement_entropy(mps);
    let n = mps.n_sites() as f64;
    s + PI * n * n
}

/// Compute the maximum possible entropy for a given bond dimension.
///
/// For an MPS with bond dimension χ, the maximum entropy per bond is log₂(χ).
///
/// # Arguments
/// * `bond_dim` - The bond dimension
/// * `n_sites` - Number of sites
///
/// # Returns
/// Maximum possible total entropy
pub fn max_entropy_bound(bond_dim: usize, n_sites: usize) -> f64 {
    if n_sites <= 1 || bond_dim == 0 {
        return 0.0;
    }
    let n_bonds = n_sites - 1;
    n_bonds as f64 * (bond_dim as f64).log2()
}

/// Compute the entanglement entropy profile across all bonds.
///
/// Returns a vector of entropies, one for each bond.
///
/// # Arguments
/// * `mps` - The MPS state
///
/// # Returns
/// Vector of entropies at each bond
pub fn entropy_profile(mps: &MPS) -> Vec<f64> {
    mps.all_singular_values()
        .iter()
        .map(|sv| bond_entropy(sv))
        .collect()
}

/// Compute the Rényi entropy of order α at a bond.
///
/// S_α = (1/(1-α)) log₂(Σ λ^(2α))
///
/// Special cases:
/// - α → 1: von Neumann entropy
/// - α = 2: collision entropy
/// - α → ∞: min-entropy
///
/// # Arguments
/// * `singular_values` - The singular values at a bond
/// * `alpha` - The Rényi parameter (must be positive, not equal to 1)
///
/// # Returns
/// The Rényi entropy in bits
pub fn renyi_entropy(singular_values: &[f64], alpha: f64) -> f64 {
    if singular_values.is_empty() || alpha <= 0.0 {
        return 0.0;
    }

    // For α close to 1, use von Neumann entropy
    if (alpha - 1.0).abs() < 0.01 {
        return bond_entropy(singular_values);
    }

    let norm_sq: f64 = singular_values.iter().map(|&s| s * s).sum();
    if norm_sq < EPSILON {
        return 0.0;
    }

    // Compute Σ p^α where p = λ²/norm_sq
    let sum_p_alpha: f64 = singular_values
        .iter()
        .map(|&s| {
            let p = (s * s) / norm_sq;
            if p > EPSILON {
                p.powf(alpha)
            } else {
                0.0
            }
        })
        .sum();

    if sum_p_alpha < EPSILON {
        return 0.0;
    }

    (1.0 / (1.0 - alpha)) * sum_p_alpha.log2()
}

/// Compute the Schmidt rank (number of non-zero singular values) at a bond.
///
/// This gives the effective dimension of entanglement at that bond.
///
/// # Arguments
/// * `mps` - The MPS state
/// * `bond_index` - The bond to check
///
/// # Returns
/// Number of singular values above the threshold
pub fn schmidt_rank(mps: &MPS, bond_index: usize) -> usize {
    match mps.singular_values(bond_index) {
        Some(sv) => sv.iter().filter(|&&s| s > EPSILON.sqrt()).count(),
        None => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bond_entropy_product_state() {
        // Product state: single singular value of 1
        let sv = vec![1.0];
        let entropy = bond_entropy(&sv);
        assert!(entropy.abs() < EPSILON);
    }

    #[test]
    fn test_bond_entropy_bell_state() {
        // Bell state: two equal singular values
        let sqrt_half = 1.0 / 2.0_f64.sqrt();
        let sv = vec![sqrt_half, sqrt_half];
        let entropy = bond_entropy(&sv);
        assert!((entropy - 1.0).abs() < 1e-10); // 1 bit
    }

    #[test]
    fn test_bond_entropy_three_way() {
        // Three equal singular values: entropy = log₂(3)
        let val = 1.0 / 3.0_f64.sqrt();
        let sv = vec![val, val, val];
        let entropy = bond_entropy(&sv);
        let expected = 3.0_f64.log2();
        assert!((entropy - expected).abs() < 1e-10);
    }

    #[test]
    fn test_max_entropy_bound() {
        let bound = max_entropy_bound(64, 100);
        let expected = 99.0 * 64.0_f64.log2();
        assert!((bound - expected).abs() < EPSILON);
    }

    #[test]
    fn test_renyi_entropy_alpha_2() {
        let sqrt_half = 1.0 / 2.0_f64.sqrt();
        let sv = vec![sqrt_half, sqrt_half];
        let s2 = renyi_entropy(&sv, 2.0);
        // For equal distribution: S₂ = -log₂(Σ p²) = -log₂(2 * 0.25) = 1
        assert!((s2 - 1.0).abs() < 1e-10);
    }

    #[test]
    fn test_augmented_entropy() {
        let mps = MPS::new(100, 32);
        let aug = augmented_entropy(&mps);
        let expected_poly = PI * 100.0 * 100.0;
        // Product state has zero entanglement entropy
        assert!((aug - expected_poly).abs() < 1.0);
    }

    #[test]
    fn test_entropy_profile() {
        let mps = MPS::new(5, 8);
        let profile = entropy_profile(&mps);
        assert_eq!(profile.len(), 4); // n-1 bonds
                                      // Product state should have zero entropy at all bonds
        for e in profile {
            assert!(e.abs() < EPSILON);
        }
    }
}
