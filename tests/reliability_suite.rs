use quantum_wall::entropy::{bond_entropy, entropy_profile, max_entropy_bound, renyi_entropy};
use quantum_wall::{
    augmented_entropy, average_entanglement_entropy, total_entanglement_entropy, EPSILON, MPS,
};

#[test]
fn product_state_entropy_stability_over_many_sizes() {
    for n in 1..=40 {
        let mps = MPS::new(n, 8);

        assert_eq!(mps.n_sites(), n);
        assert_eq!(mps.all_singular_values().len(), n.saturating_sub(1));

        let total = total_entanglement_entropy(&mps);
        let average = average_entanglement_entropy(&mps);
        let profile = entropy_profile(&mps);

        assert!(total.abs() < EPSILON, "non-zero total entropy at size {n}");
        assert!(
            average.abs() < EPSILON,
            "non-zero average entropy at size {n}"
        );
        assert_eq!(profile.len(), n.saturating_sub(1));
        for (idx, &entry) in profile.iter().enumerate() {
            assert!(
                entry.abs() < EPSILON,
                "entropy spike at bond {idx} for size {n}"
            );
        }

        let expected_augmented = std::f64::consts::PI * (n as f64).powi(2);
        let augmented = augmented_entropy(&mps);
        assert!(
            (augmented - expected_augmented).abs() < 1e-6,
            "augmented entropy drift at size {n}: {augmented} vs {expected_augmented}"
        );
    }
}

#[test]
fn memory_usage_and_bounds_remain_well_behaved() {
    let mut previous_memory = 0usize;

    for n in 2..=34 {
        let mps = MPS::new(n, 16);
        let mem = mps.memory_usage();

        assert!(
            mem > previous_memory,
            "memory did not grow from size {} to {}",
            n - 1,
            n
        );
        previous_memory = mem;

        let bound = max_entropy_bound(mps.bond_dim(), mps.n_sites());
        assert!(bound.is_finite() && bound >= 0.0);
    }
}

#[test]
fn renyi_entropy_stays_finite_across_orders() {
    let singular_values = vec![0.6, 0.5, 0.3];
    let von_neumann = bond_entropy(&singular_values);

    for step in 0..=30 {
        let alpha = 0.5 + (step as f64) * 0.1; // 31 samples spanning 0.5..3.5
        let renyi = renyi_entropy(&singular_values, alpha);

        assert!(renyi.is_finite(), "NaN/inf at alpha={alpha}");
        if (alpha - 1.0).abs() < 0.2 {
            assert!(
                (renyi - von_neumann).abs() < 0.15,
                "Renyi near alpha=1 deviates too far: alpha={alpha}, value={renyi}, von Neumann={von_neumann}"
            );
        }
    }

    let high_order = renyi_entropy(&singular_values, 10.0);
    assert!(high_order <= von_neumann + 1e-9);
}

#[test]
fn renyi_entropy_tracks_the_von_neumann_limit_and_monotonicity() {
    let singular_values = vec![0.7, 0.5, 0.2];
    let von_neumann = bond_entropy(&singular_values);

    // α close to 1 should fall back to von Neumann entropy
    for alpha in [0.991, 1.0, 1.009] {
        let renyi = renyi_entropy(&singular_values, alpha);
        assert!(
            (renyi - von_neumann).abs() < 1e-8,
            "Rényi entropy deviates near α=1 (α={alpha}): {renyi} vs von Neumann {von_neumann}"
        );
    }

    // Rényi entropy should be non-increasing as α grows
    let mut previous = f64::INFINITY;
    for alpha in [0.5, 0.75, 1.25, 2.0, 3.5] {
        let renyi = renyi_entropy(&singular_values, alpha);
        assert!(
            renyi <= previous + 1e-12,
            "Rényi entropy increased at α={alpha}"
        );
        previous = renyi;
    }
}

#[test]
fn memory_usage_matches_tensor_layout_documentation() {
    let mps = MPS::new(4, 8);

    // Manual tensor element counts based on left/right caps from construction
    let element_counts = [1 * 2 * 8, 2 * 2 * 4, 4 * 2 * 2, 8 * 2 * 1];
    let tensor_elements: usize = element_counts.iter().sum();
    let expected_tensor_bytes = tensor_elements * std::mem::size_of::<num_complex::Complex64>();

    let expected_sv_bytes = 3 * std::mem::size_of::<f64>(); // n_sites - 1 = 3 bonds, each with a single singular value
    let expected_total = expected_tensor_bytes + expected_sv_bytes;

    assert_eq!(mps.memory_usage(), expected_total);
    assert_eq!(mps.n_sites(), 4);
    assert_eq!(mps.bond_dim(), 8);
}

#[test]
fn max_entropy_bound_matches_log_scaling_from_docs() {
    let n_sites = 6;
    let bond_dim = 16;

    let computed_bound = max_entropy_bound(bond_dim, n_sites);
    let expected_bound = (n_sites as f64 - 1.0) * (bond_dim as f64).log2();

    assert!((computed_bound - expected_bound).abs() < 1e-12);
}

#[test]
fn max_entropy_bound_handles_degenerate_cases() {
    assert_eq!(max_entropy_bound(0, 10), 0.0);
    assert_eq!(max_entropy_bound(8, 0), 0.0);
    assert_eq!(max_entropy_bound(8, 1), 0.0);
}

#[test]
fn renyi_entropy_handles_empty_or_invalid_inputs() {
    let empty: Vec<f64> = Vec::new();
    assert_eq!(renyi_entropy(&empty, 2.0), 0.0);

    let singular_values = vec![0.5, 0.5];

    for &alpha in &[0.0, -1.0, -10.0] {
        assert_eq!(renyi_entropy(&singular_values, alpha), 0.0);
    }
}

#[test]
fn aggregate_scaling_invariance_survives_zero_entries() {
    let mut mps = MPS::new(5, 4);
    mps.set_singular_values(0, vec![0.0, 0.9, 0.4]);
    mps.set_singular_values(1, vec![0.5, 0.0, 0.25]);
    mps.set_singular_values(2, vec![0.7, 0.0]);
    mps.set_singular_values(3, vec![0.6, 0.3, 0.0]);

    let mut scaled = MPS::new(5, 4);
    let factor = 5.5;
    scaled.set_singular_values(0, vec![0.0 * factor, 0.9 * factor, 0.4 * factor]);
    scaled.set_singular_values(1, vec![0.5 * factor, 0.0 * factor, 0.25 * factor]);
    scaled.set_singular_values(2, vec![0.7 * factor, 0.0 * factor]);
    scaled.set_singular_values(3, vec![0.6 * factor, 0.3 * factor, 0.0 * factor]);

    let profile = entropy_profile(&mps);
    let profile_scaled = entropy_profile(&scaled);
    assert_eq!(profile.len(), profile_scaled.len());
    for (a, b) in profile.iter().zip(profile_scaled.iter()) {
        assert!((a - b).abs() < 1e-12);
    }

    let total = total_entanglement_entropy(&mps);
    let total_scaled = total_entanglement_entropy(&scaled);
    assert!((total - total_scaled).abs() < 1e-12);

    let average = average_entanglement_entropy(&mps);
    let average_scaled = average_entanglement_entropy(&scaled);
    assert!((average - average_scaled).abs() < 1e-12);

    let augmented = augmented_entropy(&mps);
    let augmented_scaled = augmented_entropy(&scaled);
    assert!((augmented - augmented_scaled).abs() < 1e-12);
}
