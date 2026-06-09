//! Integration tests for the zkfl-prover.
//!
//! Updated for the new API:
//!   - prove_round now takes 2 extra trailing args:
//!       gradient_root_bytes: &[u8]
//!       norm_proof_bytes:    &[u8]
//!   - IVCState::finalize() requires a keys_dir (use IVCKeys::setup_and_save
//!     first, then finalize_with_keys for convenience in unit tests).

use ark_bn254::Fr;
use ark_ff::PrimeField;
use ark_serialize::CanonicalDeserialize;
use std::path::PathBuf;

use zkfl_prover::circuits::ivc_accumulator::{IVCKeys, IVCState};
use zkfl_prover::circuits::round_prover::{bytes_to_fr, FLRoundProver};
use zkfl_prover::norm_proof::bulletproof_norm::{verify_norm_proof, NormProver};

// ─── Helpers ──────────────────────────────────────────────────────────────────

fn temp_keys_dir(label: &str) -> PathBuf {
    let dir = std::env::temp_dir()
        .join(format!("ivc_keys_integ_{}_{}", label, std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn dummy_gradient_root() -> Vec<u8> {
    b"gradient_merkle_root_bytes_dummy".to_vec()
}

fn dummy_norm_proof() -> Vec<u8> {
    b"norm_proof_json_bytes_dummy".to_vec()
}

// ─── Test 1: Full FL round prove + verify ─────────────────────────────────────

#[test]
fn test_full_fl_round() {
    let norm_bound = 1.0_f64;

    println!("[test_full_fl_round] Groth16 setup (OsRng, Poseidon circuit)…");
    let prover = FLRoundProver::setup(norm_bound).expect("setup");

    let gradients = vec![0.12_f64, -0.08, 0.05, 0.07, -0.11];
    let l2: f64 = gradients.iter().map(|g| g * g).sum::<f64>().sqrt();
    assert!(l2 < norm_bound, "test gradients must be within bound");

    let prev_hash_fr = Fr::from(0u64);
    let proof = prover
        .prove_round(0, prev_hash_fr, &gradients, norm_bound, 5,
                     &dummy_gradient_root(), &dummy_norm_proof())
        .expect("prove_round");

    println!("  round_id:                {}", proof.round_id);
    println!("  prev_hash:               {}…", &proof.prev_model_hash[..16]);
    println!("  new_hash:                {}…", &proof.new_model_hash[..16]);
    println!("  gradient_root_commit:    {}…", &proof.gradient_root_commit[..16]);
    println!("  norm_proof_commit:       {}…", &proof.norm_proof_commit[..16]);
    println!(
        "  proof size:              {} bytes",
        hex::decode(&proof.proof_bytes).unwrap().len()
    );

    let valid = FLRoundProver::verify_proof(&proof).expect("verify_proof");
    assert!(valid, "FL round proof must be valid");
    println!("[test_full_fl_round] PASS");
}

// ─── Test 2: Bulletproof norm proof (Fiat-Shamir) ─────────────────────────────

#[test]
fn test_norm_proof() {
    let gradients = vec![0.1_f64, -0.2, 0.05, 0.15, -0.1, 0.03, -0.07, 0.11];
    let bound = 1.0_f64;

    let l2: f64 = gradients.iter().map(|g| g * g).sum::<f64>().sqrt();
    assert!(l2 < bound, "test gradients must be within bound");

    let d = gradients.len();
    let prover = NormProver::new_with_challenge_size(d, d); // challenge all
    let proof = prover.prove(&gradients, bound).expect("prove");

    println!("[test_norm_proof] dimension={}, challenge_size={}", proof.dimension, proof.challenge_size);
    println!("  challenge_indices: {:?}", proof.challenge_indices);

    let valid = verify_norm_proof(&proof);
    assert!(valid, "Norm proof must verify");
    println!("[test_norm_proof] PASS");
}

// ─── Test 3: IVC accumulation — 3 rounds, real Groth16 summary proof ──────────

#[test]
fn test_ivc_accumulation() {
    let norm_bound = 1.0_f64;

    println!("[test_ivc_accumulation] Setup…");
    let prover = FLRoundProver::setup(norm_bound).expect("setup");

    let initial_hash_fr = Fr::from(0u64);
    let mut state = IVCState::new(&initial_hash_fr);

    let rounds = 3u64;
    let mut prev_hash_fr = initial_hash_fr;

    for round in 0..rounds {
        let scale = 0.1 + round as f64 * 0.05;
        let gradients = vec![scale, -scale * 0.8, scale * 0.5, -scale * 0.3, scale * 0.2];

        let grad_root = format!("gradient_root_round_{}", round).into_bytes();
        let norm_bytes = format!("norm_proof_round_{}", round).into_bytes();

        let proof = prover
            .prove_round(round, prev_hash_fr, &gradients, norm_bound, 3,
                         &grad_root, &norm_bytes)
            .expect("prove_round");

        // Decode new_hash for next round.
        let new_bytes = hex::decode(&proof.new_model_hash).unwrap();
        prev_hash_fr = Fr::deserialize_compressed(new_bytes.as_slice()).unwrap();

        state.fold_round(proof).expect("fold_round");
        println!("[test_ivc_accumulation] Round {} folded ✓", round);
    }

    assert_eq!(state.round, rounds);

    println!("[test_ivc_accumulation] Generating IVC keys + Groth16 IVC summary proof…");
    let keys_dir = temp_keys_dir("accum");
    let keys = IVCKeys::setup_and_save(&keys_dir).expect("ivc setup");

    let final_proof = state.finalize_with_keys(&keys).expect("finalize");
    assert_eq!(final_proof.total_rounds, rounds);
    assert_ne!(final_proof.initial_model_hash, final_proof.final_model_hash);

    // Verify the IVC summary Groth16 proof (embedded VK — unit-test path).
    let valid = final_proof.verify().expect("IVC verify");
    assert!(valid, "IVC summary proof must be valid");

    // Also verify with the pinned external VK (production path).
    let pinned_hex = keys.vk_hex();
    let valid2 = final_proof.verify_with_pinned_vk(&pinned_hex).expect("IVC verify pinned");
    assert!(valid2, "IVC summary proof must be valid against pinned VK");

    println!("[test_ivc_accumulation] On-chain anchor: {}", final_proof.on_chain_anchor);
    println!("[test_ivc_accumulation] PASS");

    // Cleanup temp keys.
    let _ = std::fs::remove_dir_all(&keys_dir);
}

// ─── Test 4: Small gradient norm proof ────────────────────────────────────────

#[test]
fn test_norm_proof_small_gradient() {
    let gradients = vec![0.001_f64; 16];
    let bound = 1.0_f64;
    let prover = NormProver::new(gradients.len());
    let proof = prover.prove(&gradients, bound).expect("prove");
    assert!(verify_norm_proof(&proof));
}

// ─── Test 5: Norm proof — exact power-of-two dimension ────────────────────────

#[test]
fn test_norm_proof_power_of_two_dimension() {
    let gradients = vec![0.05_f64; 8];
    let bound = 0.5_f64;
    let prover = NormProver::new_with_challenge_size(gradients.len(), 8);
    let proof = prover.prove(&gradients, bound).expect("prove");
    assert!(verify_norm_proof(&proof));
}

// ─── Test 6: Different gradient roots → different model hashes ────────────────

#[test]
fn test_gradient_root_binding() {
    let norm_bound = 1.0_f64;
    let prover = FLRoundProver::setup(norm_bound).expect("setup");
    let gradients = vec![0.1_f64, 0.2, 0.05];

    let p1 = prover.prove_round(
        0, Fr::from(0u64), &gradients, norm_bound, 3,
        b"root_A", b"norm_proof_bytes",
    ).expect("p1");

    let p2 = prover.prove_round(
        0, Fr::from(0u64), &gradients, norm_bound, 3,
        b"root_B", b"norm_proof_bytes",
    ).expect("p2");

    // Different gradient roots must produce different new_model_hashes.
    assert_ne!(p1.new_model_hash, p2.new_model_hash,
        "Different gradient roots must produce different model hashes (Fix 3)");
    assert!(FLRoundProver::verify_proof(&p1).expect("verify p1"));
    assert!(FLRoundProver::verify_proof(&p2).expect("verify p2"));
    println!("[test_gradient_root_binding] PASS");
}

// ─── Test 7: Norm proof challenge size is ≥ 20% of d ─────────────────────────

#[test]
fn test_norm_challenge_fraction() {
    // For d=5000, k should be max(1024, ceil(0.20 * 5000)) = max(1024, 1000) = 1024
    let d = 5000;
    let prover = NormProver::new(d);
    let k = prover.challenge_size();
    let expected = std::cmp::max(1024, (d as f64 * 0.20).ceil() as usize);
    assert_eq!(k, expected,
        "challenge_size should be max(1024, ceil(0.20*d)) for d={}", d);
    println!("[test_norm_challenge_fraction] d={}, k={} (expected {})", d, k, expected);

    // For d=10000, k should be max(1024, ceil(0.20 * 10000)) = 2000
    let d2 = 10000;
    let prover2 = NormProver::new(d2);
    let k2 = prover2.challenge_size();
    let expected2 = std::cmp::max(1024, (d2 as f64 * 0.20).ceil() as usize);
    assert_eq!(k2, expected2,
        "challenge_size should be max(1024, ceil(0.20*d)) for d={}", d2);
    println!("[test_norm_challenge_fraction] d={}, k={} (expected {})", d2, k2, expected2);

    println!("[test_norm_challenge_fraction] PASS");
}

// ─── Test 8: IVC padding invariant — different N, same VK ────────────────────

#[test]
fn test_ivc_padding_invariant() {
    let norm_bound = 1.0_f64;
    let prover = FLRoundProver::setup(norm_bound).expect("setup");
    let initial_hash = Fr::from(0u64);

    let make_state = |n_rounds: u64| {
        let mut state = IVCState::new(&initial_hash);
        let mut prev = initial_hash;
        for i in 0..n_rounds {
            let grads = vec![0.01 * (i + 1) as f64];
            let proof = prover.prove_round(
                i, prev, &grads, norm_bound, 1,
                b"root", b"norm",
            ).unwrap();
            prev = Fr::deserialize_compressed(
                hex::decode(&proof.new_model_hash).unwrap().as_slice()
            ).unwrap();
            state.fold_round(proof).unwrap();
        }
        state
    };

    let state1 = make_state(1);
    let state2 = make_state(2);
    let keys_dir = temp_keys_dir("padding");
    let keys = IVCKeys::setup_and_save(&keys_dir).expect("setup");

    let ivc1 = state1.finalize_with_keys(&keys).unwrap();
    let ivc2 = state2.finalize_with_keys(&keys).unwrap();

    // Both must verify individually with the same VK (Fix 6).
    assert!(ivc1.verify().unwrap(), "1-round IVC must verify");
    assert!(ivc2.verify().unwrap(), "2-round IVC must verify");

    // Their anchors must differ (different histories).
    assert_ne!(ivc1.on_chain_anchor, ivc2.on_chain_anchor);

    let _ = std::fs::remove_dir_all(&keys_dir);
    println!("[test_ivc_padding_invariant] PASS");
}

// ─── Test 9: Load IVC proof from demo file (if available) ─────────────────────

#[test]
fn test_ivc_from_file() {
    // Load the actual CLI-generated proof and run IVC on it.
    let proof_path = std::path::PathBuf::from("demo/proofs/proof_round_0.json");
    if !proof_path.exists() {
        eprintln!("Skipping test_ivc_from_file — proof_round_0.json not found");
        return;
    }

    use zkfl_prover::circuits::ivc_accumulator::IVCState;
    use zkfl_prover::circuits::round_prover::FLProof;

    let data = std::fs::read_to_string(&proof_path).expect("read proof");
    let proof: FLProof = match serde_json::from_str(&data) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Skipping test_ivc_from_file — proof file has old format ({}). Re-run ivc-setup + prove-round to regenerate.", e);
            return;
        }
    };

    // Genesis initial hash: Fr::from(0) — consistent with prove-round's
    // decode_prev_hash("000...000") which uses Fr::deserialize_compressed → Fr::zero().
    let initial_fr = ark_bn254::Fr::from(0u64);

    let mut state = IVCState::new(&initial_fr);
    state.fold_round(proof).expect("fold_round");

    // Need IVC keys — generate ephemeral keys for this test.
    let keys_dir = temp_keys_dir("from_file");
    let keys = IVCKeys::setup_and_save(&keys_dir).expect("ivc setup");

    let ivc = state.finalize_with_keys(&keys).expect("finalize");
    println!("IVC anchor: {}", ivc.on_chain_anchor);

    let valid = ivc.verify().expect("verify");
    assert!(valid, "IVC summary proof should be valid");

    let _ = std::fs::remove_dir_all(&keys_dir);
    println!("test_ivc_from_file PASS");
}
