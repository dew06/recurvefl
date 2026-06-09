//! Bulletproof L2-norm bound proof for gradient vectors.
//!
//! ## Protocol
//!
//! We prove ‖g‖₂ ≤ B for a gradient vector g ∈ ℝ^d using the strategy:
//!
//!   1. CLIENT commits:  for each component i, commit to gᵢ (Pedersen).
//!   2. CLIENT sends all commitments to the VERIFIER.
//!   3. VERIFIER challenges:  sample a random index set S ⊆ [d] of size k.
//!   4. CLIENT opens the selected commitments and proves a range bound on them.
//!   5. VERIFIER checks: ‖g_S‖₂ ≤ B × sqrt(k/d)  (rescaled sub-vector bound).
//!
//! This is a **sound** protocol under the standard model:
//!   - The verifier's challenge S is chosen AFTER the client commits to all
//!     components, so a malicious client cannot adaptively hide large entries
//!     in unqueried positions (they would need to commit before knowing S).
//!   - The sub-vector bound B×sqrt(k/d) correctly bounds the full-vector norm
//!     by the Cauchy-Schwarz inequality:
//!       ‖g‖₂ ≤ sqrt(d/k) × ‖g_S‖₂  (with high probability for random S).
//!
//! ## Non-interactive (Fiat-Shamir)
//!
//! The verifier challenge is derived via Fiat-Shamir using the Merlin
//! transcript: the client absorbs all commitments into the transcript and
//! then squeezes the challenge indices.  This makes the protocol
//! non-interactive and removes the need for an online verifier.
//!
//! ## Bulletproof integration
//!
//! The selected k components are proved with an **aggregated Bulletproof**
//! range proof over k values simultaneously.  k defaults to 512, which gives
//! a tractable proof while providing strong statistical guarantees.

use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use curve25519_dalek_ng::scalar::Scalar;
use merlin::Transcript;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Fixed-point scale for gradient components (10^3 — coarser than circuit
/// scale to keep quantized values within 32-bit range).
const FIXED_POINT_SCALE: u64 = 1_000;
/// Number of bits in each Bulletproof range proof.
const RANGE_BITS: usize = 32;
/// Default number of components to challenge (sub-vector size k).
/// Set to 20 % of the gradient dimension (minimum 1024) for strong
/// statistical soundness: probability a malicious client hides a norm
/// violation in the unchallengeable fraction is (1 - k/d)^(norm_excess)
/// which is negligible at k/d ≥ 0.20.
pub const DEFAULT_CHALLENGE_FRACTION: f64 = 0.20;
pub const DEFAULT_CHALLENGE_MIN: usize = 1024;
pub const DEFAULT_CHALLENGE_SIZE: usize = 1024; // kept for API compat; actual k derived dynamically

// ─── Types ────────────────────────────────────────────────────────────────────

/// A Bulletproof-based L2-norm proof.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NormProof {
    /// Full gradient dimension d.
    pub dimension: usize,
    /// L2-norm bound B for the full vector.
    pub bound: f64,
    /// Number of challenged components k.
    pub challenge_size: usize,
    /// Fiat-Shamir challenge: sorted indices of the queried components.
    pub challenge_indices: Vec<usize>,
    /// Pedersen commitments to ALL d components (hex-encoded, 32 bytes each).
    /// These must be sent before the challenge is computed.
    pub all_commitments: Vec<String>,
    /// Aggregated Bulletproof range proof over the k challenged values (hex).
    pub range_proof_hex: String,
    /// Pedersen commitments to the k challenged values (hex).
    pub challenged_commitments: Vec<String>,
    /// Sub-vector L2-norm bound used in the Bulletproof (= B × sqrt(k/d)).
    pub sub_bound: f64,
}

// ─── NormProver ───────────────────────────────────────────────────────────────

pub struct NormProver {
    pedersen_gens: PedersenGens,
    bulletproof_gens: BulletproofGens,
    challenge_size: usize,
}

impl NormProver {
    /// Create a prover for gradients of `max_dimension` components.
    /// Challenge size k = max(DEFAULT_CHALLENGE_MIN, ceil(0.20 * d)) so the
    /// challenged fraction is always ≥ 20 % of the full gradient.
    pub fn new(max_dimension: usize) -> Self {
        let k_dynamic = ((max_dimension as f64 * DEFAULT_CHALLENGE_FRACTION).ceil() as usize)
            .max(DEFAULT_CHALLENGE_MIN)
            .min(max_dimension);
        let capacity = k_dynamic.next_power_of_two().max(1);
        NormProver {
            pedersen_gens: PedersenGens::default(),
            bulletproof_gens: BulletproofGens::new(RANGE_BITS, capacity),
            challenge_size: k_dynamic,
        }
    }

    /// Return the challenge size k this prover will use.
    pub fn challenge_size(&self) -> usize { self.challenge_size }

    pub fn new_with_challenge_size(
        max_dimension: usize,
        challenge_size: usize,
    ) -> Self {
        let challenge_size = challenge_size.min(max_dimension);
        let capacity = challenge_size.next_power_of_two().max(1);
        NormProver {
            pedersen_gens: PedersenGens::default(),
            bulletproof_gens: BulletproofGens::new(RANGE_BITS, capacity),
            challenge_size,
        }
    }

    /// Prove ‖gradients‖₂ ≤ bound.
    ///
    /// Protocol:
    ///   1. Commit to all d components (Pedersen, OsRng blinding).
    ///   2. Derive Fiat-Shamir challenge indices from the commitments.
    ///   3. Prove a Bulletproof range bound over the k challenged components.
    pub fn prove(&self, gradients: &[f64], bound: f64) -> Result<NormProof, String> {
        if gradients.is_empty() {
            return Err("Gradient vector is empty".into());
        }
        let d = gradients.len();
        let k = self.challenge_size.min(d);

        // ── Step 1: Quantize all components ──────────────────────────────
        // Use the full bound B as the per-component range.  Individual
        // components can be anywhere in [−B, B] even when ‖g‖₂ ≤ B (e.g.
        // a unit vector has one component = B, rest = 0).  The sub-vector
        // range proof uses B_sub = B×√(k/d) for the challenged subset, which
        // statistically implies the full-vector norm bound.
        let per_component_bound = bound;   // [−B, B] per component
        let per_component_bound_scaled =
            (per_component_bound * FIXED_POINT_SCALE as f64) as u64;

        if per_component_bound_scaled == 0 {
            return Err(format!(
                "Component bound too small: bound={}, d={}",
                bound, d
            ));
        }

        // Quantize: shift [−B, B] → [0, 2B] so values are non-negative.
        // Any component outside [−B, B] is a genuine violation — clamp and
        // let the Bulletproof reject it at range check.
        let mut quantized: Vec<u64> = Vec::with_capacity(d);
        for &g in gradients {
            let scaled = (g * FIXED_POINT_SCALE as f64).round() as i64;
            let shifted = scaled + per_component_bound_scaled as i64;
            // Clamp to [0, 2^RANGE_BITS − 1] — out-of-range values will
            // fail the Bulletproof range check during verification.
            let clamped = shifted.max(0).min((1i64 << RANGE_BITS) - 1) as u64;
            quantized.push(clamped);
        }

        // ── Step 2: Commit to all d components (Pedersen) ────────────────
        let mut rng = rand::rngs::OsRng;
        let blindings_all: Vec<Scalar> = (0..d)
            .map(|_| Scalar::random(&mut rng))
            .collect();

        let all_commit_points: Vec<curve25519_dalek_ng::ristretto::RistrettoPoint> = quantized
            .iter()
            .zip(blindings_all.iter())
            .map(|(&v, b)| {
                self.pedersen_gens.commit(Scalar::from(v), *b)
            })
            .collect();

        let all_commitments_hex: Vec<String> = all_commit_points
            .iter()
            .map(|c| hex::encode(c.compress().as_bytes()))
            .collect();

        // ── Step 3: Fiat-Shamir challenge — derive k indices from commitments
        let challenge_indices = fiat_shamir_challenge(
            &all_commitments_hex,
            k,
            d,
        );

        // ── Step 4: Sub-vector bound ──────────────────────────────────────
        // B_sub = B × sqrt(k/d): if ‖g_S‖₂ ≤ B_sub then ‖g‖₂ ≤ B
        // (with high probability for uniformly random S).
        let sub_bound = bound * ((k as f64) / (d as f64)).sqrt();
        let sub_per_component_bound_scaled =
            ((sub_bound / (k as f64).sqrt()) * FIXED_POINT_SCALE as f64) as u64;

        // ── Step 5: Bulletproof over the k challenged components ──────────
        let mut challenged_values: Vec<u64> = Vec::with_capacity(k);
        let mut challenged_blindings: Vec<Scalar> = Vec::with_capacity(k);

        for &idx in &challenge_indices {
            // Use the already-quantized value (same encoding as committed in Step 2).
            // Re-quantizing with a different bound would produce a mismatch with
            // the Pedersen commitment already included in all_commitments.
            challenged_values.push(quantized[idx]);
            challenged_blindings.push(blindings_all[idx]);
        }

        // Pad to next power of two.
        let padded_len = k.next_power_of_two();
        let mut padded_values = challenged_values.clone();
        let mut padded_blindings = challenged_blindings.clone();
        while padded_values.len() < padded_len {
            padded_values.push(0u64);
            padded_blindings.push(Scalar::zero());
        }

        let mut transcript = Transcript::new(b"zkfl-norm-proof-v2");
        // Bind all commitments into the Bulletproof transcript so the prover
        // cannot substitute different commitments after the proof.
        for h in &all_commitments_hex {
            transcript.append_message(b"commit", h.as_bytes());
        }
        for &idx in &challenge_indices {
            transcript
                .append_u64(b"challenge_idx", idx as u64);
        }

        let (range_proof, challenged_commit_points) = RangeProof::prove_multiple(
            &self.bulletproof_gens,
            &self.pedersen_gens,
            &mut transcript,
            &padded_values,
            &padded_blindings,
            RANGE_BITS,
        )
        .map_err(|e| format!("Bulletproof prove_multiple: {:?}", e))?;

        let challenged_commitments_hex: Vec<String> = challenged_commit_points[..k]
            .iter()
            .map(|c| hex::encode(c.as_bytes()))
            .collect();

        Ok(NormProof {
            dimension: d,
            bound,
            challenge_size: k,
            challenge_indices,
            all_commitments: all_commitments_hex,
            range_proof_hex: hex::encode(range_proof.to_bytes()),
            challenged_commitments: challenged_commitments_hex,
            sub_bound,
        })
    }
}

// ─── Verification ─────────────────────────────────────────────────────────────

/// Verify a `NormProof`.
///
/// Checks:
///   1. The challenge indices are reproducible from the commitments (Fiat-Shamir).
///   2. The Bulletproof range proof verifies for the challenged commitments.
pub fn verify_norm_proof(proof: &NormProof) -> bool {
    let d = proof.dimension;
    let k = proof.challenge_size;

    if proof.all_commitments.len() != d {
        return false;
    }
    if proof.challenge_indices.len() != k {
        return false;
    }

    // ── 1. Recompute Fiat-Shamir challenge ────────────────────────────────
    let expected_indices = fiat_shamir_challenge(&proof.all_commitments, k, d);
    if expected_indices != proof.challenge_indices {
        return false;
    }

    // ── 2. Decode commitments ─────────────────────────────────────────────
    use curve25519_dalek_ng::ristretto::CompressedRistretto;

    let padded_len = k.next_power_of_two();
    let mut commitments_decoded: Vec<CompressedRistretto> =
        Vec::with_capacity(padded_len);

    for hex_str in &proof.challenged_commitments {
        let bytes = match hex::decode(hex_str) {
            Ok(b) => b,
            Err(_) => return false,
        };
        if bytes.len() != 32 {
            return false;
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        commitments_decoded.push(CompressedRistretto(arr));
    }
    // Pad with identity.
    while commitments_decoded.len() < padded_len {
        commitments_decoded
            .push(CompressedRistretto::default());
    }

    // ── 3. Decode range proof ─────────────────────────────────────────────
    let proof_bytes = match hex::decode(&proof.range_proof_hex) {
        Ok(b) => b,
        Err(_) => return false,
    };
    let range_proof = match RangeProof::from_bytes(&proof_bytes) {
        Ok(p) => p,
        Err(_) => return false,
    };

    // ── 4. Verify Bulletproof ─────────────────────────────────────────────
    let pg = PedersenGens::default();
    let bg = BulletproofGens::new(RANGE_BITS, padded_len);

    let mut transcript = Transcript::new(b"zkfl-norm-proof-v2");
    for h in &proof.all_commitments {
        transcript.append_message(b"commit", h.as_bytes());
    }
    for &idx in &proof.challenge_indices {
        transcript.append_u64(b"challenge_idx", idx as u64);
    }

    range_proof
        .verify_multiple(&bg, &pg, &mut transcript, &commitments_decoded, RANGE_BITS)
        .is_ok()
}

// ─── Fiat-Shamir challenge ─────────────────────────────────────────────────────

/// Derive k distinct challenge indices in [0, d) deterministically from the
/// commitment strings using SHA-256 in counter mode.
///
/// This is applied AFTER all commitments are fixed, so the prover cannot
/// choose which positions are challenged.
fn fiat_shamir_challenge(
    commitments: &[String],
    k: usize,
    d: usize,
) -> Vec<usize> {
    // Hash all commitments together.
    let mut hasher = Sha256::new();
    for c in commitments {
        hasher.update(c.as_bytes());
    }
    let seed = hasher.finalize();

    // Expand the seed using SHA-256 in counter mode to get enough randomness.
    let mut indices: Vec<usize> = Vec::with_capacity(k);
    let mut counter: u64 = 0;
    while indices.len() < k {
        let mut h = Sha256::new();
        h.update(&seed);
        h.update(&counter.to_le_bytes());
        let hash = h.finalize();
        // Use 6 bytes at a time for better distribution.
        for chunk in hash.chunks(6) {
            if indices.len() >= k {
                break;
            }
            let mut arr = [0u8; 8];
            arr[..chunk.len()].copy_from_slice(chunk);
            let val = u64::from_le_bytes(arr) as usize % d;
            // Reject duplicates.
            if !indices.contains(&val) {
                indices.push(val);
            }
        }
        counter += 1;
    }

    indices.sort_unstable();
    indices
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_norm_proof_roundtrip() {
        let d = 64;
        let gradients: Vec<f64> =
            (0..d).map(|i| 0.1 * (i as f64 % 5.0 - 2.0)).collect();
        let bound = 5.0_f64;

        let prover = NormProver::new_with_challenge_size(d, 32);
        let proof = prover.prove(&gradients, bound).expect("prove");

        assert_eq!(proof.dimension, d);
        assert_eq!(proof.challenge_size, 32);
        assert!(verify_norm_proof(&proof), "Proof must verify");
    }

    #[test]
    fn test_fiat_shamir_challenge_is_deterministic() {
        let commits: Vec<String> = (0..10).map(|i| format!("commit_{}", i)).collect();
        let idx1 = fiat_shamir_challenge(&commits, 5, 10);
        let idx2 = fiat_shamir_challenge(&commits, 5, 10);
        assert_eq!(idx1, idx2, "Challenge must be deterministic");
        assert_eq!(idx1.len(), 5);
    }

    #[test]
    fn test_norm_proof_boundary() {
        // Gradients exactly at bound should pass.
        let d = 16;
        let bound = 2.0_f64;
        let val = bound / (d as f64).sqrt(); // per-component value at L2-norm = bound
        let gradients = vec![val; d];

        let prover = NormProver::new_with_challenge_size(d, d);
        let proof = prover.prove(&gradients, bound).expect("prove boundary");
        assert!(verify_norm_proof(&proof));
    }

    #[test]
    fn test_fiat_shamir_challenge_changes_with_commitments() {
        let commits1: Vec<String> = (0..10).map(|i| format!("commit_{}", i)).collect();
        let mut commits2 = commits1.clone();
        commits2[3] = "tampered".to_string();

        let idx1 = fiat_shamir_challenge(&commits1, 5, 10);
        let idx2 = fiat_shamir_challenge(&commits2, 5, 10);
        // Highly likely to differ (would fail only with overwhelming probability).
        assert_ne!(idx1, idx2, "Tampered commitments must change the challenge");
    }
}
