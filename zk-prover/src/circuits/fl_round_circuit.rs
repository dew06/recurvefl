//! FL Round Circuit — one step of the IVC fold for Federated Learning
//!
//! ## Public inputs (6 total — all known to the on-chain verifier)
//!
//!   0. prev_model_hash   : Fr  — Poseidon hash of the model from the prior round
//!   1. round_id          : Fr  — zero-based round index
//!   2. new_model_hash    : Fr  — Poseidon(prev, norm, round_id, gradient_root, norm_commit)
//!   3. next_round_id     : Fr  — round_id + 1
//!   4. gradient_root     : Fr  — Poseidon of the gradient Merkle root bytes
//!                                (fixes Critical 3: real aggregation commitment)
//!   5. norm_proof_commit : Fr  — Poseidon of the Bulletproof commitment bytes
//!                                (fixes Significant 4: links norm proof to circuit)
//!
//! ## Private witnesses
//!
//!   - gradient_norm_scaled : Fr  — scaled L2-norm, proved ≤ norm_bound_scaled
//!   - client_count         : Fr  — number of contributing clients
//!
//! ## Constraints
//!
//!   1. round_id_new = round_id_prev + 1
//!   2. gradient_norm_scaled ≤ norm_bound_scaled  (64-bit range check)
//!   3. new_model_hash = Poseidon(prev, norm, round_id, gradient_root, norm_proof_commit)
//!      (binds gradient content AND norm proof commitment into the chain hash)

use ark_bn254::Fr;
use ark_crypto_primitives::sponge::{
    constraints::CryptographicSpongeVar,
    poseidon::{
        constraints::PoseidonSpongeVar,
        PoseidonConfig, PoseidonSponge,
    },
    CryptographicSponge,
};
use ark_ff::{BigInteger, PrimeField};
use ark_r1cs_std::{
    alloc::AllocVar,
    boolean::Boolean,
    eq::EqGadget,
    fields::{fp::FpVar, FieldVar},
    R1CSVar,
};
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystemRef, SynthesisError,
};
use ark_std::One;
use sha2::{Digest, Sha256};

/// Fixed-point scale factor: floating-point gradients are multiplied by this
/// before entering the circuit as integers.
pub const FIXED_POINT_SCALE: u64 = 1_000_000;

// ─── Poseidon configuration ──────────────────────────────────────────────────

/// Build a Poseidon config for BN254 scalar field (Fr).
/// Parameters: state=3, rate=2, capacity=1, full_rounds=8, partial_rounds=57, α=5.
/// Matches the EVM Poseidon used by Zcash / Aztec / Semaphore.
pub fn poseidon_config() -> PoseidonConfig<Fr> {
    use ark_crypto_primitives::sponge::poseidon::traits::find_poseidon_ark_and_mds;
    let (ark, mds) = find_poseidon_ark_and_mds::<Fr>(254, 3, 8, 57, 0);
    PoseidonConfig {
        full_rounds: 8,
        partial_rounds: 57,
        alpha: 5,
        ark,
        mds,
        rate: 2,
        capacity: 1,
    }
}

/// Compute Poseidon hash outside the circuit (native field arithmetic),
/// matching exactly what the in-circuit gadget enforces.
pub fn poseidon_hash_native(inputs: &[Fr]) -> Fr {
    let cfg = poseidon_config();
    let mut sponge = PoseidonSponge::<Fr>::new(&cfg);
    sponge.absorb(&inputs);
    sponge.squeeze_field_elements::<Fr>(1)[0]
}

/// Map arbitrary bytes → a single Fr field element via Poseidon of 4-byte chunks.
/// Used to commit gradient Merkle roots and norm proof bytes into the circuit.
pub fn bytes_to_field_commitment(bytes: &[u8]) -> Fr {
    let cfg = poseidon_config();
    let chunks: Vec<Fr> = bytes
        .chunks(4)
        .map(|c| {
            let mut buf = [0u8; 4];
            buf[..c.len()].copy_from_slice(c);
            Fr::from(u32::from_le_bytes(buf) as u64)
        })
        .collect();
    let mut sponge = PoseidonSponge::<Fr>::new(&cfg);
    for chunk in &chunks {
        sponge.absorb(chunk);
    }
    sponge.squeeze_field_elements::<Fr>(1)[0]
}

/// Compute the gradient Merkle root commitment from raw bytes.
/// If bytes is empty (genesis), returns Fr::from(0).
pub fn gradient_root_to_fr(gradient_root_bytes: &[u8]) -> Fr {
    if gradient_root_bytes.is_empty() {
        return Fr::from(0u64);
    }
    bytes_to_field_commitment(gradient_root_bytes)
}

/// Compute the norm proof commitment from the serialised NormProof bytes.
/// Callers pass `serde_json::to_vec(&norm_proof)` or the raw challenge bytes.
pub fn norm_proof_commitment(norm_proof_bytes: &[u8]) -> Fr {
    if norm_proof_bytes.is_empty() {
        return Fr::from(0u64);
    }
    bytes_to_field_commitment(norm_proof_bytes)
}

// ─── FL Round Circuit ────────────────────────────────────────────────────────

/// The FL round circuit for a single aggregation step.
#[derive(Clone, Debug)]
pub struct FLRoundCircuit {
    // ── Public inputs (0–3) ─────────────────────────────────────────────────
    pub prev_model_hash:   Fr,
    pub round_id:          Fr,
    pub new_model_hash:    Fr,   // computed by FLRoundCircuit::new
    pub next_round_id:     Fr,   // round_id + 1

    // ── Public inputs (4–5) — Fix 3 & 4 ────────────────────────────────────
    /// Poseidon commitment of the gradient Merkle root (binds aggregated
    /// gradient content to the proof — Fix 3).
    pub gradient_root_commit: Fr,
    /// Poseidon commitment of the Bulletproof norm proof bytes (links the
    /// off-circuit norm proof to this Groth16 proof — Fix 4).
    pub norm_proof_commit:    Fr,

    // ── Private witnesses ───────────────────────────────────────────────────
    pub gradient_norm_scaled: Fr,
    pub client_count:         Fr,

    // ── Parameters ──────────────────────────────────────────────────────────
    pub norm_bound_scaled: u64,
    pub poseidon_cfg:      PoseidonConfig<Fr>,
}

impl FLRoundCircuit {
    /// Construct a circuit with all witnesses and compute `new_model_hash`.
    ///
    /// `new_model_hash = Poseidon(prev, norm, round_id, gradient_root_commit,
    ///                            norm_proof_commit)`
    pub fn new(
        prev_model_hash:      Fr,
        round_id:             Fr,
        gradient_norm_scaled: Fr,
        client_count:         Fr,
        norm_bound_scaled:    u64,
        gradient_root_commit: Fr,
        norm_proof_commit:    Fr,
    ) -> Self {
        let poseidon_cfg = poseidon_config();
        let new_model_hash = poseidon_hash_native(&[
            prev_model_hash,
            gradient_norm_scaled,
            round_id,
            gradient_root_commit,
            norm_proof_commit,
        ]);
        let next_round_id = round_id + Fr::one();
        FLRoundCircuit {
            prev_model_hash,
            round_id,
            new_model_hash,
            next_round_id,
            gradient_root_commit,
            norm_proof_commit,
            gradient_norm_scaled,
            client_count,
            norm_bound_scaled,
            poseidon_cfg,
        }
    }

    /// Compute the new model hash without building a full circuit instance.
    pub fn compute_new_hash(
        prev_model_hash:      Fr,
        gradient_norm_scaled: Fr,
        round_id:             Fr,
        gradient_root_commit: Fr,
        norm_proof_commit:    Fr,
    ) -> Fr {
        poseidon_hash_native(&[
            prev_model_hash,
            gradient_norm_scaled,
            round_id,
            gradient_root_commit,
            norm_proof_commit,
        ])
    }
}

// ─── R1CS ConstraintSynthesizer implementation ───────────────────────────────

impl ConstraintSynthesizer<Fr> for FLRoundCircuit {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<Fr>,
    ) -> Result<(), SynthesisError> {
        // ── Public inputs ──────────────────────────────────────────────────
        let prev_hash_var = FpVar::<Fr>::new_input(cs.clone(), || {
            Ok(self.prev_model_hash)
        })?;
        let round_id_var = FpVar::<Fr>::new_input(cs.clone(), || {
            Ok(self.round_id)
        })?;
        let new_hash_var = FpVar::<Fr>::new_input(cs.clone(), || {
            Ok(self.new_model_hash)
        })?;
        let next_round_id_var = FpVar::<Fr>::new_input(cs.clone(), || {
            Ok(self.next_round_id)
        })?;
        // Fix 3: gradient Merkle root commitment
        let gradient_root_var = FpVar::<Fr>::new_input(cs.clone(), || {
            Ok(self.gradient_root_commit)
        })?;
        // Fix 4: norm proof commitment
        let norm_commit_var = FpVar::<Fr>::new_input(cs.clone(), || {
            Ok(self.norm_proof_commit)
        })?;

        // ── Private witnesses ──────────────────────────────────────────────
        let norm_var = FpVar::<Fr>::new_witness(cs.clone(), || {
            Ok(self.gradient_norm_scaled)
        })?;
        let _client_count_var = FpVar::<Fr>::new_witness(cs.clone(), || {
            Ok(self.client_count)
        })?;

        // ── Constraint 1: round counter increments by exactly 1 ────────────
        let expected_next = &round_id_var + FpVar::constant(Fr::one());
        next_round_id_var.enforce_equal(&expected_next)?;

        // ── Constraint 2: gradient norm is within bound ────────────────────
        // diff = bound - norm ≥ 0.  If norm > bound, diff wraps to ~Fr::MAX
        // (255-bit number), which cannot be bit-decomposed into 64 bits.
        let bound_var = FpVar::constant(Fr::from(self.norm_bound_scaled));
        let diff_var = &bound_var - &norm_var;
        enforce_range_check(cs.clone(), &diff_var, 64)?;

        // ── Constraint 3: new_model_hash = Poseidon(prev, norm, round_id,
        //                                    gradient_root, norm_proof_commit)
        // Binding gradient content (root) and norm proof into the hash chain
        // ensures neither can be swapped after the proof is generated.
        let mut sponge = PoseidonSpongeVar::<Fr>::new(cs.clone(), &self.poseidon_cfg);
        sponge.absorb(&prev_hash_var)?;
        sponge.absorb(&norm_var)?;
        sponge.absorb(&round_id_var)?;
        sponge.absorb(&gradient_root_var)?;   // Fix 3
        sponge.absorb(&norm_commit_var)?;      // Fix 4
        let squeezed = sponge.squeeze_field_elements(1)?;
        new_hash_var.enforce_equal(&squeezed[0])?;

        Ok(())
    }
}

// ─── Range check gadget ──────────────────────────────────────────────────────

/// Enforce that `var` represents a value in [0, 2^num_bits).
fn enforce_range_check(
    cs: ConstraintSystemRef<Fr>,
    var: &FpVar<Fr>,
    num_bits: usize,
) -> Result<(), SynthesisError> {
    let val_bigint = var.value().unwrap_or(Fr::from(0u64)).into_bigint();
    let bits: Vec<bool> =
        (0..num_bits).map(|i| val_bigint.get_bit(i)).collect();

    let bit_vars: Vec<Boolean<Fr>> = bits
        .iter()
        .map(|&b| Boolean::new_witness(cs.clone(), || Ok(b)))
        .collect::<Result<_, _>>()?;

    let mut reconstructed = FpVar::constant(Fr::from(0u64));
    for (i, bit) in bit_vars.iter().enumerate() {
        let coeff = if i < 64 {
            Fr::from(2u64.pow(i as u32))
        } else {
            Fr::from(2u64.pow(63)) * Fr::from(2u64.pow((i - 63) as u32))
        };
        let term = bit.select(
            &FpVar::constant(coeff),
            &FpVar::constant(Fr::from(0u64)),
        )?;
        reconstructed += &term;
    }
    var.enforce_equal(&reconstructed)?;
    Ok(())
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::One;
    use ark_relations::r1cs::ConstraintSystem;

    #[test]
    fn test_fl_round_circuit_satisfiable() {
        let prev_hash           = Fr::from(12345678u64);
        let round_id            = Fr::from(0u64);
        let norm_scaled         = Fr::from(500_000u64); // 0.5 in fixed-point
        let client_count        = Fr::from(3u64);
        let norm_bound_scaled   = 1_000_000u64;          // bound = 1.0
        let gradient_root_commit = Fr::from(99999u64);   // fake root commitment
        let norm_proof_commit    = Fr::from(55555u64);   // fake norm-proof commitment

        let circuit = FLRoundCircuit::new(
            prev_hash,
            round_id,
            norm_scaled,
            client_count,
            norm_bound_scaled,
            gradient_root_commit,
            norm_proof_commit,
        );

        // Verify that native Poseidon matches.
        let expected = poseidon_hash_native(&[
            prev_hash, norm_scaled, round_id, gradient_root_commit, norm_proof_commit,
        ]);
        assert_eq!(circuit.new_model_hash, expected);

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        println!("FL Round Circuit: {} constraints", cs.num_constraints());
        assert!(cs.is_satisfied().unwrap(), "Constraints not satisfied");
    }

    #[test]
    fn test_poseidon_native_consistency() {
        let h1 = poseidon_hash_native(&[Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)]);
        let h2 = poseidon_hash_native(&[Fr::from(1u64), Fr::from(2u64), Fr::from(4u64)]);
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_gradient_root_commit_changes_hash() {
        let prev = Fr::from(1u64);
        let rid  = Fr::from(0u64);
        let norm = Fr::from(100u64);
        let cc   = Fr::from(3u64);
        let npc  = Fr::from(77u64);

        let c1 = FLRoundCircuit::new(prev, rid, norm, cc, 1_000_000, Fr::from(1u64), npc);
        let c2 = FLRoundCircuit::new(prev, rid, norm, cc, 1_000_000, Fr::from(2u64), npc);
        assert_ne!(c1.new_model_hash, c2.new_model_hash,
            "Different gradient roots must yield different model hashes");
    }

    #[test]
    fn test_norm_proof_commit_changes_hash() {
        let prev = Fr::from(1u64);
        let rid  = Fr::from(0u64);
        let norm = Fr::from(100u64);
        let cc   = Fr::from(3u64);
        let grc  = Fr::from(42u64);

        let c1 = FLRoundCircuit::new(prev, rid, norm, cc, 1_000_000, grc, Fr::from(1u64));
        let c2 = FLRoundCircuit::new(prev, rid, norm, cc, 1_000_000, grc, Fr::from(2u64));
        assert_ne!(c1.new_model_hash, c2.new_model_hash,
            "Different norm proof commits must yield different model hashes");
    }
}
