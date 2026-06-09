//! FL Round Prover — Groth16 prove/verify for one FL round.
//!
//! ## Changes in this version
//!
//! The circuit now has 6 public inputs instead of 4:
//!   [prev_model_hash, round_id, new_model_hash, next_round_id,
//!    gradient_root_commit, norm_proof_commit]
//!
//! `gradient_root_commit` = Poseidon(gradient_merkle_root_bytes)
//!   Fixes Critical 3: the aggregated gradient content is committed into the
//!   Groth16 proof, so the coordinator cannot swap gradients post-proof.
//!
//! `norm_proof_commit` = Poseidon(norm_proof_json_bytes)
//!   Fixes Significant 4: the Bulletproof norm proof is cryptographically
//!   linked to the round circuit.  The on-chain verifier checks this field
//!   against the CommitmentDatum.norm_proof_hash.

use std::path::Path;

use ark_bn254::{Bn254, Fr};
use ark_ff::PrimeField;
use ark_groth16::{
    prepare_verifying_key, Groth16, PreparedVerifyingKey, ProvingKey,
    VerifyingKey,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_snark::SNARK;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::fl_round_circuit::{
    bytes_to_field_commitment, gradient_root_to_fr, norm_proof_commitment,
    poseidon_config, FLRoundCircuit, FIXED_POINT_SCALE,
};

// ─── Public Types ─────────────────────────────────────────────────────────────

/// Serialisable bundle containing a Groth16 proof for one FL round.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FLProof {
    pub round_id:           u64,
    /// Model hash from the prior round (Fr LE bytes, hex).
    pub prev_model_hash:    String,
    /// Model hash after this round (Fr LE bytes, hex).
    pub new_model_hash:     String,
    pub gradient_norm_bound: f64,
    pub client_count:       u32,
    /// Groth16 proof bytes (hex, ark-serialize compressed).
    pub proof_bytes:        String,
    /// Groth16 verification key (hex, ark-serialize compressed).
    pub vk_bytes:           String,
    // ── New fields for Fix 3 & 4 ─────────────────────────────────────────
    /// Poseidon commitment of the gradient Merkle root (Fix 3).
    /// Hex-encoded Fr bytes.
    pub gradient_root_commit: String,
    /// Poseidon commitment of the norm proof bytes (Fix 4).
    /// Hex-encoded Fr bytes.  Verifier uses this to confirm the norm proof
    /// that was submitted off-chain matches the one committed in this proof.
    pub norm_proof_commit:    String,
}

// ─── FLRoundProver ────────────────────────────────────────────────────────────

pub struct FLRoundProver {
    pk:                ProvingKey<Bn254>,
    vk:                VerifyingKey<Bn254>,
    #[allow(dead_code)]
    pvk:               PreparedVerifyingKey<Bn254>,
    pub norm_bound_scaled: u64,
}

impl FLRoundProver {
    // ── Key generation ────────────────────────────────────────────────────

    /// Generate a fresh Groth16 SRS using the OS random number generator.
    pub fn setup(norm_bound: f64) -> Result<Self, String> {
        let norm_bound_scaled = (norm_bound * FIXED_POINT_SCALE as f64) as u64;
        let blank = FLRoundCircuit::new(
            Fr::from(0u64), Fr::from(0u64),
            Fr::from(0u64), Fr::from(1u64),
            norm_bound_scaled,
            Fr::from(0u64), Fr::from(0u64),
        );
        let mut rng = OsRng;
        let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(blank, &mut rng)
            .map_err(|e| format!("Groth16 setup: {:?}", e))?;
        let pvk = prepare_verifying_key(&vk);
        Ok(FLRoundProver { pk, vk, pvk, norm_bound_scaled })
    }

    pub fn save_keys(&self, pk_path: &Path, vk_path: &Path) -> Result<(), String> {
        let mut pk_buf = Vec::new();
        self.pk.serialize_compressed(&mut pk_buf)
            .map_err(|e| format!("PK serialize: {:?}", e))?;
        std::fs::write(pk_path, &pk_buf)
            .map_err(|e| format!("PK write {:?}: {}", pk_path, e))?;

        let mut vk_buf = Vec::new();
        self.vk.serialize_compressed(&mut vk_buf)
            .map_err(|e| format!("VK serialize: {:?}", e))?;
        std::fs::write(vk_path, &vk_buf)
            .map_err(|e| format!("VK write {:?}: {}", vk_path, e))?;
        Ok(())
    }

    pub fn load_keys(pk_path: &Path, vk_path: &Path, norm_bound: f64) -> Result<Self, String> {
        let pk_bytes = std::fs::read(pk_path)
            .map_err(|e| format!("PK read {:?}: {}", pk_path, e))?;
        let pk = ProvingKey::<Bn254>::deserialize_compressed(pk_bytes.as_slice())
            .map_err(|e| format!("PK deserialize: {:?}", e))?;
        let vk_bytes = std::fs::read(vk_path)
            .map_err(|e| format!("VK read {:?}: {}", vk_path, e))?;
        let vk = VerifyingKey::<Bn254>::deserialize_compressed(vk_bytes.as_slice())
            .map_err(|e| format!("VK deserialize: {:?}", e))?;
        let pvk = prepare_verifying_key(&vk);
        let norm_bound_scaled = (norm_bound * FIXED_POINT_SCALE as f64) as u64;
        Ok(FLRoundProver { pk, vk, pvk, norm_bound_scaled })
    }

    // ── Proving ───────────────────────────────────────────────────────────

    /// Prove one FL round.
    ///
    /// # New parameters (Fix 3 & 4)
    ///
    /// * `gradient_root_bytes` — raw bytes of the gradient Merkle root
    ///   (e.g. SHA-256 of all client gradient hashes).  The coordinator
    ///   builds this before calling `prove_round`.
    ///
    /// * `norm_proof_bytes` — serialised NormProof JSON bytes for the
    ///   aggregated gradient.  Pass `serde_json::to_vec(&norm_proof).unwrap()`.
    pub fn prove_round(
        &self,
        round_id:           u64,
        prev_hash_fr:       Fr,
        gradients:          &[f64],
        gradient_norm_bound: f64,
        client_count:       u32,
        gradient_root_bytes: &[u8],
        norm_proof_bytes:   &[u8],
    ) -> Result<FLProof, String> {
        // Compute L2-norm and scale.
        let l2_norm: f64 = gradients.iter().map(|g| g * g).sum::<f64>().sqrt();
        let norm_scaled = (l2_norm * FIXED_POINT_SCALE as f64) as u64;
        if norm_scaled > self.norm_bound_scaled {
            return Err(format!(
                "Gradient L2-norm {:.6} exceeds bound {:.6}",
                l2_norm, gradient_norm_bound
            ));
        }

        // Compute commitments for the two new public inputs.
        let gradient_root_commit = gradient_root_to_fr(gradient_root_bytes);
        let norm_proof_commit    = norm_proof_commitment(norm_proof_bytes);

        let circuit = FLRoundCircuit::new(
            prev_hash_fr,
            Fr::from(round_id),
            Fr::from(norm_scaled),
            Fr::from(client_count as u64),
            self.norm_bound_scaled,
            gradient_root_commit,
            norm_proof_commit,
        );

        let new_hash_fr    = circuit.new_model_hash;
        let prev_hash_bytes = fr_to_bytes(&prev_hash_fr);
        let new_hash_bytes  = fr_to_bytes(&new_hash_fr);

        let mut rng = OsRng;
        let proof = Groth16::<Bn254>::prove(&self.pk, circuit, &mut rng)
            .map_err(|e| format!("Groth16 prove: {:?}", e))?;

        Ok(FLProof {
            round_id,
            prev_model_hash:    hex::encode(&prev_hash_bytes),
            new_model_hash:     hex::encode(&new_hash_bytes),
            gradient_norm_bound,
            client_count,
            proof_bytes:        hex::encode(serialize_proof(&proof)?),
            vk_bytes:           hex::encode(serialize_vk(&self.vk)?),
            gradient_root_commit: hex::encode(fr_to_bytes(&gradient_root_commit)),
            norm_proof_commit:    hex::encode(fr_to_bytes(&norm_proof_commit)),
        })
    }

    // ── Verification ──────────────────────────────────────────────────────

    /// Verify a [`FLProof`] using the VK embedded in the proof.
    ///
    /// Reconstructs all 6 public inputs from the proof's fields.
    pub fn verify_proof(fl_proof: &FLProof) -> Result<bool, String> {
        let vk_bytes = hex::decode(&fl_proof.vk_bytes)
            .map_err(|e| format!("VK hex: {}", e))?;
        let vk = VerifyingKey::<Bn254>::deserialize_compressed(vk_bytes.as_slice())
            .map_err(|e| format!("VK deser: {:?}", e))?;
        let pvk = prepare_verifying_key(&vk);

        let proof_bytes = hex::decode(&fl_proof.proof_bytes)
            .map_err(|e| format!("proof hex: {}", e))?;
        let proof = ark_groth16::Proof::<Bn254>::deserialize_compressed(proof_bytes.as_slice())
            .map_err(|e| format!("proof deser: {:?}", e))?;

        // Reconstruct all 6 public inputs (must match generate_constraints order).
        let prev_hash_fr = fr_from_hex(&fl_proof.prev_model_hash, "prev_model_hash")?;
        let round_id_fr  = Fr::from(fl_proof.round_id);
        let new_hash_fr  = fr_from_hex(&fl_proof.new_model_hash, "new_model_hash")?;
        let next_round_id_fr     = Fr::from(fl_proof.round_id + 1);
        let gradient_root_commit = fr_from_hex(&fl_proof.gradient_root_commit, "gradient_root_commit")?;
        let norm_proof_commit    = fr_from_hex(&fl_proof.norm_proof_commit, "norm_proof_commit")?;

        let public_inputs = vec![
            prev_hash_fr,
            round_id_fr,
            new_hash_fr,
            next_round_id_fr,
            gradient_root_commit,
            norm_proof_commit,
        ];

        Groth16::<Bn254>::verify_with_processed_vk(&pvk, &public_inputs, &proof)
            .map_err(|e| format!("Groth16 verify: {:?}", e))
    }

    pub fn export_vk_hex(&self) -> Result<String, String> {
        Ok(hex::encode(serialize_vk(&self.vk)?))
    }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

fn serialize_proof(proof: &ark_groth16::Proof<Bn254>) -> Result<Vec<u8>, String> {
    let mut buf = Vec::new();
    proof.serialize_compressed(&mut buf)
        .map_err(|e| format!("proof serialize: {:?}", e))?;
    Ok(buf)
}

fn serialize_vk(vk: &VerifyingKey<Bn254>) -> Result<Vec<u8>, String> {
    let mut buf = Vec::new();
    vk.serialize_compressed(&mut buf)
        .map_err(|e| format!("vk serialize: {:?}", e))?;
    Ok(buf)
}

/// Deserialise an Fr from a hex string (Fr LE bytes from fr_to_bytes).
fn fr_from_hex(hex_str: &str, field: &str) -> Result<Fr, String> {
    let bytes = hex::decode(hex_str)
        .map_err(|e| format!("{} hex: {}", field, e))?;
    Fr::deserialize_compressed(bytes.as_slice())
        .map_err(|e| format!("{} Fr deser: {:?}", field, e))
}

/// Map an Fr field element → 32 little-endian bytes (canonical form).
pub fn fr_to_bytes(fr: &Fr) -> Vec<u8> {
    let mut buf = Vec::new();
    fr.serialize_compressed(&mut buf).unwrap();
    buf
}

/// Map arbitrary bytes → Fr via SHA-256 reduction (for external hashes).
pub fn bytes_to_fr(bytes: &[u8]) -> Fr {
    let hash = Sha256::digest(bytes);
    let mut reduced = [0u8; 32];
    reduced[1..].copy_from_slice(&hash[1..]);
    Fr::from_be_bytes_mod_order(&reduced)
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_gradient_root() -> Vec<u8> {
        b"gradient_merkle_root_bytes_dummy".to_vec()
    }

    fn dummy_norm_proof() -> Vec<u8> {
        b"norm_proof_json_bytes_dummy".to_vec()
    }

    #[test]
    fn test_round_prove_verify() {
        let norm_bound = 1.0_f64;
        let prover = FLRoundProver::setup(norm_bound).expect("setup");
        let prev_hash_fr = Fr::from(0u64);
        let gradients    = vec![0.1_f64, -0.2, 0.05, -0.1, 0.15];

        let fl_proof = prover.prove_round(
            0, prev_hash_fr, &gradients, norm_bound, 5,
            &dummy_gradient_root(), &dummy_norm_proof(),
        ).expect("prove_round");

        assert!(FLRoundProver::verify_proof(&fl_proof).expect("verify"));
    }

    #[test]
    fn test_pk_persist_roundtrip() {
        use std::path::PathBuf;
        let dir      = std::env::temp_dir();
        let pk_path  = dir.join("test_pk.bin");
        let vk_path  = dir.join("test_vk.bin");
        let norm_bound = 1.0_f64;

        let prover = FLRoundProver::setup(norm_bound).expect("setup");
        prover.save_keys(&pk_path, &vk_path).expect("save_keys");

        let loaded = FLRoundProver::load_keys(&pk_path, &vk_path, norm_bound)
            .expect("load_keys");
        let fl_proof = loaded.prove_round(
            1, Fr::from(42u64), &[0.05, -0.1, 0.08], norm_bound, 3,
            &dummy_gradient_root(), &dummy_norm_proof(),
        ).expect("prove_round after load");

        assert!(FLRoundProver::verify_proof(&fl_proof).expect("verify loaded"));
        let _ = std::fs::remove_file(&pk_path);
        let _ = std::fs::remove_file(&vk_path);
    }

    #[test]
    fn test_different_gradient_roots_give_different_proofs() {
        let norm_bound = 1.0_f64;
        let prover     = FLRoundProver::setup(norm_bound).expect("setup");
        let gradients  = vec![0.1, 0.2, 0.05];

        let p1 = prover.prove_round(
            0, Fr::from(0u64), &gradients, norm_bound, 3,
            b"root_A", b"norm_proof_bytes",
        ).expect("p1");
        let p2 = prover.prove_round(
            0, Fr::from(0u64), &gradients, norm_bound, 3,
            b"root_B", b"norm_proof_bytes",
        ).expect("p2");

        // Different roots → different model hashes (gradient content is bound).
        assert_ne!(p1.new_model_hash, p2.new_model_hash,
            "Different gradient roots must produce different model hashes");
        assert!(FLRoundProver::verify_proof(&p1).expect("verify p1"));
        assert!(FLRoundProver::verify_proof(&p2).expect("verify p2"));
    }
}
