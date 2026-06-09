// lib/types.ak
// Shared types for the Recursive Verifiable Federated Learning system

use groth16_verify.{Groth16VK}

// FL Round phases
pub type RoundPhase {
  Registration
  Training
  Aggregation
  Finalized
}

// Main round datum
pub type RoundDatum {
  round_id: Int,
  phase: RoundPhase,
  deadline: Int,
  // POSIXTime (milliseconds)
  min_participants: Int,
  participant_root: ByteArray,
  // 32-byte Merkle root of participant PKHs
  committed_hashes: ByteArray,
  // 32-byte Merkle root of gradient update hashes
  aggregated_proof_hash: ByteArray,
  // SHA256 of the Groth16 ZK proof bytes (A||B||C)
  model_hash: ByteArray,
  // SHA256 of current global model weights
  total_stake_weight: Int,
  // ── Fix 1: pinned VK hash ─────────────────────────────────────────────────
  // blake2b_256 of the serialised Groth16 verification key.
  // Set during contract deployment; every FinalizeRound call checks that
  // the supplied VK hashes to this value — the prover cannot use a fresh VK.
  vk_hash: ByteArray,
  // ── Fix 5: committed norm-proof hash ──────────────────────────────────────
  // blake2b_256 of the aggregated norm proof, set during SubmitAggregation.
  // FinalizeRound enforces that the Groth16 public input norm_proof_commit
  // was derived from data matching this hash.  Stored here so the verifier
  // does not need to walk reference inputs at finalization time.
  committed_norm_proof_hash: ByteArray,
}

// Participant commitment datum (for inbox UTxOs)
pub type CommitmentDatum {
  client_pkh: ByteArray,
  round_id: Int,
  gradient_hash: ByteArray,
  // SHA256(gradient_update || round_id || client_pk)
  norm_proof_hash: ByteArray,
  // SHA256 of the norm proof
}

// Registry entry datum
pub type RegistryDatum {
  participant_pkh: ByteArray,
  bls_pub_key: ByteArray,
  // BLS12-381 G2 public key (96 bytes compressed)
  stake_weight: Int,
  registered_at: Int,
}

// Round redeemer actions
pub type RoundAction {
  StartTraining { participant_merkle_root: ByteArray, actual_count: Int }
  SubmitAggregation {
    new_model_hash: ByteArray,
    proof_hash: ByteArray,
    gradient_merkle_root: ByteArray,
    participant_count: Int,
    // ── Fix 5: submit the aggregated norm-proof hash so it lands in the datum
    norm_proof_hash: ByteArray,
  }
  FinalizeRound {
    groth16_proof_a: ByteArray,
    // G1 point, 48 bytes compressed
    groth16_proof_b: ByteArray,
    // G2 point, 96 bytes compressed
    groth16_proof_c: ByteArray,
    // G1 point, 48 bytes compressed
    // ── Fix 1: full VK supplied by coordinator ───────────────────────────────
    // The contract hashes this VK and checks it against datum.vk_hash to
    // ensure the correct, pre-committed verification key is used.
    groth16_vk: Groth16VK,
    aggregated_bls_sig: ByteArray,
    // Aggregated BLS G1 signature over new_model_hash
    aggregated_bls_pub_key: ByteArray,
    // Aggregated BLS G2 public key: sum of all registered participants' BLS keys.
    new_model_hash: ByteArray,
    new_round_id: Int,
  }
  AdvanceToNextRound
}
