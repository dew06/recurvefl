// validators/round_contract.ak
// Main FL round state machine contract.
// Uses a thread token NFT to track the active round UTxO.
// Enforces phase transitions, real Groth16 pairing verification, and real BLS
// aggregate signature verification.
//
// ── Fixes in this version ──────────────────────────────────────────────────
//
// Fix 1 (Critical): Real Groth16 on-chain pairing verification.
//   FinalizeRound now calls groth16_verify(vk, A, B, C, public_inputs)
//   instead of the old blake2b hash check.  The VK supplied in the redeemer
//   is validated against datum.vk_hash (set at deployment time) so the prover
//   cannot substitute a freshly generated key.
//
// Fix 5 (Significant): norm_proof_hash enforced on-chain.
//   SubmitAggregation writes norm_proof_hash into datum.committed_norm_proof_hash.
//   FinalizeRound checks that datum.committed_norm_proof_hash is non-empty,
//   confirming a real norm proof was submitted before finalisation.
//   (Full binding to the Groth16 public input norm_proof_commit is enforced
//   off-chain by the verifier comparing CommitmentDatum.norm_proof_hash
//   against the circuit's norm_proof_commit field.)

use aiken/builtin
use aiken/collection/list
use aiken/crypto
use cardano/transaction.{ScriptContext, Transaction, Input, Output}
use cardano/assets.{PolicyId, AssetName, Value}
use cardano/interval.{Interval, Finite, PositiveInfinity}
use zkfl_cardano/types.{
  RoundDatum, RegistryDatum, RoundAction, RoundPhase,
  Registration, Training, Aggregation, Finalized,
  StartTraining, SubmitAggregation, FinalizeRound, AdvanceToNextRound,
}
use zkfl_cardano/bls_verify.{verify_bls_signature, aggregate_public_keys}
use groth16_verify.{groth16_verify, Groth16VK}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn must_be_signed_by(tx: Transaction, pkh: ByteArray) -> Bool {
  list.any(tx.extra_signatories, fn(signer) { signer == pkh })
}

fn find_thread_output(
  outputs: List<Output>,
  policy_id: ByteArray,
) -> Option<Output> {
  list.find(
    outputs,
    fn(o) { assets.quantity_of(o.value, policy_id, #"") > 0 },
  )
}

fn get_output_datum(output: Output) -> Option<RoundDatum> {
  when output.datum is {
    transaction.InlineDatum(d) -> {
      expect datum: RoundDatum = d
      Some(datum)
    }
    _ -> None
  }
}

fn deadline_not_exceeded(tx: Transaction, deadline: Int) -> Bool {
  when tx.validity_range.upper_bound.bound_type is {
    Finite(upper) -> upper <= deadline
    PositiveInfinity -> True
  }
}

// ── Registry helpers ──────────────────────────────────────────────────────────

// Extract a RegistryDatum from a reference input's inline datum.
fn get_registry_datum(input: Input) -> Option<RegistryDatum> {
  when input.output.datum is {
    transaction.InlineDatum(d) -> {
      // Try to interpret as RegistryDatum; fails gracefully if not.
      if builtin.length_of_bytearray(d) > 0 {
        expect reg: RegistryDatum = d
        Some(reg)
      } else {
        None
      }
    }
    _ -> None
  }
}

// Collect all BLS public keys from reference inputs that carry RegistryDatums.
fn collect_bls_keys_from_registry(
  reference_inputs: List<Input>,
) -> List<ByteArray> {
  list.filter_map(
    reference_inputs,
    fn(input) {
      when get_registry_datum(input) is {
        Some(reg) ->
          // bls_pub_key must be 96 bytes (compressed G2)
          if builtin.length_of_bytearray(reg.bls_pub_key) == 96 {
            Some(reg.bls_pub_key)
          } else {
            None
          }
        None -> None
      }
    },
  )
}

// ── Serialise a Groth16VK to bytes for hashing ────────────────────────────────
// We hash alpha || beta || gamma || delta || γ_abc[0] || γ_abc[1] || …
// This is a minimal canonical encoding; the coordinator must hash the VK
// using the same ordering when computing datum.vk_hash at deployment time.
fn vk_to_bytes(vk: Groth16VK) -> ByteArray {
  let abc_bytes =
    list.foldl(
      vk.gamma_abc,
      #"",
      fn(acc, pt) { builtin.append_bytearray(acc, pt) },
    )
  builtin.append_bytearray(
    builtin.append_bytearray(
      builtin.append_bytearray(
        builtin.append_bytearray(vk.alpha, vk.beta),
        vk.gamma,
      ),
      vk.delta,
    ),
    abc_bytes,
  )
}

// ── Validator ─────────────────────────────────────────────────────────────────

validator round_contract(thread_policy_id: ByteArray) {
  spend(
    datum: Option<RoundDatum>,
    redeemer: RoundAction,
    _own_ref: transaction.OutputReference,
    ctx: ScriptContext,
  ) {
    expect Some(d) = datum
    let tx = ctx.transaction
    expect Some(cont_output) = find_thread_output(tx.outputs, thread_policy_id)
    expect Some(cont_datum) = get_output_datum(cont_output)

    when redeemer is {
      // ── StartTraining ────────────────────────────────────────────────────
      StartTraining { participant_merkle_root, actual_count } -> {
        expect Registration = d.phase
        let enough_participants = actual_count >= d.min_participants
        let in_time = deadline_not_exceeded(tx, d.deadline)
        let valid_output =
          cont_datum.phase == Training
            && cont_datum.participant_root == participant_merkle_root
            && cont_datum.round_id == d.round_id
            && cont_datum.min_participants == d.min_participants
            && cont_datum.deadline == d.deadline
            && cont_datum.model_hash == d.model_hash
        enough_participants && in_time && valid_output
      }

      // ── SubmitAggregation ────────────────────────────────────────────────
      // Fix 5: norm_proof_hash is now recorded in the output datum so
      //        FinalizeRound can confirm a real norm proof was submitted.
      SubmitAggregation {
        new_model_hash,
        proof_hash,
        gradient_merkle_root,
        participant_count,
        norm_proof_hash,
      } -> {
        expect Training = d.phase
        let non_empty_root =
          builtin.length_of_bytearray(gradient_merkle_root) > 0
        let valid_count = participant_count >= d.min_participants
        // Fix 5: norm proof hash must be non-empty.
        let norm_proof_present =
          builtin.length_of_bytearray(norm_proof_hash) > 0
        let valid_output =
          cont_datum.phase == Aggregation
            && cont_datum.committed_hashes == gradient_merkle_root
            && cont_datum.model_hash == new_model_hash
            && cont_datum.aggregated_proof_hash == proof_hash
            && cont_datum.round_id == d.round_id
            && cont_datum.participant_root == d.participant_root
            // Fix 5: write norm_proof_hash into the continuing datum.
            && cont_datum.committed_norm_proof_hash == norm_proof_hash
        non_empty_root && valid_count && norm_proof_present && valid_output
      }

      // ── FinalizeRound ────────────────────────────────────────────────────
      //
      // Fix 1 (Critical): Real Groth16 on-chain pairing verification.
      //   The VK supplied in the redeemer is hashed and checked against
      //   datum.vk_hash.  Then groth16_verify is called with the full 6
      //   public inputs in the order the Rust circuit produces them:
      //     [prev_model_hash, round_id, new_model_hash, next_round_id,
      //      gradient_root_commit, norm_proof_commit]
      //
      // Fix 5 (Significant): Check that a norm proof was committed before
      //   this round was allowed to progress to Aggregation.
      //
      FinalizeRound {
        groth16_proof_a,
        groth16_proof_b,
        groth16_proof_c,
        groth16_vk,
        aggregated_bls_sig,
        aggregated_bls_pub_key,
        new_model_hash,
        new_round_id,
      } -> {
        expect Aggregation = d.phase

        // ── Fix 1a: Validate the supplied VK against the pinned hash ──────
        // datum.vk_hash was set at deployment time (or in the genesis tx).
        // We hash alpha||beta||gamma||delta||γ_abc[…] and compare.
        let vk_bytes = vk_to_bytes(groth16_vk)
        let computed_vk_hash = crypto.blake2b_256(vk_bytes)
        let vk_hash_ok = computed_vk_hash == d.vk_hash

        // ── Fix 5: Confirm norm proof was submitted ────────────────────────
        // datum.committed_norm_proof_hash was written by SubmitAggregation.
        // We just require it is non-empty here; deeper binding (to the
        // Groth16 norm_proof_commit public input) is checked off-chain.
        let norm_proof_committed =
          builtin.length_of_bytearray(d.committed_norm_proof_hash) > 0

        // ── Fix 1b: Build Groth16 public inputs ───────────────────────────
        // Order must exactly match FLRoundCircuit::generate_constraints:
        //   [prev_model_hash, round_id, new_model_hash, next_round_id,
        //    gradient_root_commit, norm_proof_commit]
        //
        // prev_model_hash = d.model_hash  (model hash before this round)
        // round_id        = d.round_id    (as big-endian 32-byte encoding)
        // new_model_hash  = new_model_hash (supplied by coordinator)
        // next_round_id   = new_round_id
        // gradient_root_commit = d.committed_hashes (gradient Merkle root)
        // norm_proof_commit    = d.committed_norm_proof_hash
        //
        // Field elements are encoded as 32-byte big-endian ByteArrays for the
        // groth16_verify scalar-mul helper.
        let public_inputs: List<ByteArray> = [
          d.model_hash,
          // prev_model_hash (Fr LE bytes from Rust, 32 bytes)
          builtin.integer_to_bytearray(True, 32, d.round_id),
          // round_id (big-endian 32 bytes)
          new_model_hash,
          // new_model_hash (Fr LE bytes from Rust, 32 bytes)
          builtin.integer_to_bytearray(True, 32, new_round_id),
          // next_round_id (big-endian 32 bytes)
          d.committed_hashes,
          // gradient_root_commit (Fr LE bytes from Rust, 32 bytes)
          d.committed_norm_proof_hash,
          // norm_proof_commit (Fr LE bytes from Rust, 32 bytes)
        ]

        // ── Fix 1c: Full Groth16 pairing check ────────────────────────────
        let groth16_ok =
          groth16_verify(
            groth16_vk,
            groth16_proof_a,
            groth16_proof_b,
            groth16_proof_c,
            public_inputs,
          )

        // ── 2. Collect BLS pubkeys from reference inputs ──────────────────
        let registry_keys =
          collect_bls_keys_from_registry(tx.reference_inputs)
        let enough_keys = list.length(registry_keys) >= d.min_participants

        // ── 3. Compute aggregate pubkey on-chain and compare ─────────────
        let on_chain_agg_pk = aggregate_public_keys(registry_keys)
        let agg_pk_matches = on_chain_agg_pk == aggregated_bls_pub_key

        // ── 4. Verify BLS aggregate signature ────────────────────────────
        let bls_ok =
          verify_bls_signature(
            new_model_hash,
            aggregated_bls_sig,
            aggregated_bls_pub_key,
          )

        // ── 5. Output datum correctness ───────────────────────────────────
        let valid_output =
          cont_datum.phase == Finalized
            && cont_datum.round_id == new_round_id
            && cont_datum.model_hash == new_model_hash
            && new_round_id == d.round_id + 1

        vk_hash_ok && norm_proof_committed && groth16_ok
          && enough_keys && agg_pk_matches && bls_ok && valid_output
      }

      // ── AdvanceToNextRound ───────────────────────────────────────────────
      AdvanceToNextRound -> {
        expect Finalized = d.phase
        let valid_output =
          cont_datum.phase == Registration
            && cont_datum.round_id == d.round_id + 1
            && cont_datum.participant_root == #""
            && cont_datum.committed_hashes == #""
            && cont_datum.aggregated_proof_hash == #""
            && cont_datum.committed_norm_proof_hash == #""
        valid_output
      }
    }
  }

  else(_) {
    fail
  }
}
