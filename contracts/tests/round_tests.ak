// tests/round_tests.ak
// Unit tests for the FL round contract phase-transition logic.
// These tests exercise the datum / redeemer validation rules independently
// of the full validator context so they can run with `aiken check`.

use aiken/builtin
use aiken/collection/list
use zkfl_cardano/types.{
  RoundDatum, RoundAction, RoundPhase,
  Registration, Training, Aggregation, Finalized,
  StartTraining, SubmitAggregation, FinalizeRound, AdvanceToNextRound,
}

// ──────────────────────────────────────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────────────────────────────────────

fn make_registration_datum() -> RoundDatum {
  RoundDatum {
    round_id: 1,
    phase: Registration,
    deadline: 1_700_000_000_000,
    min_participants: 3,
    participant_root: #"",
    committed_hashes: #"",
    aggregated_proof_hash: #"",
    model_hash: #"deadbeef",
    total_stake_weight: 0,
  }
}

fn make_training_datum() -> RoundDatum {
  RoundDatum {
    round_id: 1,
    phase: Training,
    deadline: 1_700_000_000_000,
    min_participants: 3,
    participant_root: #"aabbccdd",
    committed_hashes: #"",
    aggregated_proof_hash: #"",
    model_hash: #"deadbeef",
    total_stake_weight: 0,
  }
}

fn make_aggregation_datum() -> RoundDatum {
  RoundDatum {
    round_id: 1,
    phase: Aggregation,
    deadline: 1_700_000_000_000,
    min_participants: 3,
    participant_root: #"aabbccdd",
    committed_hashes: #"cafebabe",
    aggregated_proof_hash: #"00112233",
    model_hash: #"deadbeef",
    total_stake_weight: 0,
  }
}

fn make_finalized_datum(new_round_id: Int) -> RoundDatum {
  RoundDatum {
    round_id: new_round_id,
    phase: Finalized,
    deadline: 1_700_000_000_000,
    min_participants: 3,
    participant_root: #"aabbccdd",
    committed_hashes: #"cafebabe",
    aggregated_proof_hash: #"00112233",
    model_hash: #"1234abcd",
    total_stake_weight: 0,
  }
}

// ──────────────────────────────────────────────────────────────────────────────
// Phase-guard helpers (mirror validator logic without full ScriptContext)
// ──────────────────────────────────────────────────────────────────────────────

fn check_start_training(
  datum: RoundDatum,
  participant_merkle_root: ByteArray,
  actual_count: Int,
  output_datum: RoundDatum,
) -> Bool {
  // Guard
  let phase_ok =
    when datum.phase is {
      Registration -> True
      _ -> False
    }
  let enough = actual_count >= datum.min_participants
  let output_ok =
    output_datum.phase == Training && output_datum.participant_root == participant_merkle_root && output_datum.round_id == datum.round_id && output_datum.model_hash == datum.model_hash
  phase_ok && enough && output_ok
}

fn check_submit_aggregation(
  datum: RoundDatum,
  new_model_hash: ByteArray,
  proof_hash: ByteArray,
  gradient_merkle_root: ByteArray,
  participant_count: Int,
  output_datum: RoundDatum,
) -> Bool {
  let phase_ok =
    when datum.phase is {
      Training -> True
      _ -> False
    }
  let non_empty = builtin.length_of_bytearray(gradient_merkle_root) > 0
  let valid_count = participant_count >= datum.min_participants
  let output_ok =
    output_datum.phase == Aggregation && output_datum.committed_hashes == gradient_merkle_root && output_datum.model_hash == new_model_hash && output_datum.aggregated_proof_hash == proof_hash && output_datum.round_id == datum.round_id
  phase_ok && non_empty && valid_count && output_ok
}

fn check_advance_to_next_round(
  datum: RoundDatum,
  output_datum: RoundDatum,
) -> Bool {
  let phase_ok =
    when datum.phase is {
      Finalized -> True
      _ -> False
    }
  let output_ok =
    output_datum.phase == Registration && output_datum.round_id == datum.round_id + 1 && output_datum.participant_root == #"" && output_datum.committed_hashes == #"" && output_datum.aggregated_proof_hash == #""
  phase_ok && output_ok
}

// ──────────────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────────────

test test_registration_to_training_transition() {
  let datum = make_registration_datum()
  let participant_root = #"aabbccdd"
  let actual_count = 4

  // Simulate the expected output datum after StartTraining
  let output_datum =
    RoundDatum {
      ..datum,
      phase: Training,
      participant_root: participant_root,
    }

  check_start_training(datum, participant_root, actual_count, output_datum)
}

test test_training_to_aggregation_transition() {
  let datum = make_training_datum()
  let new_model_hash = #"1234abcd"
  let proof_hash = #"00112233"
  let gradient_root = #"cafebabe"
  let participant_count = 4

  // Simulate the expected output datum after SubmitAggregation
  let output_datum =
    RoundDatum {
      ..datum,
      phase: Aggregation,
      model_hash: new_model_hash,
      aggregated_proof_hash: proof_hash,
      committed_hashes: gradient_root,
    }

  check_submit_aggregation(
    datum,
    new_model_hash,
    proof_hash,
    gradient_root,
    participant_count,
    output_datum,
  )
}

test test_advance_to_next_round() {
  let datum = make_finalized_datum(2)
  let output_datum =
    RoundDatum {
      round_id: 3,
      phase: Registration,
      deadline: datum.deadline,
      min_participants: datum.min_participants,
      participant_root: #"",
      committed_hashes: #"",
      aggregated_proof_hash: #"",
      model_hash: datum.model_hash,
      total_stake_weight: 0,
    }
  check_advance_to_next_round(datum, output_datum)
}

test test_start_training_fails_with_wrong_phase() {
  // datum is already in Training — StartTraining should fail
  let datum = make_training_datum()
  let output_datum =
    RoundDatum { ..datum, phase: Training, participant_root: #"aabb" }
  !check_start_training(datum, #"aabb", 4, output_datum)
}

test test_start_training_fails_with_insufficient_participants() {
  let datum = make_registration_datum()
  let output_datum =
    RoundDatum { ..datum, phase: Training, participant_root: #"aabb" }
  // Only 2 participants, min is 3
  !check_start_training(datum, #"aabb", 2, output_datum)
}

test test_aggregation_fails_with_empty_root() {
  let datum = make_training_datum()
  let output_datum =
    RoundDatum {
      ..datum,
      phase: Aggregation,
      committed_hashes: #"",
      model_hash: #"new",
      aggregated_proof_hash: #"hash",
    }
  // Empty gradient root should fail
  !check_submit_aggregation(datum, #"new", #"hash", #"", 4, output_datum)
}
