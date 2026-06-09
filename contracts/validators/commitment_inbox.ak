// validators/commitment_inbox.ak
// Participants submit gradient commitments here during Training phase.
// Each participant locks a small amount with their CommitmentDatum.
// Aggregator batch-collects these when submitting aggregation.
//
// Spending is allowed if:
//   1. The round contract UTxO is being spent in the same tx (batch collection), OR
//   2. The participant signed AND the deadline has exceeded (reclaim)

use aiken/builtin
use aiken/collection/list
use cardano/transaction.{ScriptContext, Transaction, Input, Output}
use cardano/address.{Address, Script}
use zkfl_cardano/types.{CommitmentDatum}

// Check if the transaction is signed by a given pub key hash
fn must_be_signed_by(tx: Transaction, pkh: ByteArray) -> Bool {
  list.any(tx.extra_signatories, fn(signer) { signer == pkh })
}

// Check if the round contract address is being spent in this transaction
// round_contract_addr is the 28-byte script hash of the round contract
fn any_input_from_script(tx: Transaction, script_hash: ByteArray) -> Bool {
  list.any(
    tx.inputs,
    fn(inp) {
      when inp.output.address.payment_credential is {
        Script(hash) -> hash == script_hash
        _ -> False
      }
    },
  )
}

validator commitment_inbox(round_contract_hash: ByteArray) {
  spend(
    datum: Option<CommitmentDatum>,
    _redeemer: Data,
    _own_ref: transaction.OutputReference,
    ctx: ScriptContext,
  ) {
    expect Some(d) = datum
    let tx = ctx.transaction

    // Path 1: batch collection by aggregator — round contract is being spent
    let is_batch_collect = any_input_from_script(tx, round_contract_hash)

    // Path 2: participant reclaims their own commitment (requires their signature)
    let participant_reclaim = must_be_signed_by(tx, d.client_pkh)

    is_batch_collect || participant_reclaim
  }

  else(_) {
    fail
  }
}
