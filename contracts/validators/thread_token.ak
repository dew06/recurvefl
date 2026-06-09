// validators/thread_token.ak
// One-shot minting policy: mints exactly 1 NFT tied to a specific UTxO reference.
// This NFT tracks the "active" round state UTxO throughout its lifetime.
// The UTxO reference must be consumed in the minting transaction to ensure
// the policy can only fire once (one-shot guarantee).

use aiken/collection/list
use aiken/builtin
use cardano/transaction.{ScriptContext, Transaction, Input, OutputReference}
use cardano/assets

validator thread_token(utxo_ref: OutputReference) {
  mint(
    _redeemer: Data,
    policy_id: ByteArray,
    ctx: ScriptContext,
  ) {
    let tx = ctx.transaction

    // 1. The specified UTxO must be consumed in this transaction
    let consumed =
      list.any(
        tx.inputs,
        fn(inp) { inp.output_reference == utxo_ref },
      )

    // 2. Must mint exactly 1 token with empty asset name under this policy
    let minted_qty = assets.quantity_of(tx.mint, policy_id, #"")
    let exact_one = minted_qty == 1

    consumed && exact_one
  }

  else(_) {
    fail
  }
}
