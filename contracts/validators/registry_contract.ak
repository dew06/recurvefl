// validators/registry_contract.ak
// Manages participant registration for the FL system.
// Each participant locks a small ADA deposit and registers their BLS pubkey.
// Multiple participants can register simultaneously (separate UTxOs).
// Registration: send ADA to this script address with a RegistryDatum.
// Deregistration: must be signed by the registered participant.

use aiken/builtin
use aiken/collection/list
use cardano/transaction.{ScriptContext, Transaction, Input}
use zkfl_cardano/types.{RegistryDatum}

// Check if the transaction is signed by a given pub key hash
fn must_be_signed_by(tx: Transaction, pkh: ByteArray) -> Bool {
  list.any(tx.extra_signatories, fn(signer) { signer == pkh })
}

validator registry_contract {
  spend(
    datum: Option<RegistryDatum>,
    _redeemer: Data,
    _own_ref: transaction.OutputReference,
    ctx: ScriptContext,
  ) {
    // Registration is done by simply sending ADA to this address with RegistryDatum.
    // Spending (deregistration) requires the participant's signature.
    expect Some(d) = datum
    let tx = ctx.transaction
    must_be_signed_by(tx, d.participant_pkh)
  }

  else(_) {
    fail
  }
}
