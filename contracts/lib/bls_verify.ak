// lib/bls_verify.ak
// Helper module for BLS12-381 signature verification.
// Uses CIP-0381 built-in functions available on Cardano (Conway era).
//
// BLS signature scheme (minimal-pubkey-size):
//   - Signatures are G1 points (48 bytes compressed)
//   - Public keys are G2 points (96 bytes compressed)
//   - Message is hashed to a G1 point via hash-to-curve
//
// Verification equation:
//   e(sig, G2_gen) == e(H(msg), pk)
// Equivalently (batch-friendly):
//   e(sig, G2_gen) * e(-H(msg), pk) == GT_one

use aiken/builtin
use aiken/collection/list

// ──────────────────────────────────────────────────────────────────────────────
// verify_bls_signature
//
// Verify a BLS12-381 signature in the minimal-pubkey-size setting.
//
// Parameters:
//   message          – raw bytes to verify (will be hashed to G1)
//   aggregated_sig   – compressed G1 point (48 bytes)
//   aggregated_pub_key – compressed G2 point (96 bytes)
//
// Returns True iff the signature is valid.
// ──────────────────────────────────────────────────────────────────────────────
pub fn verify_bls_signature(
  message: ByteArray,
  aggregated_sig: ByteArray,
  aggregated_pub_key: ByteArray,
) -> Bool {
  // Decompress points
  let sig_g1 = builtin.bls12_381_g1_uncompress(aggregated_sig)
  let pk_g2 = builtin.bls12_381_g2_uncompress(aggregated_pub_key)

  // Hash message to G1 using the agreed domain-separation tag
  let dst = "fl-round-v1"
  let msg_g1 = builtin.bls12_381_g1_hash_to_group(message, dst)

  // G2 generator (fixed well-known point)
  let g2_gen = builtin.bls12_381_g2_generator()

  // LHS: e(sig, G2_gen)
  let lhs = builtin.bls12_381_miller_loop(sig_g1, g2_gen)

  // RHS: e(-H(msg), pk)  →  negate the G1 hash point
  let neg_msg = builtin.bls12_381_g1_neg(msg_g1)
  let rhs = builtin.bls12_381_miller_loop(neg_msg, pk_g2)

  // Final check: lhs * rhs == GT_one  (i.e. they are inverses)
  builtin.bls12_381_final_verify(lhs, rhs)
}

// ──────────────────────────────────────────────────────────────────────────────
// aggregate_public_keys
//
// Aggregate a list of compressed G2 public keys into a single G2 point.
// The result is the sum of all individual public-key points.
//
// Parameters:
//   keys – list of compressed G2 points (each 96 bytes)
//
// Returns the compressed aggregated G2 point.
// ──────────────────────────────────────────────────────────────────────────────
pub fn aggregate_public_keys(keys: List<ByteArray>) -> ByteArray {
  // Start from the G2 identity element (point at infinity)
  let identity = builtin.bls12_381_g2_generator()
  // Uncompress all keys and fold-add them
  let points = list.map(keys, builtin.bls12_381_g2_uncompress)
  let sum =
    list.foldl(
      points,
      // seed: negate generator then add it to get identity workaround
      // Aiken stdlib exposes bls12_381_g2_neg; use neg(gen) + gen == identity
      builtin.bls12_381_g2_add(
        builtin.bls12_381_g2_neg(identity),
        identity,
      ),
      fn(acc, p) { builtin.bls12_381_g2_add(acc, p) },
    )
  builtin.bls12_381_g2_compress(sum)
}

// ──────────────────────────────────────────────────────────────────────────────
// verify_aggregate_bls_multi
//
// Verify that `aggregated_sig` is a valid aggregate BLS signature
// over the SAME `message` for all keys in `pub_keys`.
//
// This is a convenience wrapper: aggregates the keys then calls
// verify_bls_signature.
// ──────────────────────────────────────────────────────────────────────────────
pub fn verify_aggregate_bls_multi(
  message: ByteArray,
  aggregated_sig: ByteArray,
  pub_keys: List<ByteArray>,
) -> Bool {
  let agg_pk = aggregate_public_keys(pub_keys)
  verify_bls_signature(message, aggregated_sig, agg_pk)
}
