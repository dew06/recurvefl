// lib/groth16_verify.ak
// Groth16 zero-knowledge proof verification on BLS12-381.
//
// Proof π = (A: G1, B: G2, C: G1)
// Verification key (VK) is stored off-chain / passed as a parameter.
//
// Verification equation (4-pairing check):
//   e(A, B) == e(α, β) · e(vk_x, γ) · e(C, δ)
//
// Equivalently (all on one side):
//   e(A, B) · e(-α, β) · e(-vk_x, γ) · e(-C, δ) == GT_one
//
// where vk_x = γ_abc[0] + Σ public_inputs[i] * γ_abc[i+1]
//
// Note: On-chain scalar-multiplication in G1 is implemented via repeated
// point-doubling and addition since Plutus V3 does not expose a native
// scalar-mul for G1/G2. For a small number of public inputs this is
// feasible within execution budget.

use aiken/builtin
use aiken/collection/list

// ──────────────────────────────────────────────────────────────────────────────
// Groth16VK — Verification key
// ──────────────────────────────────────────────────────────────────────────────
pub type Groth16VK {
  alpha: ByteArray,
  // G1 compressed (48 bytes)
  beta: ByteArray,
  // G2 compressed (96 bytes)
  gamma: ByteArray,
  // G2 compressed (96 bytes)
  delta: ByteArray,
  // G2 compressed (96 bytes)
  gamma_abc: List<ByteArray>,
  // List of G1 points; length = num_public_inputs + 1
}

// ──────────────────────────────────────────────────────────────────────────────
// scalar_mul_g1
//
// Compute scalar * P for a G1 point P using double-and-add.
// `scalar` is a big-endian ByteArray representing a non-negative integer.
// ──────────────────────────────────────────────────────────────────────────────
fn scalar_mul_g1(
  point: builtin.Bls12_381_G1_Element,
  scalar: ByteArray,
) -> builtin.Bls12_381_G1_Element {
  // Build identity = P + (-P)
  let identity =
    builtin.bls12_381_g1_add(
      point,
      builtin.bls12_381_g1_neg(point),
    )
  // Process each byte of the scalar (big-endian)
  let n = builtin.length_of_bytearray(scalar)
  scalar_mul_g1_loop(point, identity, scalar, 0, n)
}

fn scalar_mul_g1_loop(
  base: builtin.Bls12_381_G1_Element,
  acc: builtin.Bls12_381_G1_Element,
  scalar: ByteArray,
  byte_idx: Int,
  total_bytes: Int,
) -> builtin.Bls12_381_G1_Element {
  if byte_idx >= total_bytes {
    acc
  } else {
    let byte_val = builtin.index_bytearray(scalar, byte_idx)
    let acc2 = process_byte_g1(base, acc, byte_val, 7)
    scalar_mul_g1_loop(base, acc2, scalar, byte_idx + 1, total_bytes)
  }
}

fn process_byte_g1(
  base: builtin.Bls12_381_G1_Element,
  acc: builtin.Bls12_381_G1_Element,
  byte_val: Int,
  bit_pos: Int,
) -> builtin.Bls12_381_G1_Element {
  if bit_pos < 0 {
    acc
  } else {
    // Double the accumulator
    let doubled = builtin.bls12_381_g1_add(acc, acc)
    // If bit is set, add base
    let bit = byte_val / builtin.exp_integer(2, bit_pos) % 2
    let new_acc =
      if bit == 1 {
        builtin.bls12_381_g1_add(doubled, base)
      } else {
        doubled
      }
    process_byte_g1(base, new_acc, byte_val, bit_pos - 1)
  }
}

// ──────────────────────────────────────────────────────────────────────────────
// compute_vk_x
//
// vk_x = gamma_abc[0] + Σ (public_inputs[i] * gamma_abc[i+1])
// ──────────────────────────────────────────────────────────────────────────────
fn compute_vk_x(
  gamma_abc: List<ByteArray>,
  public_inputs: List<ByteArray>,
) -> builtin.Bls12_381_G1_Element {
  // Base = gamma_abc[0]
  expect [head, ..tail] = gamma_abc
  let base_point = builtin.bls12_381_g1_uncompress(head)

  // Fold public inputs
  let (result, _) =
    list.foldl(
      public_inputs,
      (base_point, tail),
      fn(state, scalar) {
        let (acc, remaining_abc) = state
        expect [abc_i, ..rest_abc] = remaining_abc
        let g1_i = builtin.bls12_381_g1_uncompress(abc_i)
        let contribution = scalar_mul_g1(g1_i, scalar)
        (builtin.bls12_381_g1_add(acc, contribution), rest_abc)
      },
    )
  result
}

// ──────────────────────────────────────────────────────────────────────────────
// groth16_verify
//
// Full Groth16 verification.
//
// Parameters:
//   vk            – verification key
//   proof_a       – compressed G1 point (48 bytes)
//   proof_b       – compressed G2 point (96 bytes)
//   proof_c       – compressed G1 point (48 bytes)
//   public_inputs – list of field elements as big-endian ByteArrays
//
// Returns True iff the proof is valid.
// ──────────────────────────────────────────────────────────────────────────────
pub fn groth16_verify(
  vk: Groth16VK,
  proof_a: ByteArray,
  proof_b: ByteArray,
  proof_c: ByteArray,
  public_inputs: List<ByteArray>,
) -> Bool {
  // Decompress proof elements
  let a = builtin.bls12_381_g1_uncompress(proof_a)
  let b = builtin.bls12_381_g2_uncompress(proof_b)
  let c = builtin.bls12_381_g1_uncompress(proof_c)

  // Decompress VK elements
  let alpha = builtin.bls12_381_g1_uncompress(vk.alpha)
  let beta = builtin.bls12_381_g2_uncompress(vk.beta)
  let gamma = builtin.bls12_381_g2_uncompress(vk.gamma)
  let delta = builtin.bls12_381_g2_uncompress(vk.delta)

  // Compute vk_x
  let vk_x = compute_vk_x(vk.gamma_abc, public_inputs)

  // Four Miller-loop computations
  let ml1 = builtin.bls12_381_miller_loop(a, b)
  let ml2 = builtin.bls12_381_miller_loop(builtin.bls12_381_g1_neg(alpha), beta)
  let ml3 =
    builtin.bls12_381_miller_loop(builtin.bls12_381_g1_neg(vk_x), gamma)
  let ml4 = builtin.bls12_381_miller_loop(builtin.bls12_381_g1_neg(c), delta)

  // Combine all Miller-loop results
  let combined =
    builtin.bls12_381_mul_miller_loop_result(
      builtin.bls12_381_mul_miller_loop_result(ml1, ml2),
      builtin.bls12_381_mul_miller_loop_result(ml3, ml4),
    )

  // Final exponentiation and GT_one check
  builtin.bls12_381_final_verify(
    combined,
    builtin.bls12_381_miller_loop_result_one(),
  )
}
