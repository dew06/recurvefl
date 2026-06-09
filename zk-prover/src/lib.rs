//! zkfl-prover — Recursive Verifiable Federated Learning ZK Prover
//!
//! # Architecture
//!
//! ```text
//! Client gradients
//!       │
//!       ▼
//! ┌─────────────────────────────────────────────────────────────┐
//! │  NormProver (Bulletproofs)                                   │
//! │  • k = max(1024, ⌈0.20 × d⌉) random components challenged  │
//! │  • Per-component range proof: |gᵢ| ≤ B/√d                  │
//! │  • Implies ‖g‖₂ ≤ B  (Fix 7: strong soundness)             │
//! └─────────────────────────────────────────────────────────────┘
//!       │ NormProof  (norm_proof_commit = Poseidon(proof_bytes))
//!       ▼
//! ┌─────────────────────────────────────────────────────────────┐
//! │  FLRoundProver (Groth16 over FL Round R1CS circuit)         │
//! │  • 6 public inputs:                                         │
//! │    [prev_hash, round_id, new_hash, next_round_id,           │
//! │     gradient_root_commit, norm_proof_commit]                 │
//! │  • gradient_root_commit binds aggregated gradient content   │
//! │    (Fix 3)                                                   │
//! │  • norm_proof_commit links Bulletproof to round circuit     │
//! │    (Fix 4)                                                   │
//! │  • Output: FLProof (serialised Groth16 proof + vk)          │
//! └─────────────────────────────────────────────────────────────┘
//!       │ FLProof (per round)
//!       ▼
//! ┌─────────────────────────────────────────────────────────────┐
//! │  IVCSummaryCircuit (Groth16 over MAX_ROUNDS=64 slot circuit) │
//! │  • Fixed-size circuit regardless of actual N ≤ 64           │
//! │    (Fix 6: one VK covers all training runs)                  │
//! │  • VK persisted to ivc_vk.bin, pinned on-chain (Fix 2)      │
//! │  • Output: FinalIVCProof (O(1) size, all-rounds committed)  │
//! └─────────────────────────────────────────────────────────────┘
//!       │ FinalIVCProof
//!       ▼
//!  Cardano smart contract
//!  • groth16_verify(vk, A, B, C, public_inputs) on-chain (Fix 1)
//!  • VK checked against pinned datum.vk_hash (Fix 1)
//!  • norm_proof_hash checked from datum.committed_norm_proof_hash (Fix 5)
//! ```

pub mod circuits;
pub mod norm_proof;
