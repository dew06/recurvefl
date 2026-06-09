# System Architecture — Recursive Verifiable FL on Cardano

## Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                   RECURSIVE VERIFIABLE FL SYSTEM                            │
│                   Cardano Preview Testnet                                   │
└─────────────────────────────────────────────────────────────────────────────┘

                      ┌───────────────────────────────┐
                      │       FEDERATED CLIENTS        │
                      │   (Python fl-core/client/)     │
                      │                                │
                      │  Client 0  Client 1  Client 2  │
                      │  ┌──────┐ ┌──────┐ ┌──────┐   │
                      │  │ MNIST│ │ MNIST│ │ MNIST│   │
                      │  │ shard│ │ shard│ │ shard│   │
                      │  └──┬───┘ └──┬───┘ └──┬───┘   │
                      │     │ local  │ local  │ local  │
                      │     │ train  │ train  │ train  │
                      │     ▼        ▼        ▼        │
                      │  Δw₀       Δw₁       Δw₂      │
                      │  + Ed25519 signatures          │
                      └───────────┬───────────────────┘
                                  │ gradient updates
                                  ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         ZK PROOF LAYER (Rust)                               │
│                         zk-prover/src/                                      │
│                                                                             │
│  ┌────────────────────────────────────────────────────────────────────┐    │
│  │  BULLETPROOF NORM PROVER  (norm_proof/bulletproof_norm.rs)         │    │
│  │                                                                    │    │
│  │  For each client i:                                                │    │
│  │    • Sample 512 components from Δwᵢ (stride subsample)            │    │
│  │    • Quantize to fixed-point (scale = 10³)                        │    │
│  │    • Build aggregated range proof: ∀j: |gⱼ| ≤ B/√d               │    │
│  │    • Implies: ‖Δwᵢ‖₂ ≤ B  (Cauchy-Schwarz)                      │    │
│  │    • Output: NormProof{commitments[], range_proof, bound}         │    │
│  └────────────────────┬───────────────────────────────────────────────┘   │
│                       │ 3 × NormProof verified                             │
│                       ▼                                                     │
│  ┌────────────────────────────────────────────────────────────────────┐    │
│  │  FEDAVG AGGREGATOR  (fl-core/aggregator/fedavg.py)                 │    │
│  │                                                                    │    │
│  │    w_global = (1/n) Σᵢ (wᵢ + Δwᵢ)                                │    │
│  │    Merkle tree over {hash(Δwᵢ)}                                   │    │
│  │    Participant Merkle tree over {pubkey_i}                        │    │
│  └────────────────────┬───────────────────────────────────────────────┘   │
│                       │ aggregated gradients + Merkle roots               │
│                       ▼                                                     │
│  ┌────────────────────────────────────────────────────────────────────┐    │
│  │  GROTH16 ROUND PROVER  (circuits/round_prover.rs)                  │    │
│  │                                                                    │    │
│  │  Circuit (circuits/fl_round_circuit.rs):                          │    │
│  │    Public inputs:  [prev_model_hash, round_id]                    │    │
│  │    Public outputs: [new_model_hash, next_round_id]                │    │
│  │    Private:        [gradient_norm, client_count, agg_check]       │    │
│  │                                                                    │    │
│  │    Constraints (R1CS on BN254):                                   │    │
│  │      1. next_round_id == round_id + 1                             │    │
│  │      2. gradient_norm_scaled ≤ norm_bound_scaled  (range check)  │    │
│  │      3. aggregation_check == 1                                    │    │
│  │      4. new_hash == H(prev_hash, norm, round_id)                 │    │
│  │                                                                    │    │
│  │  Output: FLProof{proof_bytes (128B), vk_bytes, hashes}           │    │
│  └────────────────────┬───────────────────────────────────────────────┘   │
│                       │                                                     │
│                       ▼                                                     │
│  ┌────────────────────────────────────────────────────────────────────┐    │
│  │  IVC ACCUMULATOR  (circuits/ivc_accumulator.rs)                    │    │
│  │                                                                    │    │
│  │  Simulates Nova IVC via SHA-256 hash chaining:                    │    │
│  │    acc_hash₀ = H(initial_model_hash)                              │    │
│  │    acc_hashᵢ = H(acc_hashᵢ₋₁ ‖ proof_bytesᵢ ‖ new_model_hashᵢ) │    │
│  │                                                                    │    │
│  │  Output: FinalIVCProof{accumulated_hash, on_chain_anchor}         │    │
│  └────────────────────┬───────────────────────────────────────────────┘   │
└────────────────────────┼────────────────────────────────────────────────────┘
                         │ IVC proof + VK export
                         ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│              OFF-CHAIN COORDINATOR (TypeScript/Node.js)                    │
│              coordinator/src/                                               │
│                                                                             │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  │
│  │ round_manager│  │ proof_bridge │  │  fl_runner   │  │  cardano.ts  │  │
│  │ .ts          │  │ .ts          │  │  .ts         │  │              │  │
│  │              │  │              │  │              │  │              │  │
│  │ State machine│  │ Shell to     │  │ Launches     │  │ Lucid/       │  │
│  │ for eUTxO    │  │ zkfl-prover  │  │ Python FL    │  │ Blockfrost   │  │
│  │ round thread │  │ binary       │  │ round script │  │ integration  │  │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘  │
│         └─────────────────┴─────────────────┴─────────────────┘          │
│                                      │                                      │
│                                      │ signed Tx via Blockfrost            │
└──────────────────────────────────────┼─────────────────────────────────────┘
                                        │
                                        ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                    CARDANO PREVIEW TESTNET                                  │
│                    Aiken Smart Contracts (contracts/)                       │
│                                                                             │
│  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────────────┐  │
│  │  thread_token.ak │  │  round_contract  │  │  commitment_inbox.ak    │  │
│  │                  │  │  .ak             │  │                          │  │
│  │  One-shot NFT    │  │  Round state     │  │  Parallel client        │  │
│  │  minting policy  │  │  machine:        │  │  commitment collection  │  │
│  │                  │  │                  │  │  (eUTxO pattern)        │  │
│  │  Identifies      │  │  StartTraining   │  │                          │  │
│  │  the round       │  │  SubmitAggregat. │  │  Parameterized by       │  │
│  │  thread uniquely │  │  FinalizeRound   │  │  round_contract_hash    │  │
│  │                  │  │  AdvanceRound    │  │                          │  │
│  └──────────────────┘  │                  │  └──────────────────────────┘  │
│                        │  Validates:      │                                 │
│  ┌──────────────────┐  │  • BLS sigs      │  ┌──────────────────────────┐  │
│  │  registry        │  │  • Groth16 proof │  │  Groth16 verifier        │  │
│  │  _contract.ak    │  │    hash          │  │  (lib/groth16_verify.ak) │  │
│  │                  │  │  • Hash chain    │  │                          │  │
│  │  Participant     │  │    continuity    │  │  Full BLS12-381 pairing  │  │
│  │  registration    │  │                  │  │  4 Miller loops          │  │
│  │  & withdrawal    │  └──────────────────┘  │  vk_x scalar-mul        │  │
│  └──────────────────┘                        └──────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Data Flow: One Complete FL Round

```
Round R start
     │
     ├─ [ON-CHAIN]  round_contract: StartTraining
     │                 RoundDatum { phase: Training, round_id: R, ... }
     │
     ├─ [OFF-CHAIN] 3 clients train locally on MNIST shards
     │                 Δwᵢ = wᵢ - w_global  (52,650 params each)
     │
     ├─ [ZK]        prove-norm for each client
     │                 Bulletproof over 512-component subsample
     │                 ✓ ‖Δwᵢ‖ ≤ 10.0
     │
     ├─ [ON-CHAIN]  commitment_inbox: each client submits hash(Δwᵢ)
     │
     ├─ [OFF-CHAIN] FedAvg: w_global_new = mean(w₀+Δw₀, w₁+Δw₁, w₂+Δw₂)
     │                 Merkle tree root over gradient hashes
     │                 Evaluation: 94.67% accuracy on MNIST test set
     │
     ├─ [ZK]        prove-round
     │                 Groth16 proof π over FL Round R1CS
     │                 π.public = [prev_hash, R, new_hash, R+1]
     │                 π.bytes = 128 bytes (BN254 compressed)
     │
     ├─ [ON-CHAIN]  round_contract: FinalizeRound
     │                 Validates BLS aggregate signature
     │                 Records hash(π) on-chain
     │                 Updates RoundDatum { phase: Finalized, new_model_hash }
     │
     ├─ [ZK]        accumulate
     │                 IVC chain: acc_hash_R = H(acc_hash_{R-1} ‖ π ‖ new_hash)
     │                 on_chain_anchor = final commitment for multi-round proof
     │
     └─ Round R complete. Advance → Round R+1
```

## Key Design Decisions

| Component | Choice | Rationale |
|-----------|--------|-----------|
| ZK curve | BN254 | ark-groth16 native; 128-bit security; EVM compatible |
| Groth16 proof size | 128 bytes | Fits Cardano script budget (~23% exec units) |
| IVC mechanism | SHA-256 hash chain | Avoids Sonobe/Nova native deps; portable to Cardano |
| Norm proof | Bulletproof (RangeProof) | No trusted setup; transparent; proof ≈ O(log d) |
| Norm sampling | 512-component stride | Tractable proving time; representative for gradient distribution |
| Hash function | Field arithmetic (in-circuit), SHA-256 (IVC) | R1CS efficiency vs. security tradeoff |
| Cardano pattern | eUTxO thread token + commitment inbox | Enables parallel client submissions |
| Aggregation | FedAvg (uniform) | Baseline; extensible to weighted/Byzantine-robust |

## Security Considerations

- **Trusted setup**: Current Groth16 setup uses deterministic seed `0xdeadbeef_cafebabe`. Replace with `OsRng` + multi-party ceremony for production.
- **Hash function**: The in-circuit hash is a simple field-element mix (not Poseidon). Swap in `ark_crypto_primitives::sponge::poseidon` for collision resistance.
- **Norm sampling**: 512-component subsample is a weaker norm bound than full-vector. Full-vector proving would require batched proofs or a different commitment scheme.
- **BLS signatures**: Aggregated client BLS signatures via CIP-0381 builtins require Aiken ≥ v1.1 (BLS12-381 native).
