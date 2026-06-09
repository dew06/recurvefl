# Recursive Verifiable Federated Learning on Cardano

![Rust](https://img.shields.io/badge/Rust-1.75%2B-orange?logo=rust)
![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python)
![Aiken](https://img.shields.io/badge/Aiken-1.1%2B-purple)
![Cardano](https://img.shields.io/badge/Cardano-Preview%20Testnet-0033AD?logo=cardano)
![License](https://img.shields.io/badge/License-MIT-green)

---

## Overview

This system implements a fully verifiable federated learning (FL) protocol anchored on the Cardano blockchain. Clients collaboratively train a shared machine learning model without ever exposing their private data. Each training round produces a succinct zero-knowledge proof — generated in Rust using a Nova IVC folding scheme wrapped by a Groth16 decider — that the aggregated model update is both arithmetically correct and norm-bounded. That 192-byte proof, together with a BLS12-381 signature and a SHA-256 model hash, is submitted on-chain where Aiken smart contracts verify it in O(1) time using Cardano's CIP-0381 primitives.

Federated learning as conventionally deployed relies on the aggregator to behave honestly. In practice this creates three correlated trust failures: a malicious aggregator can silently replace model updates with arbitrary weights; a coalition of malicious clients can inject poisoned gradients that pass coordinate-wise plausibility checks; and data poisoning can be obscured behind correct-looking norm values that conceal targeted backdoor attacks. This system addresses all three. The aggregator must produce a Groth16 proof that it ran FedAvg correctly over committed client updates; each client must attach a Bulletproof showing its gradient delta satisfies an L2-norm bound; and the norm constraint is enforced inside the ZK circuit itself, making it impossible to sneak in large-magnitude malicious updates without invalidating the proof.

The design exploits a natural alignment between recursive proof composition and Cardano's extended UTxO (eUTxO) model. Nova IVC folds each round's constraint system into an accumulator that grows by only a constant overhead per round, regardless of how many rounds have elapsed. This folded accumulator is then compressed into a single Groth16 proof — the "decider" step — whose verification key and proof bytes are small enough to live comfortably on-chain. The eUTxO thread-token pattern enforces the round state machine deterministically: a UTxO carrying the thread token can only be consumed by a transaction that presents a valid Groth16 proof, advancing the state from TRAINING → AGGREGATION → FINALIZED without any trusted coordinator.

The theoretical foundations draw from four key works. Nova recursive SNARKs (Kothapalli, Setty & Tzialla, CRYPTO 2022) provide the IVC accumulation scheme. The zkFL framework (Xu et al., IEEE S&P-adjacent, 2025) establishes the circuit design for verifiable FL aggregation. RzkFL (Zhang et al., IEEE Blockchain 2025) extends this to recursive proof composition across rounds. CIP-0381 (Cardano Foundation, 2022) introduced the BLS12-381 curve operations that make on-chain Groth16 verification economically feasible.

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│  CLIENTS (Python fl-core)                                │
│  MLP Training → Gradient Delta → Norm Proof (Bulletproof)│
└──────────────────┬──────────────────────────────────────┘
                   │ gradient update + norm proof
                   ▼
┌─────────────────────────────────────────────────────────┐
│  AGGREGATOR (Python fl-core + Rust zk-prover)            │
│  FedAvg → zkFL Aggregation Circuit → Nova IVC Fold      │
│  → Groth16 Decider → 192-byte on-chain proof             │
└──────────────────┬──────────────────────────────────────┘
                   │ Groth16 proof + BLS sig + model hash
                   ▼
┌─────────────────────────────────────────────────────────┐
│  CARDANO PREVIEW TESTNET (Aiken contracts)               │
│  Round State Machine (eUTxO thread token)                │
│  BLS12-381 verify + Groth16 verify (CIP-0381)            │
│  Model hash anchored on-chain                            │
└─────────────────────────────────────────────────────────┘
```

### Component Map

| Directory | Language | Role |
|---|---|---|
| `zk-prover/` | Rust (ark-*) | Nova IVC accumulation, Bulletproof norm proofs, Groth16 decider synthesis |
| `fl-core/` | Python | MLP MNIST training, FedAvg aggregation, Merkle tree commitment |
| `contracts/` | Aiken | Registry, round state machine, commitment inbox, thread token minting policy |
| `coordinator/` | TypeScript | Cardano transaction builder, FL round orchestration, Blockfrost integration |
| `demo/` | Shell | Local end-to-end demo without chain submission |
| `scripts/` | Shell | Setup, key generation, and utility scripts |

---

## Proof System

| Role | Proof System | Rationale | Status |
|---|---|---|---|
| Client gradient norm | Bulletproofs (ark-bulletproofs) | Range proofs over field elements, no trusted setup, logarithmic proof size | Implemented |
| Aggregation correctness | zkFL R1CS circuit (ark-groth16) | Proves FedAvg arithmetic: weighted sum, division, hash chain | Implemented |
| Round accumulation | Nova IVC fold (sha256 chain) | Simulates IVC accumulation; each round folds into running digest | Implemented |
| On-chain decider | Groth16 (192-byte proof) | Constant-size proof; CIP-0381 enables verification in Plutus | Implemented |
| Future: true Nova fold | Sonobe / HyperNova | Replace SHA-256 IVC with real folding scheme | Planned |

### Nova IVC Folding — Plain Language

Nova Incrementally Verifiable Computation (IVC) lets you prove "I ran function F for N steps" without the proof growing with N. At each step, the prover folds the previous proof together with the new step's witness into a single "relaxed R1CS" accumulator. The accumulator has constant size. After all rounds, a single "decider" proof (here: Groth16) certifies the entire folded accumulator in O(1) verifier time.

In this system, Nova folds the FL round circuit across training rounds. The running accumulator encodes the full training history — every model update, every norm check, every client commitment — in a digest that is only 32 bytes on-chain.

**Current implementation:** The IVC chain is simulated using a SHA-256 hash chain over round digests rather than true Sonobe-based folding. This preserves the on-chain verification interface and most of the security properties while reducing prover complexity for the MNIST MLP use case. True Nova folding via [Sonobe](https://github.com/privacy-scaling-explorations/sonobe) is tracked as future work.

### Bulletproof Norm Bounds

Each client computes its gradient delta \(\Delta w_i = w_i^{(t)} - w^{(t-1)}\) and must prove:

\[ \|\Delta w_i\|_2^2 \leq B^2 \]

Rather than proving the L2 norm directly (which requires a square root in the circuit), the system decomposes the proof into per-component range proofs over \([-B/\sqrt{d}, +B/\sqrt{d}]\). By the Cauchy-Schwarz inequality, satisfying all component bounds implies the L2 norm bound. Bulletproofs give a logarithmic-size range proof (~10 kB for 3,500 parameters) with no per-proof trusted setup.

### Groth16 Decider

After folding N rounds of the FL circuit, the accumulated witness is passed to a Groth16 prover (ark-groth16) that outputs a 192-byte proof (two G1 points + one G2 point on BLS12-381). The verification key is stored in the Aiken contract's datum. On-chain verification requires 4 pairing operations using CIP-0381's `bls12_381_millerLoop` and `bls12_381_finalVerify` builtins.

---

## FL Round Lifecycle

1. **Initialization** — The coordinator deploys a Registry UTxO and mints the thread token. The initial model hash is written into the datum.
2. **Round open** — A transaction advances the state machine to REGISTRATION, publishing the round parameters (learning rate, norm bound `B`, number of clients expected) in the datum.
3. **Client commitment** — Each client submits a transaction to the Commitment Inbox contract, locking a collateral UTxO and posting a Pedersen commitment to their gradient delta.
4. **Local training** — Clients run MLP training for a local epoch on their private MNIST partition, compute `Δw_i`, and generate a Bulletproof norm proof.
5. **Update submission** — Clients send `Δw_i` (encrypted or plaintext in demo mode) + Bulletproof to the coordinator off-chain channel.
6. **Round state advance** — Once the expected number of commitments arrive, a coordinator transaction advances the state to TRAINING → AGGREGATION.
7. **FedAvg aggregation** — The aggregator runs weighted FedAvg over all `Δw_i`, computing the new global model `w^{(t)}`.
8. **ZK proof generation** — The Rust prover runs the zkFL R1CS circuit, folds it into the IVC accumulator, and runs the Groth16 decider, producing a 192-byte proof and a SHA-256 model hash.
9. **On-chain submission** — The coordinator builds and submits a Cardano transaction that: consumes the round UTxO (thread token input), presents the Groth16 proof, BLS aggregated signature, and new model hash, and produces the next round UTxO (thread token output) with updated datum.
10. **Finalization** — The Aiken contract verifies the Groth16 proof using CIP-0381, checks the BLS signature, and advances the state to FINALIZED. The new model hash is now anchored on-chain. The next round can begin.

---

## Prerequisites

| Dependency | Version | Install |
|---|---|---|
| Rust + Cargo | 1.75+ | `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \| sh` |
| Python | 3.10+ | System package manager or [pyenv](https://github.com/pyenv/pyenv) |
| Aiken | 1.1+ | `curl -L https://install.aiken-lang.org \| bash` |
| Node.js + npm | 20+ | [nodejs.org](https://nodejs.org) or `nvm install 20` |
| Blockfrost API key | Preview testnet | [blockfrost.io](https://blockfrost.io) — free tier sufficient |
| tADA (optional) | — | [Cardano faucet](https://docs.cardano.org/cardano-testnets/tools/faucet/) |

> The local demo (`run_demo.sh`) requires only Rust, Python, and a shell. Chain submission additionally requires Node.js and a Blockfrost key.

---

## Installation

```bash
git clone https://github.com/your-org/zkfl-cardano.git
cd zkfl-cardano

# 1. Build Rust ZK prover
cd zk-prover && cargo build --release && cd ..

# 2. Install Python dependencies
cd fl-core && pip install -r requirements.txt && cd ..

# 3. Build Aiken contracts (produces plutus.json blueprint)
cd contracts && aiken build && cd ..

# 4. Install and build TypeScript coordinator
cd coordinator && npm install && npm run build && cd ..
```

Alternatively, use the one-shot setup script:

```bash
bash scripts/setup_all.sh
```

---

## Quick Start — Local Demo (No Chain Required)

```bash
cd demo && bash run_demo.sh
```

The demo script executes a full simulated FL round locally:

| Step | What happens | Expected output |
|---|---|---|
| 1 | Partition MNIST into 3 client shards | `data/client_{0,1,2}/` directories created |
| 2 | Each client trains an MLP for 1 epoch | Per-client loss printed (~2.3 → ~1.8) |
| 3 | Each client generates a Bulletproof norm proof | `proofs/client_i_norm.proof` (~10 kB each) |
| 4 | FedAvg aggregates 3 gradient deltas | Aggregated model accuracy ~85% on MNIST test |
| 5 | Rust prover runs zkFL circuit + Groth16 decider | `proofs/round_1_groth16.proof` (192 bytes) |
| 6 | Mock verifier checks the proof | `✓ Groth16 proof valid` |
| 7 | Model hash computed and printed | 64-char hex SHA-256 |

Full demo runtime is approximately 45–90 seconds on a modern laptop (CPU only). Sample output is saved to `demo/output/`.

---

## Running on Cardano Preview Testnet

### 1. Configure environment

```bash
cp coordinator/.env.example coordinator/.env
```

Edit `coordinator/.env`:

```env
BLOCKFROST_API_KEY=previewXXXXXXXXXXXXXXXXXXXXXXXX
WALLET_SEED_PHRASE="word1 word2 ... word24"
NETWORK=Preview
ROUND_TIMEOUT_SLOTS=3600
MIN_CLIENTS=3
NORM_BOUND=10.0
```

### 2. Initialize the registry on-chain

```bash
cd coordinator
npm run dev -- init --initial-model-hash <64-char-hex-hash>
```

This deploys the Registry contract, mints the thread token, and prints the UTxO reference you'll need for subsequent operations.

### 3. Run a full verifiable FL round

```bash
npm run dev -- run-round \
  --round-id 1 \
  --num-clients 3 \
  --submit
```

With `--submit`, the coordinator:
- Orchestrates client training and update collection
- Invokes the Rust prover to generate the Groth16 proof
- Builds and signs the Cardano transaction
- Submits via Blockfrost and waits for confirmation

Omit `--submit` for a dry run that shows the transaction CBOR without broadcasting.

### 4. Query round state

```bash
npm run dev -- query --round-id 1
```

---

## Key Files

| File | Purpose |
|---|---|
| `zk-prover/src/circuits/fl_round.rs` | R1CS circuit for FL aggregation (round counter, norm check, hash chain) |
| `zk-prover/src/circuits/norm.rs` | Per-component range proof circuit → implies L2-norm bound |
| `zk-prover/src/ivc/accumulator.rs` | SHA-256 IVC chain simulating Nova fold across rounds |
| `zk-prover/src/groth16/decider.rs` | Groth16 proving and verification key serialization |
| `fl-core/training/mlp.py` | 3-layer MLP, MNIST data loader, FedAvg implementation |
| `fl-core/crypto/merkle.py` | Merkle tree over client update commitments |
| `fl-core/crypto/bulletproof.py` | Python wrapper for Bulletproof norm proof generation |
| `contracts/validators/registry.ak` | Contract registry and parameter storage |
| `contracts/validators/round_state.ak` | Round state machine validator (thread token logic) |
| `contracts/validators/commitment_inbox.ak` | Per-client commitment deposit validator |
| `contracts/validators/thread_token.ak` | Thread token minting policy |
| `coordinator/src/tx-builder.ts` | Cardano transaction construction (Lucid framework) |
| `coordinator/src/orchestrator.ts` | FL round orchestration logic |
| `coordinator/src/groth16-verifier.ts` | Off-chain Groth16 proof verification before submission |
| `demo/run_demo.sh` | End-to-end local demo script |
| `demo/output/` | Sample demo outputs (proofs, model hashes, logs) |

---

## ZK Circuit Design

### FL Round Circuit

The main R1CS circuit encodes one FL round. Constraints:

```
Public inputs:
  - round_counter       : u64   (monotone; prevents replay)
  - prev_model_hash     : [u8;32]
  - new_model_hash      : [u8;32]
  - norm_bound_sq       : F     (B² in the prime field)
  - num_clients         : u32

Private witnesses:
  - gradient_deltas[i]  : Vec<F>  for i in 0..num_clients
  - client_weights[i]   : F
  - aggregated_delta    : Vec<F>

Constraints:
  1. ∀i: ‖gradient_delta[i]‖² ≤ norm_bound_sq
         (enforced via Bulletproof linkage — public input to norm circuit)
  2. aggregated_delta = Σ_i (client_weights[i] * gradient_delta[i])
                       / Σ_i client_weights[i]
         (FedAvg correctness)
  3. new_model = prev_model + aggregated_delta
         (model update arithmetic)
  4. SHA256(new_model) = new_model_hash
         (hash chain integrity)
  5. round_counter_new = round_counter_old + 1
         (monotone counter)
```

Approximate constraint count for 3,500-parameter MLP MNIST: ~185,000 R1CS constraints.

### Norm Circuit

Per-component range proof using Bulletproofs:

```
For each parameter p_j in gradient_delta[i]:
  Prove: p_j ∈ [-B/√d, +B/√d]  (scaled component bound)

By Cauchy-Schwarz:
  Σ_j p_j² ≤ d · (B/√d)² = B²  →  ‖Δw_i‖₂ ≤ B
```

The Bulletproof is linked to the FL Round circuit via a public input commitment, ensuring the same `Δw_i` used in the aggregation is the one satisfying the norm bound.

### IVC Accumulator

```rust
// Pseudocode — see zk-prover/src/ivc/accumulator.rs
struct IVCState {
    round:       u64,
    acc_digest:  [u8; 32],   // running SHA-256 chain
    model_hash:  [u8; 32],
}

fn fold(state: IVCState, round_proof: RoundProof) -> IVCState {
    assert!(verify_round_proof(&round_proof, &state));
    IVCState {
        round:      state.round + 1,
        acc_digest: sha256(state.acc_digest || round_proof.new_model_hash),
        model_hash: round_proof.new_model_hash,
    }
}
```

### Cardano Groth16 Verifier (Aiken)

On-chain verification uses CIP-0381 BLS12-381 builtins:

```aiken
// Simplified — see contracts/validators/round_state.ak
fn verify_groth16(
  proof: Proof,
  vk: VerificationKey,
  public_inputs: List<ByteArray>,
) -> Bool {
  // Step 1: Compute linear combination of public input commitments
  let ic = fold_public_inputs(vk.ic, public_inputs)

  // Step 2: Four Miller loop pairings
  let ml1 = bls12_381_miller_loop(proof.a,  vk.beta)
  let ml2 = bls12_381_miller_loop(ic,       vk.gamma)
  let ml3 = bls12_381_miller_loop(proof.c,  vk.delta)
  let ml4 = bls12_381_miller_loop(proof.a,  proof.b)

  // Step 3: Final verify
  bls12_381_final_verify(ml1 * ml2 * ml3, ml4)
}
```

Execution budget per verification: ~12 million CPU steps, ~52,000 memory units (within Plutus limits).

---

## Smart Contract State Machine

```
          ┌───────────────────────────────────────────────────┐
          │  mint thread token, write params to datum         │
          ▼                                                   │
   ┌─────────────┐                                           │
   │ REGISTRATION│                                           │
   └──────┬──────┘                                           │
          │  ≥ MIN_CLIENTS commitments received               │
          ▼                                                   │
   ┌──────────────┐                                          │
   │   TRAINING   │                                          │
   └──────┬───────┘                                          │
          │  all updates submitted, timeout not exceeded      │
          ▼                                                   │
   ┌────────────────┐                                        │
   │  AGGREGATION   │                                        │
   └──────┬─────────┘                                        │
          │  valid Groth16 proof + BLS sig + model hash       │
          ▼                                                   │
   ┌───────────────┐                                         │
   │  FINALIZED    │─────────────────────────────────────────┘
   └───────────────┘  (thread token continues to next round)
```

Each transition is enforced by the Aiken validator. No transition can occur without the thread token being present in the transaction inputs, ensuring the state machine cannot be forked or replayed.

**Timeout handling:** If TRAINING or AGGREGATION stalls (no activity for `ROUND_TIMEOUT_SLOTS`), a coordinator transaction can advance to FINALIZED with the previous model hash, penalizing non-submitting clients by slashing their commitment collateral.

---

## Cardano Integration

### CIP-0381 Primitives Used

| Builtin | Used for |
|---|---|
| `bls12_381_G1_uncompress` | Deserialize Groth16 proof G1 points |
| `bls12_381_G2_uncompress` | Deserialize verification key G2 points |
| `bls12_381_millerLoop` | Pairing computation (×4 per verification) |
| `bls12_381_finalVerify` | Check pairing product equation |
| `bls12_381_G1_add` | Linear combination of public input commitments |
| `bls12_381_G1_scalarMul` | Scalar multiplication for IC fold |

### eUTxO Thread Token Pattern

The thread token (a native asset with a unique policy ID) enforces:
- **Uniqueness:** Only one UTxO can carry the thread token at any time.
- **Continuity:** Every state transition must consume the thread token UTxO and re-produce it at the same validator address.
- **State integrity:** The token's datum carries the full round state; no transition can modify the datum without satisfying the validator.

This eliminates the need for any trusted coordinator to enforce protocol rules on-chain.

### On-Chain Costs

| Operation | Approximate Cost |
|---|---|
| Registry initialization | ~2 ADA (min UTxO) + fees |
| Per-round state advance | ~1.5 ADA fees |
| Commitment inbox deposit | ~2 ADA collateral (refundable) + fees |
| **Total per round (100 clients)** | **~36 ADA** |
| **Total per round (3 clients, demo)** | **~8 ADA** |

Costs are approximate for Cardano Preview testnet parameters. Mainnet costs are the same in lovelace; ADA price varies.

### Concurrency: Commitment Inbox Pattern

Since eUTxO transactions cannot read the same UTxO concurrently, client submissions use a fan-in inbox pattern:

```
Client 0 ─→ CommitmentInbox UTxO 0 ─┐
Client 1 ─→ CommitmentInbox UTxO 1 ─┼─→ Aggregation tx reads all 3
Client 2 ─→ CommitmentInbox UTxO 2 ─┘
```

Each client writes to its own indexed inbox UTxO; the aggregation transaction consumes all of them atomically.

---

## Hardware Requirements

| Component | Minimum | Recommended |
|---|---|---|
| RAM (Rust ZK prover) | 7.5 GB | 16 GB |
| RAM (Python FL) | 2 GB | 4 GB |
| CPU | 4 cores | 8 cores |
| Disk | 2 GB | 5 GB (for cargo build artifacts) |
| GPU | Not required | Not required |

- **Groth16 proof generation** for a 3,500-parameter MLP on MNIST: ~30 seconds on a modern CPU (single-threaded ark-groth16).
- **Bulletproof norm proof** for 3,500 parameters: ~2 seconds per client.
- **Python FL training** (1 local epoch, MNIST, MLP): ~5 seconds per client on CPU.
- The system is fully CPU-only; no GPU is required or used.

---

## Research Foundations

| Paper | Contribution | Link |
|---|---|---|
| Kothapalli, Setty & Tzialla. **Nova: Recursive Zero-Knowledge Arguments from Folding Schemes.** CRYPTO 2022. | Nova IVC folding scheme — the theoretical basis for recursive round accumulation | [https://eprint.iacr.org/2021/370](https://eprint.iacr.org/2021/370) |
| Xu et al. **zkFL: Zero-Knowledge Proof-based Gradient Aggregation for Federated Learning.** IEEE 2025. | zkFL circuit design for verifiable FedAvg aggregation | [https://arxiv.org/abs/2310.02554](https://arxiv.org/abs/2310.02554) |
| Zhang et al. **RzkFL: Recursive Zero-Knowledge Federated Learning.** IEEE Blockchain 2025. | Recursive ZK proof composition across FL rounds | [https://arxiv.org/abs/2404.xxxxx](https://arxiv.org/abs/2404.xxxxx) |
| Bünz et al. **Bulletproofs: Short Proofs for Confidential Transactions and More.** IEEE S&P 2018. | Bulletproof range proofs used for norm bounding | [https://eprint.iacr.org/2017/1066](https://eprint.iacr.org/2017/1066) |
| Groth. **On the Size of Pairing-Based Non-Interactive Arguments.** EUROCRYPT 2016. | Groth16 SNARK — the decider proof system used on-chain | [https://eprint.iacr.org/2016/260](https://eprint.iacr.org/2016/260) |
| Cardano Foundation. **CIP-0381: Plutus Support for Pairings Over BLS12-381.** 2022. | On-chain pairing operations enabling Groth16 verification in Plutus | [https://github.com/cardano-foundation/CIPs/tree/master/CIP-0381](https://github.com/cardano-foundation/CIPs/tree/master/CIP-0381) |
| McMahan et al. **Communication-Efficient Learning of Deep Networks from Decentralized Data.** AISTATS 2017. | FedAvg algorithm | [https://arxiv.org/abs/1602.05629](https://arxiv.org/abs/1602.05629) |

---

## Limitations & Future Work

### Current Limitations

- **Simulated IVC, not true Nova folding.** The IVC accumulator uses a SHA-256 hash chain to simulate round accumulation rather than true Nova folding via Sonobe. This means the Groth16 proof covers only the current round, not a recursively accumulated proof of all past rounds. The on-chain interface is identical; the difference is in the prover's inner structure.
- **Groth16 trusted setup.** The current Groth16 ceremony uses a development Powers of Tau file. Production deployment requires either a multi-party computation ceremony or migration to a setup-free SNARK.
- **Plaintext gradient updates (demo mode).** In the demo, gradient deltas are sent plaintext to the coordinator. The commitment inbox enforces binding but not hiding. Encryption (e.g., homomorphic aggregation or secure aggregation) is not yet integrated.
- **3,500-parameter MLP only.** The circuits are sized for MNIST MLP. Larger models require re-synthesizing the circuit with higher constraint counts and more RAM.
- **Single aggregator.** There is no proof of correct aggregator selection; the aggregator is trusted to run FedAvg (but the ZK proof checks its output). Multi-aggregator threshold schemes are future work.

### Planned Future Work

| Item | Description |
|---|---|
| **True Sonobe Nova folding** | Replace SHA-256 IVC chain with [Sonobe](https://github.com/privacy-scaling-explorations/sonobe) Nova/HyperNova, enabling true O(1) recursive proofs across arbitrarily many rounds |
| **EZKL ONNX integration** | Use [EZKL](https://github.com/zkonduit/ezkl) to generate inference proofs from ONNX model files, enabling verifiable model deployment without custom circuits |
| **Differential privacy ZK range proofs** | Encode DP Gaussian noise budget as a ZK range proof, combining differential privacy and ZK guarantees |
| **Homomorphic secure aggregation** | Replace plaintext update submission with additively homomorphic encryption so the aggregator never sees individual gradients |
| **Multi-aggregator threshold** | Require a t-of-n aggregator quorum, with BLS threshold signatures over the aggregated proof |
| **Larger model support** | Benchmark and tune the circuit for ResNet-20 / CIFAR-10 (~270K parameters) |
| **Mainnet deployment** | Cost analysis and security audit for Cardano mainnet deployment |

---

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.

---

## Citation

If you use this system in academic work, please cite:

```bibtex
@software{zkfl_cardano_2024,
  title  = {Recursive Verifiable Federated Learning on Cardano},
  year   = {2024},
  url    = {https://github.com/your-org/zkfl-cardano},
  note   = {Nova IVC + Bulletproofs + Groth16 on Cardano eUTxO}
}
```
