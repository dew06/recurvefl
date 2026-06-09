# ZK Verifiable Federated Learning — Demo Guide

This demo runs the complete Recursive Verifiable FL pipeline locally — no Cardano node
or Blockfrost key required.  You can optionally extend it to submit the final proof to
the **Cardano Preview Testnet** using the TypeScript coordinator.

---

## Overview

```
fl-core/          Python FL training (MLP on MNIST, FedAvg)
zk-prover/        Rust ZK prover (Groth16 + Bulletproofs + Nova IVC)
contracts/        Aiken smart contracts (deployed on Preview Testnet)
coordinator/      TypeScript off-chain coordinator (this component)
demo/             Demo script + this guide
```

The end-to-end flow for one round:

```
[Python fl-core]          [Rust zk-prover]          [Cardano chain]
  run_fl_round.py  ──►  prove-norm (×N clients)  ──►  Commitment Inbox
                   ──►  prove-round (Groth16)     ──►  Round contract
                   ──►  accumulate (Nova IVC)          (Finalized datum)
```

---

## Prerequisites

| Tool | Minimum version | Install |
|------|----------------|---------|
| Rust + Cargo | 1.75 | https://rustup.rs |
| Python | 3.9 | https://python.org |
| PyTorch | 2.0 | `pip install torch` |
| NumPy | 1.24 | `pip install numpy` |
| cryptography | 41 | `pip install cryptography` |

For the optional Cardano submission step you also need:

| Tool | Notes |
|------|-------|
| Node.js ≥ 20 | https://nodejs.org |
| Blockfrost API key | https://blockfrost.io (free tier works) |
| Funded Preview wallet | https://docs.cardano.org/cardano-testnet/tools/faucet/ |
| Aiken ≥ 1.0 | https://aiken-lang.org (to re-deploy contracts) |

---

## Running the Demo

```bash
cd demo
./run_demo.sh
```

The script executes 7 steps (described below) and takes roughly **3–8 minutes**
depending on your machine.

---

## Step-by-Step Walkthrough

### Step 1 — Build Rust prover

```bash
cd zk-prover && cargo build --release
```

Produces `zk-prover/target/release/zkfl-prover`.  The prover implements:
- **Groth16** (via `bellman` / `arkworks`) for the FL aggregation circuit
- **Bulletproofs** (via `bulletproofs` crate) for per-client L2-norm bounds
- **Nova IVC** folding across rounds

### Step 2 — ZK Trusted Setup

```bash
zkfl-prover setup --output-dir ./keys/
```

**Output files:**

| File | Contents |
|------|----------|
| `keys/pk.bin` | Groth16 proving key (circuit-specific, large ~hundreds MB) |
| `keys/vk.bin` | Groth16 verification key (small, ~1–2 KB; embedded in Aiken contract) |
| `keys/nova_params.bin` | Nova recursion parameters |

> **Security note:** In production, the trusted setup should use a multi-party
> ceremony (MPC) rather than a single-party setup.  The `vk.bin` bytes are what
> get embedded in the Aiken validator.

### Step 3 — FL Round 1 (Python)

```bash
python3 run_fl_round.py \
  --round-id 1 \
  --num-clients 3 \
  --epochs 1 \
  --output-dir ../demo/round_1/
```

Simulates **Federated Averaging (FedAvg)** across 3 clients, each training a
2-layer MLP on a shard of MNIST for 1 epoch.

**Output files in `demo/round_1/`:**

| File | Contents |
|------|----------|
| `client_1_gradients.json` | Client 1's gradient tensors (layer → flat float array) |
| `client_2_gradients.json` | Client 2's gradient tensors |
| `client_3_gradients.json` | Client 3's gradient tensors |
| `aggregation_metadata.json` | Aggregation result (see schema below) |
| `model_round_1.pt` | PyTorch checkpoint of the aggregated model |

#### `aggregation_metadata.json` schema

```json
{
  "round_id": 1,
  "num_clients": 3,
  "client_ids": [1, 2, 3],
  "gradient_hashes": ["<blake2b-256 hex>", ...],
  "gradient_merkle_root": "<blake2b-256 hex, 32 bytes>",
  "aggregated_bls_sig": "<BLS12-381 G1 compressed hex, 48 bytes>",
  "new_model_hash": "<blake2b-256 hex, 32 bytes>",
  "model_output_path": "model_round_1.pt",
  "started_at_ms": 1700000000000,
  "finished_at_ms": 1700000003000
}
```

The **`gradient_merkle_root`** is a Blake2b-256 Merkle root over the sorted list of
individual gradient hashes.  It becomes the `committed_hashes` field in the
on-chain `RoundDatum`.

The **`aggregated_bls_sig`** is the BLS12-381 aggregated signature over all client
gradient hashes.  It is attached as transaction metadata (label 674) in the
finalization transaction.

### Step 4 — Bulletproof Norm Proofs

```bash
zkfl-prover prove-norm \
  --gradients-file demo/round_1/client_1_gradients.json \
  --bound 5.0 \
  --output demo/round_1/client_1_norm_proof.json
```

Generates one proof per client, run in sequence (parallelised in the TypeScript
coordinator via `batchProveNorm`).

**Output — `client_N_norm_proof.json`:**

```json
{
  "client_id": 1,
  "bound": 5.0,
  "proof": "<Bulletproof serialised bytes, hex>",
  "commitment": "<Pedersen commitment to gradient L2-norm, hex>"
}
```

**What the Bulletproof proves:**  Given a Pedersen commitment `C` to the gradient
vector's L2-norm `||g||`, the prover knows a vector `g` such that `C = Commit(||g||)`
and `||g||² ≤ bound²`, **without revealing the gradients themselves**.

The `norm_proof_hash` (Blake2b-256 of the proof bytes) is stored in the
`CommitmentDatum` on chain.

### Step 5 — Groth16 Round Aggregation Proof

```bash
zkfl-prover prove-round \
  --round-id 1 \
  --prev-hash 0000...0000 \
  --gradients-file demo/round_1/aggregation_metadata.json \
  --norm-bound 5.0 \
  --clients 3 \
  --output demo/round_1/round_1_proof.json
```

**Output — `round_1_proof.json`:**

```json
{
  "round_id": 1,
  "prev_model_hash": "0000...0000",
  "new_model_hash": "<blake2b-256 hex>",
  "gradient_norm_bound": 5.0,
  "client_count": 3,
  "proof_bytes": "<[π_A ‖ π_B ‖ π_C], 192 bytes total, hex>",
  "vk_bytes": "<Groth16 verification key, hex>"
}
```

**Byte layout of `proof_bytes`:**

| Bytes | Field | Curve point |
|-------|-------|-------------|
| 0 – 47 | π_A | BLS12-381 G1 (compressed, 48 bytes) |
| 48 – 143 | π_B | BLS12-381 G2 (compressed, 96 bytes) |
| 144 – 191 | π_C | BLS12-381 G1 (compressed, 48 bytes) |

These three components are extracted by `ProofBridge.extractProofComponents()` and
placed in the **`FinalizeRound` redeemer** on chain.  The Aiken contract runs the
Groth16 verifier against the embedded `vk.bin` bytes.

**What the Groth16 circuit proves:**

1. The aggregated model `M'` is the result of FedAvg applied to the committed
   gradients.
2. All individual gradient norms satisfy `||g_i||² ≤ bound²` (via linking
   Bulletproof commitments).
3. The computation is consistent with the previous model `M` (chained hash).

### Step 6 — Local Proof Verification

```bash
zkfl-prover verify-round --proof-file demo/round_1/round_1_proof.json
zkfl-prover verify-norm  --proof-file demo/round_1/client_1_norm_proof.json
```

Both commands exit 0 on success, non-zero on failure.  They load `keys/vk.bin`
and run the verifier without any chain interaction.

### Step 7 — Nova IVC Accumulation

```bash
zkfl-prover accumulate \
  --proofs-dir demo/round_1/ \
  --rounds 1 \
  --output demo/final_ivc_proof.json
```

**Output — `final_ivc_proof.json`:**

```json
{
  "total_rounds": 1,
  "initial_model_hash": "0000...0000",
  "final_model_hash": "<blake2b-256 hex>",
  "accumulated_proof_hash": "<blake2b-256 hash of folded Nova proof, hex>",
  "last_round_proof": { ... }
}
```

**What Nova IVC does:**  Nova (Microsoft Research, 2021) is a proof system for
*Incrementally Verifiable Computation*.  Rather than verifying each round's
Groth16 proof independently, Nova *folds* them into a single, constant-size proof
that proves the entire training history.

The `accumulated_proof_hash` is what gets stored in the final `RoundDatum.aggregated_proof_hash`
on chain.  A light client can verify the entire multi-round training run by
checking a single Nova proof rather than N Groth16 proofs.

---

## Output File Reference

```
demo/
├── run_demo.sh                  # This script
├── README_DEMO.md               # This guide
├── final_ivc_proof.json         # Nova IVC proof spanning all rounds
└── round_1/
    ├── client_1_gradients.json  # Client 1 gradient tensors
    ├── client_2_gradients.json  # Client 2 gradient tensors
    ├── client_3_gradients.json  # Client 3 gradient tensors
    ├── aggregation_metadata.json # FedAvg result + BLS sig + Merkle root
    ├── model_round_1.pt         # Aggregated PyTorch model checkpoint
    ├── client_1_norm_proof.json # Bulletproof for client 1
    ├── client_2_norm_proof.json # Bulletproof for client 2
    ├── client_3_norm_proof.json # Bulletproof for client 3
    └── round_1_proof.json       # Groth16 round aggregation proof
```

---

## How to Read the Proofs

### Inspect a norm proof

```bash
python3 -c "
import json, sys
p = json.load(open('demo/round_1/client_1_norm_proof.json'))
print('Client:', p['client_id'])
print('Bound:', p['bound'])
print('Commitment (Pedersen):', p['commitment'][:32], '...')
print('Proof size:', len(bytes.fromhex(p['proof'])), 'bytes')
"
```

### Inspect the round proof

```bash
python3 -c "
import json
p = json.load(open('demo/round_1/round_1_proof.json'))
print('Round:', p['round_id'])
print('Previous model:', p['prev_model_hash'][:16], '...')
print('New model:', p['new_model_hash'][:16], '...')
print('Clients:', p['client_count'])
pb = bytes.fromhex(p['proof_bytes'])
print('π_A (G1):', pb[:48].hex()[:32], '...')
print('π_B (G2):', pb[48:144].hex()[:32], '...')
print('π_C (G1):', pb[144:192].hex()[:32], '...')
"
```

### Inspect the IVC proof

```bash
python3 -c "
import json
p = json.load(open('demo/final_ivc_proof.json'))
print('Total rounds folded:', p['total_rounds'])
print('Initial model:', p['initial_model_hash'][:16], '...')
print('Final model:', p['final_model_hash'][:16], '...')
print('Accumulated proof hash:', p['accumulated_proof_hash'])
"
```

---

## Submitting to Cardano Preview Testnet

After running the local demo, you can submit the final proof to Cardano:

```bash
# 1. Set up environment
cd coordinator
cp .env.example .env
# Edit .env: fill in BLOCKFROST_API_KEY and WALLET_SEED_PHRASE

# 2. Install TypeScript dependencies
npm install

# 3. Deploy contracts (requires Aiken)
cd ../contracts
aiken build
# Follow contracts/README.md for deployment steps
# Copy deployed addresses back to coordinator/.env

# 4. Initialise the round on chain
npm run dev -- init --round-id 1 --initial-model-hash 0000...0000

# 5. Run a full round and submit
npm run dev -- run-round \
  --round-id 1 \
  --num-clients 3 \
  --epochs 1 \
  --norm-bound 5.0 \
  --output-dir ../demo/round_1 \
  --submit

# 6. Check on-chain state
npm run dev -- status --round-id 1
```

The `run-round --submit` command:
1. Runs the same local demo steps above
2. Submits each client's `CommitmentDatum` to the Commitment Inbox contract
3. Builds the `FinalizeRound` transaction with the Groth16 proof in the redeemer
4. Waits for chain confirmation and prints the TxHash

You can view the transaction on [Cardanoscan Preview](https://preview.cardanoscan.io).

---

## Architecture Notes

### Why Cardano?

Cardano's **UTXO model** is well-suited to this design:
- Each round is a distinct UTxO carrying the `RoundDatum` — no shared mutable state
- Client commitments are individual UTxOs at the Commitment Inbox — naturally parallel
- The Groth16 verifier runs entirely in the Plutus validator script
- Thread NFTs enforce uniqueness of the round state machine

### Why Nova IVC?

Nova's *relaxed R1CS* folding allows us to prove an unbounded number of FL rounds
with a **constant-size proof**.  The on-chain verifier only needs to verify the
final accumulated proof rather than one proof per round.

### Gradient Privacy

The system does **not** provide gradient privacy by default.  The gradient hashes
committed on chain are commitments to the *full* gradient tensors (which may be
visible off-chain).  To add gradient privacy, combine with:
- **Secure aggregation** (e.g., Bonawitz et al. 2017) before hashing
- **Differential privacy** (noise injection before `prove-norm`)
- **Homomorphic encryption** of the gradient tensors
