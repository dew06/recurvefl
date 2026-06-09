/**
 * types.ts
 * All TypeScript types mirroring the Aiken on-chain types for the
 * Recursive Verifiable Federated Learning system on Cardano.
 */

// ---------------------------------------------------------------------------
// On-chain datum types
// ---------------------------------------------------------------------------

/** Maps to the Aiken RoundPhase enum (4 constructors) */
export type RoundPhase = 'Registration' | 'Training' | 'Aggregation' | 'Finalized'

/**
 * Mirrors the Aiken RoundDatum constructor.
 * Held in the UTxO at the Round contract address.
 */
export interface RoundDatum {
  /** Monotonically increasing round identifier */
  round_id: number
  /** Current phase in the FL round state machine */
  phase: RoundPhase
  /** Absolute deadline for the current phase (POSIX ms) */
  deadline: number
  /** Minimum number of participants required to advance */
  min_participants: number
  /** Blake2b-256 Merkle root of registered participant PKHs (hex, 32 bytes) */
  participant_root: string
  /** Blake2b-256 hash of the sorted list of committed gradient hashes (hex, 32 bytes) */
  committed_hashes: string
  /** Blake2b-256 hash of the aggregated Groth16 proof bytes (hex, 32 bytes) */
  aggregated_proof_hash: string
  /** Blake2b-256 hash of the current global model weights (hex, 32 bytes) */
  model_hash: string
  /** Sum of stake weights of all participating clients */
  total_stake_weight: number
}

/**
 * Mirrors the Aiken CommitmentDatum constructor.
 * One UTxO per client submission at the Commitment Inbox address.
 */
export interface CommitmentDatum {
  /** Blake2b-224 payment key hash of the submitting client (hex) */
  client_pkh: string
  /** Round this commitment belongs to */
  round_id: number
  /** Blake2b-256 hash of the client's gradient tensor (hex, 32 bytes) */
  gradient_hash: string
  /** Blake2b-256 hash of the Bulletproof norm-bound proof (hex, 32 bytes) */
  norm_proof_hash: string
}

/**
 * Mirrors the Aiken RegistryDatum constructor.
 * One UTxO per client in the Registry contract.
 */
export interface RegistryDatum {
  /** Blake2b-224 payment key hash (hex) */
  participant_pkh: string
  /** BLS12-381 G2 compressed public key for signature aggregation (hex, 96 bytes) */
  bls_pub_key: string
  /** Relative stake weight used for weighted FedAvg */
  stake_weight: number
  /** POSIX ms timestamp of registration */
  registered_at: number
}

// ---------------------------------------------------------------------------
// ZK proof types (output from Rust prover)
// ---------------------------------------------------------------------------

/**
 * Full Groth16 proof for a single FL round.
 * Written by `zkfl-prover prove-round` to a JSON file.
 */
export interface FLProof {
  /** Round identifier this proof covers */
  round_id: number
  /** Blake2b-256 hash of the model before this round (hex, 32 bytes) */
  prev_model_hash: string
  /** Blake2b-256 hash of the model after aggregation (hex, 32 bytes) */
  new_model_hash: string
  /** L2-norm bound enforced on individual client gradients */
  gradient_norm_bound: number
  /** Number of clients included in the aggregation */
  client_count: number
  /** Groth16 proof bytes: [π_a ‖ π_b ‖ π_c] concatenated, hex-encoded */
  proof_bytes: string
  /** Groth16 verification key bytes, hex-encoded */
  vk_bytes: string
}

/**
 * Final IVC (Nova) accumulated proof spanning all rounds.
 * Written by `zkfl-prover accumulate` to a JSON file.
 */
export interface FinalIVCProof {
  /** Total number of FL rounds accumulated */
  total_rounds: number
  /** Blake2b-256 hash of the initial (genesis) model (hex, 32 bytes) */
  initial_model_hash: string
  /** Blake2b-256 hash of the final trained model (hex, 32 bytes) */
  final_model_hash: string
  /** Blake2b-256 hash of the Nova accumulated folded proof (hex, 32 bytes) */
  accumulated_proof_hash: string
  /** The last round's individual Groth16 proof (for on-chain verification) */
  last_round_proof: FLProof
}

/**
 * Bulletproof range/norm-bound proof for one client's gradient vector.
 * Written by `zkfl-prover prove-norm` to a JSON file.
 */
export interface NormProof {
  /** Client index (0-based) within the current round */
  client_id: number
  /** The L2-norm bound that is proven */
  bound: number
  /** Serialised Bulletproof bytes, hex-encoded */
  proof: string
  /** Pedersen commitment to the gradient norm, hex-encoded */
  commitment: string
}

// ---------------------------------------------------------------------------
// Coordinator configuration
// ---------------------------------------------------------------------------

/**
 * Per-round configuration passed to RoundManager.
 * Loaded from environment variables or a JSON config file.
 */
export interface RoundConfig {
  /** Round number to initialise / manage */
  roundId: number
  /** Minimum registered participants before Training can begin */
  minParticipants: number
  /** L2-norm bound enforced in Bulletproof proofs */
  normBound: number
  /** Absolute deadline (POSIX ms) for the Training phase */
  trainingDeadlineMs: number
  /** Bech32 address of the deployed Round contract */
  scriptAddress: string
  /** Policy ID of the thread NFT minted at round initialisation */
  threadPolicyId: string
  /** Bech32 address of the Commitment Inbox contract */
  commitmentAddress: string
}

// ---------------------------------------------------------------------------
// Aggregation & Merkle helpers
// ---------------------------------------------------------------------------

/** Output of the Python FL runner's aggregation step */
export interface AggregationMetadata {
  round_id: number
  num_clients: number
  client_ids: number[]
  /** Blake2b-256 hashes of each client's gradient file (hex, 32 bytes each) */
  gradient_hashes: string[]
  /** Merkle root over sorted gradient_hashes */
  gradient_merkle_root: string
  /** BLS12-381 G1 compressed aggregated signature (hex, 48 bytes) */
  aggregated_bls_sig: string
  /** Blake2b-256 hash of the new model weights (hex, 32 bytes) */
  new_model_hash: string
  /** Path to the aggregated model weights file */
  model_output_path: string
  /** Timestamps */
  started_at_ms: number
  finished_at_ms: number
}

/** Decoded Groth16 proof components for use in a Cardano redeemer */
export interface ProofComponents {
  /** π_A — G1 compressed point (hex, 48 bytes) */
  proof_a: string
  /** π_B — G2 compressed point (hex, 96 bytes) */
  proof_b: string
  /** π_C — G1 compressed point (hex, 48 bytes) */
  proof_c: string
}

/** Summary printed after a completed run-round command */
export interface RoundSummary {
  roundId: number
  clientCount: number
  modelHash: string
  proofHash: string
  ivcAccumulatedHash: string
  txHash?: string
  durationMs: number
  accuracyPct?: number
}
