/**
 * cardano.ts
 * Cardano interaction layer using lucid-cardano.
 * Handles Lucid initialisation, UTxO lookups, datum encoding/decoding,
 * and raw transaction submission.
 */

import {
  Lucid,
  Blockfrost,
  Data,
  type TxHash,
  type UTxO,
  type Network,
} from 'lucid-cardano'
import * as fsExtra from 'fs-extra'
import type { RoundDatum, CommitmentDatum, RegistryDatum, RoundPhase } from './types.js'

// ---------------------------------------------------------------------------
// Lucid initialisation
// ---------------------------------------------------------------------------

/**
 * Create and return an initialised Lucid instance connected to Blockfrost.
 *
 * Required env vars:
 *   BLOCKFROST_API_KEY — e.g. "preview_AbC123..."
 *   WALLET_SEED_PHRASE  — 24-word BIP-39 mnemonic (optional; omit for read-only)
 */
export async function getLucid(
  network: 'Preview' | 'Preprod' | 'Mainnet' = 'Preview'
): Promise<Lucid> {
  const apiKey = process.env.BLOCKFROST_API_KEY
  if (!apiKey) {
    throw new Error(
      'BLOCKFROST_API_KEY is not set. Copy .env.example → .env and fill in your key.'
    )
  }

  const blockfrostUrl = `https://cardano-${network.toLowerCase()}.blockfrost.io/api/v0`

  const lucid = await Lucid.new(
    new Blockfrost(blockfrostUrl, apiKey),
    network as Network
  )

  const seed = process.env.WALLET_SEED_PHRASE
  if (seed && seed.trim().split(/\s+/).length >= 15) {
    lucid.selectWalletFromSeed(seed)
  }

  return lucid
}

// ---------------------------------------------------------------------------
// UTxO helpers
// ---------------------------------------------------------------------------

/**
 * Return the first UTxO found at `scriptAddress`.
 * In a thread-token pattern, the script holds exactly one UTxO carrying the NFT;
 * additional overloads may be needed if multiple UTxOs are expected.
 */
export async function getScriptUtxo(
  lucid: Lucid,
  scriptAddress: string
): Promise<UTxO | null> {
  const utxos = await lucid.utxosAt(scriptAddress)
  return utxos[0] ?? null
}

/**
 * Return ALL UTxOs at a script address (e.g. Commitment Inbox).
 */
export async function getAllScriptUtxos(
  lucid: Lucid,
  scriptAddress: string
): Promise<UTxO[]> {
  return lucid.utxosAt(scriptAddress)
}

/**
 * Return the UTxO whose inline datum decodes to the given round_id.
 */
export async function getRoundUtxo(
  lucid: Lucid,
  scriptAddress: string,
  roundId: number
): Promise<UTxO | null> {
  const utxos = await lucid.utxosAt(scriptAddress)
  for (const utxo of utxos) {
    try {
      if (utxo.datum) {
        const decoded = decodeRoundDatum(Data.from(utxo.datum))
        if (decoded.round_id === roundId) return utxo
      }
    } catch {
      // Not a RoundDatum — skip
    }
  }
  return null
}

/**
 * Submit a hex-encoded, CBOR-serialised signed transaction.
 */
export async function submitTx(lucid: Lucid, txHex: string): Promise<TxHash> {
  return lucid.wallet.submitTx(txHex)
}

// ---------------------------------------------------------------------------
// Plutus Data helpers
// ---------------------------------------------------------------------------

/**
 * Encode a JS string (hex) as a Plutus ByteString.
 * lucid-cardano represents raw bytes as hex strings already.
 */
function hexToData(hex: string): string {
  return hex
}

// ---------------------------------------------------------------------------
// RoundDatum encoding / decoding
// ---------------------------------------------------------------------------

/**
 * Encode a RoundDatum to the Plutus Constr Data format expected by Aiken.
 *
 * Aiken layout (zero-based constructor index 0):
 *   { round_id, phase, deadline, min_participants,
 *     participant_root, committed_hashes, aggregated_proof_hash,
 *     model_hash, total_stake_weight }
 */
export function encodeRoundDatum(datum: RoundDatum): Data {
  const phaseIndex: Record<RoundPhase, number> = {
    Registration: 0,
    Training: 1,
    Aggregation: 2,
    Finalized: 3,
  }

  return {
    alternative: 0,
    fields: [
      BigInt(datum.round_id),
      { alternative: phaseIndex[datum.phase], fields: [] },
      BigInt(datum.deadline),
      BigInt(datum.min_participants),
      hexToData(datum.participant_root),
      hexToData(datum.committed_hashes),
      hexToData(datum.aggregated_proof_hash),
      hexToData(datum.model_hash),
      BigInt(datum.total_stake_weight),
    ],
  } as unknown as Data
}

/** Decode Plutus Constr Data back to a RoundDatum. */
export function decodeRoundDatum(data: Data): RoundDatum {
  const phases: RoundPhase[] = ['Registration', 'Training', 'Aggregation', 'Finalized']
  const d = data as unknown as { alternative: number; fields: unknown[] }

  if (d.alternative !== 0) {
    throw new Error(`Expected RoundDatum constr 0, got ${d.alternative}`)
  }

  const phaseRaw = d.fields[1] as { alternative?: number; index?: number }
  const phaseIdx = phaseRaw.alternative ?? phaseRaw.index ?? 0

  return {
    round_id: Number(d.fields[0] as bigint),
    phase: phases[phaseIdx] ?? 'Registration',
    deadline: Number(d.fields[2] as bigint),
    min_participants: Number(d.fields[3] as bigint),
    participant_root: d.fields[4] as string,
    committed_hashes: d.fields[5] as string,
    aggregated_proof_hash: d.fields[6] as string,
    model_hash: d.fields[7] as string,
    total_stake_weight: Number(d.fields[8] as bigint),
  }
}

// ---------------------------------------------------------------------------
// CommitmentDatum encoding / decoding
// ---------------------------------------------------------------------------

/**
 * Encode a CommitmentDatum to Plutus Constr Data.
 * Aiken constructor index 0, fields: [client_pkh, round_id, gradient_hash, norm_proof_hash]
 */
export function encodeCommitmentDatum(datum: CommitmentDatum): Data {
  return {
    alternative: 0,
    fields: [
      hexToData(datum.client_pkh),
      BigInt(datum.round_id),
      hexToData(datum.gradient_hash),
      hexToData(datum.norm_proof_hash),
    ],
  } as unknown as Data
}

export function decodeCommitmentDatum(data: Data): CommitmentDatum {
  const d = data as unknown as { alternative: number; fields: unknown[] }
  return {
    client_pkh: d.fields[0] as string,
    round_id: Number(d.fields[1] as bigint),
    gradient_hash: d.fields[2] as string,
    norm_proof_hash: d.fields[3] as string,
  }
}

// ---------------------------------------------------------------------------
// RegistryDatum encoding / decoding
// ---------------------------------------------------------------------------

/**
 * Encode a RegistryDatum to Plutus Constr Data.
 * Aiken constructor index 0: [participant_pkh, bls_pub_key, stake_weight, registered_at]
 */
export function encodeRegistryDatum(datum: RegistryDatum): Data {
  return {
    alternative: 0,
    fields: [
      hexToData(datum.participant_pkh),
      hexToData(datum.bls_pub_key),
      BigInt(datum.stake_weight),
      BigInt(datum.registered_at),
    ],
  } as unknown as Data
}

export function decodeRegistryDatum(data: Data): RegistryDatum {
  const d = data as unknown as { alternative: number; fields: unknown[] }
  return {
    participant_pkh: d.fields[0] as string,
    bls_pub_key: d.fields[1] as string,
    stake_weight: Number(d.fields[2] as bigint),
    registered_at: Number(d.fields[3] as bigint),
  }
}

// ---------------------------------------------------------------------------
// Redeemer builders
// ---------------------------------------------------------------------------

/**
 * Build a Plutus redeemer for the FinalizeRound action.
 *
 * Aiken FinalizeRound redeemer layout (constructor 2):
 *   { new_model_hash, proof_a, proof_b, proof_c,
 *     gradient_merkle_root, aggregated_bls_sig, participant_count }
 */
export function buildFinalizeRedeemer(params: {
  newModelHash: string
  proofA: string
  proofB: string
  proofC: string
  gradientMerkleRoot: string
  aggregatedBlsSig: string
  participantCount: number
}): Data {
  return {
    alternative: 2, // FinalizeRound constructor index in Aiken
    fields: [
      hexToData(params.newModelHash),
      hexToData(params.proofA),
      hexToData(params.proofB),
      hexToData(params.proofC),
      hexToData(params.gradientMerkleRoot),
      hexToData(params.aggregatedBlsSig),
      BigInt(params.participantCount),
    ],
  } as unknown as Data
}

/**
 * Build a Plutus redeemer for the StartTraining action (constructor 1).
 */
export function buildStartTrainingRedeemer(params: {
  participantMerkleRoot: string
  participantCount: number
}): Data {
  return {
    alternative: 1,
    fields: [
      hexToData(params.participantMerkleRoot),
      BigInt(params.participantCount),
    ],
  } as unknown as Data
}

/**
 * Build a Plutus redeemer for the SubmitCommitment action (constructor 3).
 */
export function buildSubmitCommitmentRedeemer(params: {
  gradientHash: string
  normProofHash: string
}): Data {
  return {
    alternative: 3,
    fields: [
      hexToData(params.gradientHash),
      hexToData(params.normProofHash),
    ],
  } as unknown as Data
}

// ---------------------------------------------------------------------------
// Utility
// ---------------------------------------------------------------------------

/**
 * Wait for a transaction to appear on-chain (polls Blockfrost every 5 s).
 */
export async function awaitTx(
  lucid: Lucid,
  txHash: TxHash,
  timeoutMs = 120_000
): Promise<void> {
  const start = Date.now()
  while (Date.now() - start < timeoutMs) {
    const confirmed = await lucid.awaitTx(txHash)
    if (confirmed) return
    await new Promise((r) => setTimeout(r, 5_000))
  }
  throw new Error(`Transaction ${txHash} was not confirmed within ${timeoutMs} ms`)
}

/**
 * Persist a deployment manifest (script addresses, policy IDs, etc.) to disk.
 */
export async function saveDeploymentManifest(
  outputPath: string,
  manifest: Record<string, unknown>
): Promise<void> {
  await fsExtra.outputJson(outputPath, manifest, { spaces: 2 })
}

/**
 * Load a deployment manifest from disk (written by `aiken deploy` or `init` command).
 */
export async function loadDeploymentManifest(
  manifestPath: string
): Promise<Record<string, unknown>> {
  return fsExtra.readJson(manifestPath)
}
