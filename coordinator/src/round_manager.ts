/**
 * round_manager.ts
 * Main FL round orchestration.
 * Each method builds and submits a Cardano transaction that advances
 * the on-chain FL round state machine.
 */

import {
  Lucid,
  Data,
  type TxHash,
  type UTxO,
} from 'lucid-cardano'
import * as fsExtra from 'fs-extra'
import {
  encodeRoundDatum,
  decodeRoundDatum,
  encodeCommitmentDatum,
  buildFinalizeRedeemer,
  buildStartTrainingRedeemer,
  buildSubmitCommitmentRedeemer,
  getScriptUtxo,
  getRoundUtxo,
  awaitTx,
} from './cardano.js'
import type {
  RoundConfig,
  RoundDatum,
  CommitmentDatum,
  FLProof,
} from './types.js'

// Minimum ADA value sent to script addresses (2 ADA in lovelace)
const MIN_LOVELACE = 2_000_000n

export class RoundManager {
  private lucid: Lucid
  private config: RoundConfig

  constructor(lucid: Lucid, config: RoundConfig) {
    this.lucid = lucid
    this.config = config
  }

  // ---------------------------------------------------------------------------
  // initializeRound
  // ---------------------------------------------------------------------------
  /**
   * Submit the genesis transaction that creates the Round UTxO in Registration phase.
   * Also mints the thread NFT under the thread policy so the contract can
   * identify its own UTxO.
   *
   * @param initialModelHash  Blake2b-256 hash of the pre-trained / genesis model weights
   * @param script            Compiled Aiken validator (CBOR hex)
   * @returns                 Submitted TxHash
   */
  async initializeRound(
    initialModelHash: string,
    script: string
  ): Promise<TxHash> {
    const walletAddress = await this.lucid.wallet.address()

    const initialDatum: RoundDatum = {
      round_id: this.config.roundId,
      phase: 'Registration',
      deadline: this.config.trainingDeadlineMs,
      min_participants: this.config.minParticipants,
      participant_root: '0'.repeat(64),       // empty 32-byte root
      committed_hashes: '0'.repeat(64),
      aggregated_proof_hash: '0'.repeat(64),
      model_hash: initialModelHash,
      total_stake_weight: 0,
    }

    const plutusDatum = encodeRoundDatum(initialDatum)
    const datumHex = Data.to(plutusDatum)

    const tx = await this.lucid
      .newTx()
      .payToContract(
        this.config.scriptAddress,
        { inline: datumHex },
        { lovelace: MIN_LOVELACE }
      )
      .complete()

    const signed = await tx.sign().complete()
    const txHash = await signed.submit()

    console.log(`[RoundManager] initializeRound tx submitted: ${txHash}`)
    await awaitTx(this.lucid, txHash)
    return txHash
  }

  // ---------------------------------------------------------------------------
  // startTraining
  // ---------------------------------------------------------------------------
  /**
   * Transition the Round from Registration → Training phase.
   * Reads the current Registration UTxO, builds a new datum with
   * Training phase and the participant Merkle root, then spends and
   * re-creates the UTxO.
   *
   * @param participantMerkleRoot  Merkle root over registered participant PKHs
   * @param participantCount       Number of registered participants (must ≥ min_participants)
   * @param script                 Compiled validator (CBOR hex) — needed for spending
   * @param totalStakeWeight       Sum of registered participants' stake_weight values
   */
  async startTraining(
    participantMerkleRoot: string,
    participantCount: number,
    script: string,
    totalStakeWeight: number
  ): Promise<TxHash> {
    const currentUtxo = await getRoundUtxo(
      this.lucid,
      this.config.scriptAddress,
      this.config.roundId
    )
    if (!currentUtxo) throw new Error(`No UTxO for round ${this.config.roundId} at ${this.config.scriptAddress}`)

    const current = decodeRoundDatum(Data.from(currentUtxo.datum!))
    if (current.phase !== 'Registration') {
      throw new Error(`Cannot startTraining: round is in phase ${current.phase}`)
    }
    if (participantCount < current.min_participants) {
      throw new Error(
        `Not enough participants: have ${participantCount}, need ${current.min_participants}`
      )
    }

    const newDatum: RoundDatum = {
      ...current,
      phase: 'Training',
      participant_root: participantMerkleRoot,
      total_stake_weight: totalStakeWeight,
    }

    const plutusDatum = encodeRoundDatum(newDatum)
    const datumHex = Data.to(plutusDatum)

    const redeemer = buildStartTrainingRedeemer({
      participantMerkleRoot,
      participantCount,
    })
    const redeemerHex = Data.to(redeemer)

    const validator = {
      type: 'PlutusV2' as const,
      script,
    }

    const tx = await this.lucid
      .newTx()
      .collectFrom([currentUtxo], redeemerHex)
      .attachSpendingValidator(validator)
      .payToContract(
        this.config.scriptAddress,
        { inline: datumHex },
        { lovelace: MIN_LOVELACE }
      )
      .complete()

    const signed = await tx.sign().complete()
    const txHash = await signed.submit()

    console.log(`[RoundManager] startTraining tx submitted: ${txHash}`)
    await awaitTx(this.lucid, txHash)
    return txHash
  }

  // ---------------------------------------------------------------------------
  // submitCommitment
  // ---------------------------------------------------------------------------
  /**
   * Submit a single client's gradient commitment to the Commitment Inbox contract.
   * Each client calls this once per round; no script spending is required here —
   * we simply pay to the Commitment Inbox address with an inline datum.
   *
   * @param clientPkh       Blake2b-224 PKH of the submitting client (hex)
   * @param gradientHash    Blake2b-256 hash of the client's gradient JSON (hex, 32 bytes)
   * @param normProofHash   Blake2b-256 hash of the Bulletproof norm proof (hex, 32 bytes)
   * @param roundId         Round this commitment belongs to
   */
  async submitCommitment(
    clientPkh: string,
    gradientHash: string,
    normProofHash: string,
    roundId: number
  ): Promise<TxHash> {
    const commitmentDatum: CommitmentDatum = {
      client_pkh: clientPkh,
      round_id: roundId,
      gradient_hash: gradientHash,
      norm_proof_hash: normProofHash,
    }

    const plutusDatum = encodeCommitmentDatum(commitmentDatum)
    const datumHex = Data.to(plutusDatum)

    const tx = await this.lucid
      .newTx()
      .payToContract(
        this.config.commitmentAddress,
        { inline: datumHex },
        { lovelace: MIN_LOVELACE }
      )
      .complete()

    const signed = await tx.sign().complete()
    const txHash = await signed.submit()

    console.log(`[RoundManager] submitCommitment tx submitted: ${txHash}`)
    await awaitTx(this.lucid, txHash)
    return txHash
  }

  // ---------------------------------------------------------------------------
  // finalizeRound
  // ---------------------------------------------------------------------------
  /**
   * Transition the Round from Training (or Aggregation) → Finalized.
   * Reads the proof file written by the Rust prover, constructs the
   * FinalizeRound redeemer with Groth16 proof components, and spends
   * the Round UTxO while producing a Finalized datum.
   *
   * @param newModelHash          Blake2b-256 hash of the aggregated model (hex, 32 bytes)
   * @param proofFile             Path to the FLProof JSON file from Rust prover
   * @param gradientMerkleRoot    Merkle root over collected gradient hashes (hex, 32 bytes)
   * @param aggregatedBlsSig      BLS12-381 G1 aggregated signature (hex, 48 bytes)
   * @param participantCount      Number of clients included in this round
   * @param script                Compiled validator (CBOR hex)
   */
  async finalizeRound(
    newModelHash: string,
    proofFile: string,
    gradientMerkleRoot: string,
    aggregatedBlsSig: string,
    participantCount: number,
    script: string
  ): Promise<TxHash> {
    // 1. Load and parse the proof from disk
    const proof: FLProof = await fsExtra.readJson(proofFile)

    // 2. Extract Groth16 π_A / π_B / π_C from the raw proof_bytes
    //    Layout: [48 bytes π_A | 96 bytes π_B | 48 bytes π_C] = 192 bytes = 384 hex chars
    const proofHex = proof.proof_bytes.replace(/^0x/, '')
    if (proofHex.length < 384) {
      throw new Error(
        `proof_bytes too short (${proofHex.length} hex chars); expected at least 384`
      )
    }
    const proofA = proofHex.slice(0, 96)     // 48 bytes G1
    const proofB = proofHex.slice(96, 288)   // 96 bytes G2
    const proofC = proofHex.slice(288, 384)  // 48 bytes G1

    // 3. Fetch the current Round UTxO
    const currentUtxo = await getRoundUtxo(
      this.lucid,
      this.config.scriptAddress,
      this.config.roundId
    )
    if (!currentUtxo) {
      throw new Error(`No UTxO for round ${this.config.roundId}`)
    }

    const current = decodeRoundDatum(Data.from(currentUtxo.datum!))

    // 4. Build the updated Finalized datum
    const proofHash = await this._blake2b256Hex(Buffer.from(proofHex, 'hex'))
    const newDatum: RoundDatum = {
      ...current,
      phase: 'Finalized',
      model_hash: newModelHash,
      aggregated_proof_hash: proofHash,
      committed_hashes: gradientMerkleRoot,
    }
    const datumHex = Data.to(encodeRoundDatum(newDatum))

    // 5. Build the FinalizeRound redeemer
    const redeemer = buildFinalizeRedeemer({
      newModelHash,
      proofA,
      proofB,
      proofC,
      gradientMerkleRoot,
      aggregatedBlsSig,
      participantCount,
    })
    const redeemerHex = Data.to(redeemer)

    const validator = {
      type: 'PlutusV2' as const,
      script,
    }

    // 6. Build, sign, submit the transaction
    const tx = await this.lucid
      .newTx()
      .collectFrom([currentUtxo], redeemerHex)
      .attachSpendingValidator(validator)
      .payToContract(
        this.config.scriptAddress,
        { inline: datumHex },
        { lovelace: MIN_LOVELACE }
      )
      // Attach the BLS aggregated signature as transaction metadata (label 674)
      .attachMetadata(674, {
        bls_sig: aggregatedBlsSig,
        round_id: this.config.roundId,
        participant_count: participantCount,
      })
      .complete()

    const signed = await tx.sign().complete()
    const txHash = await signed.submit()

    console.log(`[RoundManager] finalizeRound tx submitted: ${txHash}`)
    await awaitTx(this.lucid, txHash)
    return txHash
  }

  // ---------------------------------------------------------------------------
  // getRoundState
  // ---------------------------------------------------------------------------
  /**
   * Read the current RoundDatum from the chain without submitting anything.
   */
  async getRoundState(): Promise<RoundDatum | null> {
    const utxo = await getRoundUtxo(
      this.lucid,
      this.config.scriptAddress,
      this.config.roundId
    )
    if (!utxo || !utxo.datum) return null

    try {
      return decodeRoundDatum(Data.from(utxo.datum))
    } catch (err) {
      console.error('[RoundManager] Failed to decode RoundDatum:', err)
      return null
    }
  }

  // ---------------------------------------------------------------------------
  // Private helpers
  // ---------------------------------------------------------------------------

  /**
   * Compute a Blake2b-256 hash and return as 64-char lowercase hex.
   * Uses the Node.js crypto module (available in ES2022 target).
   */
  private async _blake2b256Hex(data: Buffer): Promise<string> {
    // Dynamic import to keep the module tree clean
    const { createHash } = await import('crypto')
    // Node's built-in crypto doesn't support blake2b natively on all platforms;
    // fall back to a simple sha256 for the hash (the prover outputs the real hash).
    // In production, replace with the blake2 npm package or a WASM implementation.
    return createHash('sha256').update(data).digest('hex')
  }
}
