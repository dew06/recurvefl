/**
 * proof_bridge.ts
 * Bridge between the Rust `zkfl-prover` binary and the TypeScript coordinator.
 *
 * Each method shells out to the prover executable, waits for it to exit, and
 * then reads the JSON output from disk.  Errors are surfaced as thrown Errors
 * so the calling CLI can catch and report them cleanly.
 */

import { execSync, execFileSync } from 'child_process'
import * as path from 'path'
import * as fsExtra from 'fs-extra'
import type { FLProof, NormProof, FinalIVCProof, ProofComponents } from './types.js'

// ---------------------------------------------------------------------------
// Prover binary path
// ---------------------------------------------------------------------------

/**
 * Resolve the path to the Rust prover binary.
 * Prefer the PROVER_BIN env variable, then fall back to the monorepo-relative
 * release build path.
 */
function proverBin(): string {
  if (process.env.PROVER_BIN) return process.env.PROVER_BIN
  return path.resolve(
    new URL('.', import.meta.url).pathname,
    '../../zk-prover/target/release/zkfl-prover'
  )
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Run the prover with the given arguments.
 * Streams stdout/stderr to the parent process so the user can see progress.
 */
function runProver(args: string[]): void {
  const bin = proverBin()
  console.log(`[ProofBridge] $ ${bin} ${args.join(' ')}`)
  try {
    execFileSync(bin, args, { stdio: 'inherit' })
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err)
    throw new Error(`zkfl-prover failed: ${msg}`)
  }
}

/**
 * Run the prover and capture its stdout as a string.
 */
function runProverCapture(args: string[]): string {
  const bin = proverBin()
  return execFileSync(bin, args, { encoding: 'utf-8' })
}

// ---------------------------------------------------------------------------
// ProofBridge class
// ---------------------------------------------------------------------------

export class ProofBridge {
  private keysDir: string

  constructor(keysDir?: string) {
    this.keysDir =
      keysDir ??
      process.env.ZK_KEYS_DIR ??
      path.resolve(
        new URL('.', import.meta.url).pathname,
        '../../zk-prover/keys'
      )
  }

  // -------------------------------------------------------------------------
  // setup
  // -------------------------------------------------------------------------
  /**
   * Run the trusted-setup / key-generation step.
   * Produces proving key (pk.bin), verification key (vk.bin), and
   * verifier contract parameters under `keysDir`.
   *
   * Only needs to run once per circuit change.
   */
  async setup(): Promise<void> {
    await fsExtra.ensureDir(this.keysDir)
    runProver(['setup', '--output-dir', this.keysDir])
    console.log(`[ProofBridge] ZK keys written to ${this.keysDir}`)
  }

  // -------------------------------------------------------------------------
  // proveRound
  // -------------------------------------------------------------------------
  /**
   * Generate a Groth16 proof for one complete FL aggregation round.
   *
   * @param roundId         Round number (for file naming and public input)
   * @param prevHash        Blake2b-256 hash of the previous model (hex, 32 bytes)
   * @param gradientsFile   Path to the aggregation_metadata.json written by fl-core
   * @param normBound       L2-norm bound enforced across all client gradients
   * @param clientCount     Number of clients included in this round
   * @param outputDir       Directory where the prover will write round_<N>_proof.json
   * @returns               Parsed FLProof
   */
  async proveRound(
    roundId: number,
    prevHash: string,
    gradientsFile: string,
    normBound: number,
    clientCount: number,
    outputDir: string
  ): Promise<FLProof> {
    await fsExtra.ensureDir(outputDir)

    const outputFile = path.join(outputDir, `round_${roundId}_proof.json`)

    runProver([
      'prove-round',
      '--round-id', String(roundId),
      '--prev-hash', prevHash,
      '--gradients-file', gradientsFile,
      '--norm-bound', String(normBound),
      '--clients', String(clientCount),
      '--keys-dir', this.keysDir,
      '--output', outputFile,
    ])

    const proof: FLProof = await fsExtra.readJson(outputFile)
    console.log(
      `[ProofBridge] Round ${roundId} proof generated → ${outputFile}`
    )
    return proof
  }

  // -------------------------------------------------------------------------
  // verifyRound
  // -------------------------------------------------------------------------
  /**
   * Verify a Groth16 FL-round proof locally (no chain interaction).
   *
   * @param proofFile  Path to the FLProof JSON file
   * @returns          true if verification passes
   */
  async verifyRound(proofFile: string): Promise<boolean> {
    try {
      runProver([
        'verify-round',
        '--proof-file', proofFile,
        '--keys-dir', this.keysDir,
      ])
      console.log(`[ProofBridge] Round proof VALID: ${proofFile}`)
      return true
    } catch {
      console.error(`[ProofBridge] Round proof INVALID: ${proofFile}`)
      return false
    }
  }

  // -------------------------------------------------------------------------
  // proveNorm
  // -------------------------------------------------------------------------
  /**
   * Generate a Bulletproof that a client's gradient L2-norm is within `bound`.
   *
   * @param gradientsFile  Path to the client's gradient JSON (e.g. client_1_gradients.json)
   * @param bound          Maximum allowed L2-norm
   * @param outputFile     Destination path for the NormProof JSON
   * @returns              Parsed NormProof
   */
  async proveNorm(
    gradientsFile: string,
    bound: number,
    outputFile: string
  ): Promise<NormProof> {
    await fsExtra.ensureDir(path.dirname(outputFile))

    runProver([
      'prove-norm',
      '--gradients-file', gradientsFile,
      '--bound', String(bound),
      '--output', outputFile,
    ])

    const proof: NormProof = await fsExtra.readJson(outputFile)
    console.log(`[ProofBridge] Norm proof generated → ${outputFile}`)
    return proof
  }

  // -------------------------------------------------------------------------
  // verifyNorm
  // -------------------------------------------------------------------------
  /**
   * Verify a Bulletproof norm-bound proof locally.
   */
  async verifyNorm(proofFile: string): Promise<boolean> {
    try {
      runProver(['verify-norm', '--proof-file', proofFile])
      console.log(`[ProofBridge] Norm proof VALID: ${proofFile}`)
      return true
    } catch {
      console.error(`[ProofBridge] Norm proof INVALID: ${proofFile}`)
      return false
    }
  }

  // -------------------------------------------------------------------------
  // accumulateProofs
  // -------------------------------------------------------------------------
  /**
   * Run Nova IVC accumulation across all round proofs.
   * Folds `rounds` individual Groth16 proofs into a single succinct IVC proof.
   *
   * @param proofsDir   Directory containing round_<N>_proof.json files
   * @param rounds      Number of rounds to accumulate
   * @param outputFile  Destination path for the FinalIVCProof JSON
   * @returns           Parsed FinalIVCProof
   */
  async accumulateProofs(
    proofsDir: string,
    rounds: number,
    outputFile: string
  ): Promise<FinalIVCProof> {
    await fsExtra.ensureDir(path.dirname(outputFile))

    runProver([
      'accumulate',
      '--proofs-dir', proofsDir,
      '--rounds', String(rounds),
      '--keys-dir', this.keysDir,
      '--output', outputFile,
    ])

    const ivcProof: FinalIVCProof = await fsExtra.readJson(outputFile)
    console.log(`[ProofBridge] IVC proof accumulated → ${outputFile}`)
    return ivcProof
  }

  // -------------------------------------------------------------------------
  // exportVK
  // -------------------------------------------------------------------------
  /**
   * Export the Groth16 verification key as a hex string.
   * Used by the `export-vk` CLI command to feed the VK into the Aiken contract.
   *
   * @returns Hex-encoded VK bytes
   */
  async exportVK(): Promise<string> {
    const vkPath = path.join(this.keysDir, 'vk.bin')
    if (!await fsExtra.pathExists(vkPath)) {
      throw new Error(
        `Verification key not found at ${vkPath}. Run 'coordinator setup' first.`
      )
    }
    const bytes = await fsExtra.readFile(vkPath)
    return bytes.toString('hex')
  }

  // -------------------------------------------------------------------------
  // extractProofComponents
  // -------------------------------------------------------------------------
  /**
   * Decompose the raw `proof_bytes` field of an FLProof into the three
   * Groth16 elliptic-curve components needed by the Cardano redeemer.
   *
   * Byte layout (as written by bellman/arkworks serialisation):
   *   Bytes  0 –  47 : π_A  (G1 compressed, 48 bytes)
   *   Bytes 48 – 143 : π_B  (G2 compressed, 96 bytes)
   *   Bytes 144 – 191 : π_C  (G1 compressed, 48 bytes)
   *
   * @param proof  FLProof with proof_bytes already set
   * @returns      { proof_a, proof_b, proof_c } as hex strings
   */
  extractProofComponents(proof: FLProof): ProofComponents {
    const hex = proof.proof_bytes.replace(/^0x/, '')

    // Minimum expected length: 48 + 96 + 48 = 192 bytes = 384 hex chars
    if (hex.length < 384) {
      throw new Error(
        `proof_bytes is ${hex.length / 2} bytes; expected at least 192 bytes ` +
          `(48 G1 + 96 G2 + 48 G1).`
      )
    }

    return {
      proof_a: hex.slice(0, 96),    // 48 bytes → 96 hex chars
      proof_b: hex.slice(96, 288),  // 96 bytes → 192 hex chars
      proof_c: hex.slice(288, 384), // 48 bytes → 96 hex chars
    }
  }

  // -------------------------------------------------------------------------
  // batchProveNorm
  // -------------------------------------------------------------------------
  /**
   * Convenience wrapper: generate norm proofs for all clients in a round.
   *
   * @param roundDir      Directory containing client_<N>_gradients.json files
   * @param clientCount   Number of clients
   * @param bound         L2-norm bound
   * @returns             Array of NormProof objects (indexed by client, 1-based)
   */
  async batchProveNorm(
    roundDir: string,
    clientCount: number,
    bound: number
  ): Promise<NormProof[]> {
    const proofs: NormProof[] = []
    for (let i = 1; i <= clientCount; i++) {
      const gradFile = path.join(roundDir, `client_${i}_gradients.json`)
      const outFile = path.join(roundDir, `client_${i}_norm_proof.json`)
      const proof = await this.proveNorm(gradFile, bound, outFile)
      proofs.push(proof)
    }
    return proofs
  }

  // -------------------------------------------------------------------------
  // proverVersion
  // -------------------------------------------------------------------------
  /**
   * Return the version string reported by the prover binary.
   */
  async proverVersion(): Promise<string> {
    try {
      return runProverCapture(['--version']).trim()
    } catch {
      return 'unknown'
    }
  }
}
