#!/usr/bin/env node
/**
 * index.ts
 * Main CLI entry point for the ZK-FL Cardano Coordinator.
 *
 * Commands:
 *   init          — Write the genesis Round UTxO to the chain (Registration phase)
 *   run-round     — Full FL round: train → prove → [submit to Cardano]
 *   status        — Read and display the current round state from chain
 *   verify        — Verify a proof file locally using the Rust prover
 *   export-vk     — Export the Groth16 verification key (hex) for contract deployment
 *   setup-keys    — Run the ZK trusted setup (Groth16 keygen)
 */

import 'dotenv/config'
import { Command } from 'commander'
import chalk from 'chalk'
import ora from 'ora'
import * as fsExtra from 'fs-extra'
import * as path from 'path'

import { getLucid } from './cardano.js'
import { RoundManager } from './round_manager.js'
import { ProofBridge } from './proof_bridge.js'
import { FLRunner } from './fl_runner.js'
import type { RoundConfig, RoundSummary } from './types.js'

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Read the Aiken validator script (CBOR hex) from the contracts deployment. */
async function loadValidatorScript(contractsDir?: string): Promise<string> {
  const dir =
    contractsDir ??
    process.env.CONTRACTS_DIR ??
    path.resolve(
      new URL('.', import.meta.url).pathname,
      '../../contracts'
    )
  // Aiken writes to plutus.json after `aiken build`
  const plutusJsonPath = path.join(dir, 'plutus.json')
  if (await fsExtra.pathExists(plutusJsonPath)) {
    const plutus = await fsExtra.readJson(plutusJsonPath)
    // The first validator is the Round contract
    const validator = plutus?.validators?.[0]?.compiledCode as string | undefined
    if (validator) return validator
  }
  // Fallback: read a raw hex file
  const hexPath = path.join(dir, 'round_validator.hex')
  if (await fsExtra.pathExists(hexPath)) {
    return (await fsExtra.readFile(hexPath, 'utf-8')).trim()
  }
  throw new Error(
    `Validator script not found in ${dir}. ` +
      'Run `aiken build` in the contracts directory first.'
  )
}

/** Build a RoundConfig from env + CLI options. */
function buildRoundConfig(opts: {
  roundId: string
  normBound: string
  minParticipants?: string
}): RoundConfig {
  const scriptAddress = process.env.ROUND_CONTRACT_ADDRESS
  const commitmentAddress = process.env.COMMITMENT_CONTRACT_ADDRESS
  const threadPolicyId = process.env.THREAD_POLICY_ID

  if (!scriptAddress) throw new Error('ROUND_CONTRACT_ADDRESS is not set in .env')
  if (!commitmentAddress) throw new Error('COMMITMENT_CONTRACT_ADDRESS is not set in .env')
  if (!threadPolicyId) throw new Error('THREAD_POLICY_ID is not set in .env')

  return {
    roundId: parseInt(opts.roundId, 10),
    minParticipants: parseInt(opts.minParticipants ?? '1', 10),
    normBound: parseFloat(opts.normBound),
    trainingDeadlineMs: Date.now() + 3_600_000, // 1 hour from now
    scriptAddress,
    commitmentAddress,
    threadPolicyId,
  }
}

/** Print a coloured summary table after a completed round. */
function printRoundSummary(summary: RoundSummary): void {
  const divider = chalk.gray('─'.repeat(62))
  console.log('\n' + chalk.bold.cyan('  ZK-FL Round Summary'))
  console.log(divider)
  console.log(`  ${chalk.bold('Round ID')}          ${chalk.yellow(summary.roundId)}`)
  console.log(`  ${chalk.bold('Clients')}           ${summary.clientCount}`)
  console.log(`  ${chalk.bold('Model hash')}        ${chalk.green(summary.modelHash.slice(0, 16))}…`)
  console.log(`  ${chalk.bold('Proof hash')}        ${chalk.green(summary.proofHash.slice(0, 16))}…`)
  console.log(`  ${chalk.bold('IVC acc. hash')}     ${chalk.green(summary.ivcAccumulatedHash.slice(0, 16))}…`)
  if (summary.txHash) {
    console.log(`  ${chalk.bold('Cardano TxHash')}    ${chalk.magenta(summary.txHash)}`)
  }
  if (summary.accuracyPct !== undefined && summary.accuracyPct > 0) {
    console.log(`  ${chalk.bold('Model accuracy')}    ${(summary.accuracyPct * 100).toFixed(2)}%`)
  }
  const durSec = (summary.durationMs / 1000).toFixed(1)
  console.log(`  ${chalk.bold('Duration')}          ${durSec} s`)
  console.log(divider + '\n')
}

// ---------------------------------------------------------------------------
// Commander setup
// ---------------------------------------------------------------------------

const program = new Command()

program
  .name('zkfl-coordinator')
  .description(
    'Off-chain coordinator for the Recursive Verifiable Federated Learning system on Cardano'
  )
  .version('0.1.0')

// ---------------------------------------------------------------------------
// setup-keys
// ---------------------------------------------------------------------------
program
  .command('setup-keys')
  .description(
    'Run the ZK trusted setup (Groth16 keygen). Only needed once per circuit change.'
  )
  .option('--keys-dir <path>', 'Directory to write ZK keys', '../zk-prover/keys')
  .action(async (opts) => {
    const spinner = ora('Running ZK trusted setup…').start()
    try {
      const bridge = new ProofBridge(opts.keysDir)
      await bridge.setup()
      spinner.succeed(`ZK keys written to ${chalk.cyan(opts.keysDir)}`)
    } catch (err) {
      spinner.fail('Trusted setup failed')
      console.error(chalk.red(String(err)))
      process.exit(1)
    }
  })

// ---------------------------------------------------------------------------
// init
// ---------------------------------------------------------------------------
program
  .command('init')
  .description('Initialise the Round contract on Cardano (writes Registration-phase UTxO).')
  .option('--round-id <n>', 'Round number', '1')
  .option('--initial-model-hash <hex>', 'Blake2b-256 hash of the genesis model (32 bytes hex)', '0'.repeat(64))
  .option('--min-participants <n>', 'Minimum participants to start Training', '3')
  .option('--norm-bound <f>', 'L2-norm bound for gradient Bulletproofs', '5.0')
  .option('--contracts-dir <path>', 'Path to compiled Aiken contracts directory')
  .action(async (opts) => {
    const spinner = ora('Initialising round on Cardano…').start()
    try {
      const network = (process.env.NETWORK as 'Preview' | 'Preprod' | 'Mainnet') ?? 'Preview'
      const lucid = await getLucid(network)
      const config = buildRoundConfig(opts)
      const script = await loadValidatorScript(opts.contractsDir)
      const manager = new RoundManager(lucid, config)
      const txHash = await manager.initializeRound(opts.initialModelHash, script)
      spinner.succeed(
        `Round ${chalk.yellow(opts.roundId)} initialised. TxHash: ${chalk.magenta(txHash)}`
      )
    } catch (err) {
      spinner.fail('Initialisation failed')
      console.error(chalk.red(String(err)))
      process.exit(1)
    }
  })

// ---------------------------------------------------------------------------
// run-round
// ---------------------------------------------------------------------------
program
  .command('run-round')
  .description(
    'Run one complete FL round: FL training → norm proofs → aggregation proof → IVC → [Cardano submit]'
  )
  .option('--round-id <n>', 'Round number', '1')
  .option('--num-clients <n>', 'Number of FL clients', '3')
  .option('--epochs <n>', 'Local training epochs per client', '1')
  .option('--norm-bound <f>', 'L2-norm bound for gradient Bulletproofs', '5.0')
  .option('--output-dir <path>', 'Directory for round outputs', './round_output')
  .option('--prev-model <path>', 'Path to previous round model checkpoint')
  .option('--submit', 'Submit results to Cardano chain (requires BLOCKFROST_API_KEY + contracts)')
  .option('--contracts-dir <path>', 'Path to compiled Aiken contracts directory')
  .option('--keys-dir <path>', 'ZK keys directory', '../zk-prover/keys')
  .option('--min-participants <n>', 'Minimum participants (for --submit)', '1')
  .action(async (opts) => {
    const startMs = Date.now()
    const roundId = parseInt(opts.roundId, 10)
    const numClients = parseInt(opts.numClients, 10)
    const epochs = parseInt(opts.epochs, 10)
    const normBound = parseFloat(opts.normBound)
    const outputDir = path.resolve(opts.outputDir)

    console.log(chalk.bold.cyan('\n  ZK Verifiable Federated Learning — Coordinator'))
    console.log(chalk.gray(`  Round ${roundId} | ${numClients} clients | ${epochs} epoch(s) | norm bound ${normBound}\n`))

    // ---- 1. FL Training ---------------------------------------------------
    const flSpinner = ora(`[1/5] Running FL Round ${roundId} (Python)…`).start()
    const runner = new FLRunner()
    let flResult: Awaited<ReturnType<FLRunner['runRound']>>
    try {
      flResult = await runner.runRound(roundId, numClients, epochs, outputDir, opts.prevModel)
      flSpinner.succeed(`[1/5] FL training complete. Model: ${chalk.green(flResult.aggregationMetadata.new_model_hash?.slice(0, 16))}…`)
    } catch (err) {
      flSpinner.fail('[1/5] FL training failed')
      console.error(chalk.red(String(err)))
      process.exit(1)
    }

    // ---- 2. Norm proofs (per client) ------------------------------------
    const normSpinner = ora(`[2/5] Generating Bulletproof norm proofs (${numClients} clients)…`).start()
    const bridge = new ProofBridge(opts.keysDir)
    let normProofs: Awaited<ReturnType<ProofBridge['batchProveNorm']>>
    try {
      normProofs = await bridge.batchProveNorm(outputDir, numClients, normBound)
      normSpinner.succeed(`[2/5] Norm proofs generated for ${normProofs.length} clients`)
    } catch (err) {
      normSpinner.fail('[2/5] Norm proof generation failed')
      console.error(chalk.red(String(err)))
      process.exit(1)
    }

    // ---- 3. Round aggregation proof (Groth16) ---------------------------
    const proofSpinner = ora('[3/5] Generating Groth16 round aggregation proof…').start()
    let flProof: Awaited<ReturnType<ProofBridge['proveRound']>>
    const prevHash = '0'.repeat(64) // TODO: derive from prev round state
    try {
      flProof = await bridge.proveRound(
        roundId,
        prevHash,
        path.join(outputDir, 'aggregation_metadata.json'),
        normBound,
        numClients,
        outputDir
      )
      proofSpinner.succeed(
        `[3/5] Round proof generated. Hash: ${chalk.green(flProof.proof_bytes.slice(2, 18))}…`
      )
    } catch (err) {
      proofSpinner.fail('[3/5] Round proof generation failed')
      console.error(chalk.red(String(err)))
      process.exit(1)
    }

    // ---- 4. Verify round proof locally ----------------------------------
    const verifySpinner = ora('[4/5] Verifying round proof locally…').start()
    const proofFile = path.join(outputDir, `round_${roundId}_proof.json`)
    try {
      const valid = await bridge.verifyRound(proofFile)
      if (valid) {
        verifySpinner.succeed('[4/5] Round proof verified ✓')
      } else {
        verifySpinner.warn('[4/5] Round proof verification returned false — continuing')
      }
    } catch (err) {
      verifySpinner.warn(`[4/5] Could not verify proof: ${err}`)
    }

    // ---- 5. IVC accumulation -------------------------------------------
    const ivcSpinner = ora('[5/5] Accumulating IVC proof (Nova folding)…').start()
    const ivcOutFile = path.join(path.dirname(outputDir), 'final_ivc_proof.json')
    let ivcProof: Awaited<ReturnType<ProofBridge['accumulateProofs']>>
    try {
      ivcProof = await bridge.accumulateProofs(outputDir, 1, ivcOutFile)
      ivcSpinner.succeed(
        `[5/5] IVC proof accumulated → ${chalk.cyan(ivcOutFile)}`
      )
    } catch (err) {
      ivcSpinner.fail('[5/5] IVC accumulation failed')
      console.error(chalk.red(String(err)))
      process.exit(1)
    }

    // ---- Optional: model accuracy evaluation ---------------------------
    let accuracy = 0
    try {
      const evalResult = await runner.evaluate(flResult.modelPath)
      accuracy = evalResult.accuracy
    } catch {
      // Non-fatal
    }

    // ---- Summary --------------------------------------------------------
    const summary: RoundSummary = {
      roundId,
      clientCount: numClients,
      modelHash: flResult.aggregationMetadata.new_model_hash ?? '0'.repeat(64),
      proofHash: flProof.proof_bytes.replace(/^0x/, '').slice(0, 64),
      ivcAccumulatedHash: ivcProof.accumulated_proof_hash,
      durationMs: Date.now() - startMs,
      accuracyPct: accuracy,
    }

    // ---- Optional: Cardano submission ----------------------------------
    if (opts.submit) {
      const submitSpinner = ora('Submitting finalization to Cardano…').start()
      try {
        const network = (process.env.NETWORK as 'Preview' | 'Preprod' | 'Mainnet') ?? 'Preview'
        const lucid = await getLucid(network)
        const config = buildRoundConfig({ roundId: opts.roundId, normBound: opts.normBound, minParticipants: opts.minParticipants })
        const script = await loadValidatorScript(opts.contractsDir)
        const manager = new RoundManager(lucid, config)

        const proofComponents = bridge.extractProofComponents(flProof)
        const meta = flResult.aggregationMetadata

        const txHash = await manager.finalizeRound(
          meta.new_model_hash,
          proofFile,
          meta.gradient_merkle_root,
          meta.aggregated_bls_sig,
          numClients,
          script
        )

        summary.txHash = txHash
        submitSpinner.succeed(`Submitted to Cardano. TxHash: ${chalk.magenta(txHash)}`)
      } catch (err) {
        submitSpinner.fail('Cardano submission failed (proof still saved locally)')
        console.error(chalk.red(String(err)))
      }
    }

    printRoundSummary(summary)

    // Write summary JSON
    const summaryPath = path.join(outputDir, 'round_summary.json')
    await fsExtra.outputJson(summaryPath, summary, { spaces: 2 })
    console.log(chalk.gray(`  Full summary written to ${summaryPath}`))
  })

// ---------------------------------------------------------------------------
// status
// ---------------------------------------------------------------------------
program
  .command('status')
  .description('Read and display the current round state from Cardano chain.')
  .option('--round-id <n>', 'Round number to query', '1')
  .option('--norm-bound <f>', 'norm bound (config only)', '5.0')
  .action(async (opts) => {
    const spinner = ora('Reading round state from chain…').start()
    try {
      const network = (process.env.NETWORK as 'Preview' | 'Preprod' | 'Mainnet') ?? 'Preview'
      const lucid = await getLucid(network)
      const config = buildRoundConfig(opts)
      const manager = new RoundManager(lucid, config)
      const state = await manager.getRoundState()

      if (!state) {
        spinner.warn(
          `No round state found for round ${opts.roundId} at ${config.scriptAddress}`
        )
        return
      }

      spinner.succeed('Round state retrieved')
      console.log('\n' + chalk.bold('  On-Chain Round State'))
      console.log(chalk.gray('  ' + '─'.repeat(50)))
      console.log(`  Round ID          ${chalk.yellow(state.round_id)}`)
      console.log(`  Phase             ${chalk.cyan(state.phase)}`)
      console.log(`  Deadline          ${new Date(state.deadline).toISOString()}`)
      console.log(`  Min participants  ${state.min_participants}`)
      console.log(`  Total stake       ${state.total_stake_weight}`)
      console.log(`  Model hash        ${chalk.green(state.model_hash.slice(0, 16))}…`)
      console.log(`  Participant root  ${state.participant_root.slice(0, 16)}…`)
      console.log(`  Committed hashes  ${state.committed_hashes.slice(0, 16)}…`)
      console.log(`  Agg proof hash    ${state.aggregated_proof_hash.slice(0, 16)}…`)
      console.log('')
    } catch (err) {
      spinner.fail('Failed to read round state')
      console.error(chalk.red(String(err)))
      process.exit(1)
    }
  })

// ---------------------------------------------------------------------------
// verify
// ---------------------------------------------------------------------------
program
  .command('verify')
  .description('Verify a ZK proof file locally using the Rust prover.')
  .option('--proof-file <path>', 'Path to the FLProof or NormProof JSON file')
  .option('--type <round|norm>', 'Proof type to verify', 'round')
  .option('--keys-dir <path>', 'ZK keys directory', '../zk-prover/keys')
  .action(async (opts) => {
    if (!opts.proofFile) {
      console.error(chalk.red('--proof-file is required'))
      process.exit(1)
    }

    const spinner = ora(`Verifying ${opts.type} proof: ${opts.proofFile}…`).start()
    const bridge = new ProofBridge(opts.keysDir)
    try {
      const valid =
        opts.type === 'norm'
          ? await bridge.verifyNorm(opts.proofFile)
          : await bridge.verifyRound(opts.proofFile)

      if (valid) {
        spinner.succeed(chalk.green(`Proof is VALID ✓`))
      } else {
        spinner.fail(chalk.red(`Proof is INVALID ✗`))
        process.exit(1)
      }
    } catch (err) {
      spinner.fail('Verification error')
      console.error(chalk.red(String(err)))
      process.exit(1)
    }
  })

// ---------------------------------------------------------------------------
// export-vk
// ---------------------------------------------------------------------------
program
  .command('export-vk')
  .description(
    'Export the Groth16 verification key as hex for embedding in the Aiken contract.'
  )
  .option('--keys-dir <path>', 'ZK keys directory', '../zk-prover/keys')
  .option('--output <path>', 'Write VK hex to this file (prints to stdout if omitted)')
  .action(async (opts) => {
    const spinner = ora('Exporting verification key…').start()
    try {
      const bridge = new ProofBridge(opts.keysDir)
      const vkHex = await bridge.exportVK()
      spinner.succeed(`Verification key exported (${vkHex.length / 2} bytes)`)

      if (opts.output) {
        await fsExtra.outputFile(opts.output, vkHex)
        console.log(chalk.gray(`  Written to ${opts.output}`))
      } else {
        console.log('\n' + chalk.cyan(vkHex) + '\n')
      }
    } catch (err) {
      spinner.fail('Failed to export VK')
      console.error(chalk.red(String(err)))
      process.exit(1)
    }
  })

// ---------------------------------------------------------------------------
// submit-commitment  (low-level helper for individual clients)
// ---------------------------------------------------------------------------
program
  .command('submit-commitment')
  .description('Submit a single client gradient commitment to the Commitment Inbox.')
  .option('--round-id <n>', 'Round number', '1')
  .option('--client-pkh <hex>', 'Client payment key hash (28 bytes hex)')
  .option('--gradient-hash <hex>', 'Blake2b-256 hash of gradients (32 bytes hex)')
  .option('--norm-proof-hash <hex>', 'Blake2b-256 hash of norm proof (32 bytes hex)')
  .option('--norm-bound <f>', 'norm bound (config)', '5.0')
  .action(async (opts) => {
    if (!opts.clientPkh || !opts.gradientHash || !opts.normProofHash) {
      console.error(chalk.red('--client-pkh, --gradient-hash and --norm-proof-hash are all required'))
      process.exit(1)
    }

    const spinner = ora('Submitting commitment to Cardano…').start()
    try {
      const network = (process.env.NETWORK as 'Preview' | 'Preprod' | 'Mainnet') ?? 'Preview'
      const lucid = await getLucid(network)
      const config = buildRoundConfig(opts)
      const manager = new RoundManager(lucid, config)

      const txHash = await manager.submitCommitment(
        opts.clientPkh,
        opts.gradientHash,
        opts.normProofHash,
        parseInt(opts.roundId, 10)
      )
      spinner.succeed(`Commitment submitted. TxHash: ${chalk.magenta(txHash)}`)
    } catch (err) {
      spinner.fail('Commitment submission failed')
      console.error(chalk.red(String(err)))
      process.exit(1)
    }
  })

// ---------------------------------------------------------------------------
// Run
// ---------------------------------------------------------------------------
program.parseAsync(process.argv)
