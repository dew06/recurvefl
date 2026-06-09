/**
 * fl_runner.ts
 * Subprocess wrapper around the Python FL core (fl-core/run_fl_round.py).
 * Launches the Python script, waits for completion, and parses the output
 * files produced by the FL core.
 */

import { execFileSync, execSync } from 'child_process'
import * as path from 'path'
import * as fsExtra from 'fs-extra'
import type { AggregationMetadata } from './types.js'

// ---------------------------------------------------------------------------
// Path resolution
// ---------------------------------------------------------------------------

/**
 * Resolve the path to the Python FL core directory.
 * Honour the FL_CORE_DIR env variable if set; otherwise use the
 * monorepo-relative path.
 */
function flCoreDir(): string {
  if (process.env.FL_CORE_DIR) return process.env.FL_CORE_DIR
  return path.resolve(
    new URL('.', import.meta.url).pathname,
    '../../fl-core'
  )
}

/**
 * Return the Python 3 interpreter to use.
 * Tries `python3` first, then `python`.
 */
function pythonBin(): string {
  if (process.env.PYTHON_BIN) return process.env.PYTHON_BIN
  try {
    execSync('python3 --version', { stdio: 'pipe' })
    return 'python3'
  } catch {
    return 'python'
  }
}

// ---------------------------------------------------------------------------
// FLRunner class
// ---------------------------------------------------------------------------

export class FLRunner {
  private python: string
  private flCore: string

  constructor(options?: { pythonBin?: string; flCoreDir?: string }) {
    this.python = options?.pythonBin ?? pythonBin()
    this.flCore = options?.flCoreDir ?? flCoreDir()
  }

  // -------------------------------------------------------------------------
  // runRound
  // -------------------------------------------------------------------------
  /**
   * Run one complete FL round on the Python side.
   *
   * Spawns: python3 run_fl_round.py
   *           --round-id <N>
   *           --num-clients <N>
   *           --epochs <N>
   *           --output-dir <path>
   *           [--prev-model <path>]
   *
   * Expected outputs from the Python script:
   *   <outputDir>/client_<i>_gradients.json   — per-client gradient tensors
   *   <outputDir>/aggregation_metadata.json   — aggregation metadata + model hash
   *   <outputDir>/model_round_<N>.pt          — PyTorch model checkpoint
   *
   * @param roundId         Round number to pass to the FL script
   * @param numClients      Number of FL clients to simulate
   * @param epochs          Local training epochs per client
   * @param outputDir       Directory for all outputs
   * @param prevModelPath   Optional path to the previous round's model checkpoint
   */
  async runRound(
    roundId: number,
    numClients: number,
    epochs: number,
    outputDir: string,
    prevModelPath?: string
  ): Promise<{
    aggregationMetadata: AggregationMetadata
    gradientFiles: string[]
    merkleTrees: unknown
    modelPath: string
  }> {
    await fsExtra.ensureDir(outputDir)

    const scriptPath = path.join(this.flCore, 'run_fl_round.py')

    if (!await fsExtra.pathExists(scriptPath)) {
      throw new Error(
        `FL core script not found at ${scriptPath}. ` +
          'Ensure the fl-core directory is at the expected location or set FL_CORE_DIR.'
      )
    }

    const args: string[] = [
      scriptPath,
      '--round-id', String(roundId),
      '--num-clients', String(numClients),
      '--epochs', String(epochs),
      '--output-dir', outputDir,
    ]

    if (prevModelPath) {
      args.push('--prev-model', prevModelPath)
    }

    console.log(`[FLRunner] $ ${this.python} ${args.join(' ')}`)
    try {
      execFileSync(this.python, args, {
        stdio: 'inherit',
        cwd: this.flCore,
      })
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err)
      throw new Error(`FL round script failed: ${msg}`)
    }

    // ---- Read outputs -------------------------------------------------------

    const metaPath = path.join(outputDir, 'aggregation_metadata.json')
    if (!await fsExtra.pathExists(metaPath)) {
      throw new Error(
        `aggregation_metadata.json not found in ${outputDir} after FL round.`
      )
    }
    const aggregationMetadata: AggregationMetadata = await fsExtra.readJson(metaPath)

    // Collect per-client gradient files
    const gradientFiles: string[] = []
    for (let i = 1; i <= numClients; i++) {
      const gf = path.join(outputDir, `client_${i}_gradients.json`)
      if (await fsExtra.pathExists(gf)) gradientFiles.push(gf)
    }

    // Optional Merkle tree JSON (may or may not be produced by the FL script)
    const merklePath = path.join(outputDir, 'merkle_trees.json')
    const merkleTrees = (await fsExtra.pathExists(merklePath))
      ? await fsExtra.readJson(merklePath)
      : null

    const modelPath = path.join(outputDir, `model_round_${roundId}.pt`)

    console.log(
      `[FLRunner] Round ${roundId} complete. ` +
        `${gradientFiles.length} gradient files, model at ${modelPath}`
    )

    return { aggregationMetadata, gradientFiles, merkleTrees, modelPath }
  }

  // -------------------------------------------------------------------------
  // evaluate
  // -------------------------------------------------------------------------
  /**
   * Run the Python evaluation script against a saved model checkpoint.
   *
   * Spawns: python3 evaluate.py --model-path <path>
   *
   * The script is expected to print a single JSON line:
   *   {"accuracy": 0.972, "loss": 0.091}
   *
   * @param modelPath  Path to the .pt model checkpoint
   * @returns          { accuracy, loss } as fractions [0, 1]
   */
  async evaluate(modelPath: string): Promise<{ accuracy: number; loss: number }> {
    const scriptPath = path.join(this.flCore, 'evaluate.py')

    // Gracefully handle missing evaluate script
    if (!await fsExtra.pathExists(scriptPath)) {
      console.warn(
        `[FLRunner] evaluate.py not found at ${scriptPath}; skipping evaluation.`
      )
      return { accuracy: 0, loss: 0 }
    }

    if (!await fsExtra.pathExists(modelPath)) {
      console.warn(`[FLRunner] Model checkpoint not found at ${modelPath}; skipping evaluation.`)
      return { accuracy: 0, loss: 0 }
    }

    let output: string
    try {
      output = execFileSync(
        this.python,
        [scriptPath, '--model-path', modelPath],
        { encoding: 'utf-8', cwd: this.flCore }
      )
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err)
      console.warn(`[FLRunner] evaluate.py failed: ${msg}`)
      return { accuracy: 0, loss: 0 }
    }

    // The script may print multiple lines; find the last valid JSON line
    const lines = output.trim().split('\n').reverse()
    for (const line of lines) {
      try {
        const result = JSON.parse(line.trim()) as { accuracy?: number; loss?: number }
        if (typeof result.accuracy === 'number') {
          return {
            accuracy: result.accuracy,
            loss: typeof result.loss === 'number' ? result.loss : 0,
          }
        }
      } catch {
        // Not JSON — keep looking
      }
    }

    console.warn(`[FLRunner] Could not parse accuracy from evaluate.py output.`)
    return { accuracy: 0, loss: 0 }
  }

  // -------------------------------------------------------------------------
  // checkDependencies
  // -------------------------------------------------------------------------
  /**
   * Verify that the required Python packages (torch, numpy, etc.) are installed.
   * Logs a warning for each missing package but does not throw.
   */
  async checkDependencies(): Promise<void> {
    const required = ['torch', 'numpy', 'cryptography']
    for (const pkg of required) {
      try {
        execFileSync(this.python, ['-c', `import ${pkg}`], { stdio: 'pipe' })
      } catch {
        console.warn(
          `[FLRunner] Python package '${pkg}' may not be installed. ` +
            `Run: pip install ${pkg}`
        )
      }
    }
  }
}
