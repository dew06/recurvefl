//! zkfl-prover CLI
//!
//! ```bash
//! # 1. Generate FL round Groth16 keys (OsRng)
//! zkfl-prover setup --norm-bound 10.0 --keys-dir ./keys
//!
//! # 2. Generate IVC summary Groth16 keys — run ONCE, pin VK on-chain
//! zkfl-prover ivc-setup --keys-dir ./keys
//!
//! # 3. Prove a client's norm bound (Fiat-Shamir Bulletproof)
//! zkfl-prover prove-norm --gradients-file grads.json --bound 10.0 \
//!   --output norm_proof.json
//!
//! # 4. Prove one FL round (loads pk.bin, embeds gradient root + norm proof commit)
//! zkfl-prover prove-round --round-id 0 --prev-hash <hex> \
//!   --gradients-file aggregated.json --norm-bound 10.0 --clients 3 \
//!   --keys-dir ./keys \
//!   --gradient-root <hex-or-empty> \
//!   --norm-proof-file norm_proof.json
//!
//! # 5. Verify a round proof
//! zkfl-prover verify-round --proof-file proof_round_0.json
//!
//! # 6. Verify a norm proof
//! zkfl-prover verify-norm --proof-file norm_proof.json
//!
//! # 7. Accumulate N round proofs into a single Groth16 IVC proof
//! zkfl-prover accumulate --proofs-dir ./proofs --rounds 3 \
//!   --initial-hash <hex> --keys-dir ./keys
//!
//! # 8. Export the FL-round VK for Cardano Plutus groth16_verify
//! zkfl-prover export-vk --keys-dir ./keys --output vk_cardano.json
//! ```

use std::fs;
use std::path::{Path, PathBuf};

use ark_bn254::Fr;
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use clap::{Args, Parser, Subcommand};
use serde::{Deserialize, Serialize};

use zkfl_prover::circuits::ivc_accumulator::{FinalIVCProof, IVCKeys, IVCState};
use zkfl_prover::circuits::round_prover::{bytes_to_fr, fr_to_bytes, FLProof, FLRoundProver};
use zkfl_prover::norm_proof::bulletproof_norm::{
    verify_norm_proof, NormProof, NormProver, DEFAULT_CHALLENGE_SIZE,
};

// ─── CLI ──────────────────────────────────────────────────────────────────────

#[derive(Parser, Debug)]
#[command(
    name = "zkfl-prover",
    about = "ZK prover for Recursive Verifiable Federated Learning on Cardano",
    version = "0.3.0"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Generate and persist Groth16 FL-round keys (OsRng).
    Setup(SetupArgs),
    /// Generate and persist Groth16 IVC summary keys (Fix 2: run once, pin VK on-chain).
    IvcSetup(IvcSetupArgs),
    /// Prove one FL round (loads pk.bin; embeds gradient root + norm proof).
    ProveRound(ProveRoundArgs),
    /// Verify a Groth16 round proof.
    VerifyRound(VerifyRoundArgs),
    /// Prove L2-norm bound with Fiat-Shamir Bulletproof (≥20% challenge fraction).
    ProveNorm(ProveNormArgs),
    /// Verify a Bulletproof norm proof.
    VerifyNorm(VerifyNormArgs),
    /// Accumulate round proofs into a Groth16 IVC summary proof.
    Accumulate(AccumulateArgs),
    /// Export the FL-round Groth16 VK for Cardano Plutus.
    ExportVk(ExportVkArgs),
}

// ── Argument structs ──────────────────────────────────────────────────────────

#[derive(Args, Debug)]
struct SetupArgs {
    #[arg(long, default_value = "10.0")]
    norm_bound: f64,
    #[arg(long, default_value = "./keys")]
    keys_dir: PathBuf,
}

#[derive(Args, Debug)]
struct IvcSetupArgs {
    /// Directory where ivc_pk.bin and ivc_vk.bin will be written.
    /// The VK must be pinned on-chain after this step.
    #[arg(long, default_value = "./keys")]
    keys_dir: PathBuf,
}

#[derive(Args, Debug)]
struct ProveRoundArgs {
    #[arg(long)]
    round_id: u64,
    /// Previous model hash (64 hex chars).
    #[arg(long)]
    prev_hash: String,
    /// Path to gradient JSON (plain array or {"gradients":[…]}).
    #[arg(long)]
    gradients_file: PathBuf,
    #[arg(long, default_value = "10.0")]
    norm_bound: f64,
    #[arg(long, default_value = "1")]
    clients: u32,
    #[arg(long, default_value = "./keys")]
    keys_dir: PathBuf,
    /// Hex-encoded gradient Merkle root (Fix 3).
    /// If omitted, gradient_root_commit = Fr::from(0) (no gradient binding).
    #[arg(long, default_value = "")]
    gradient_root: String,
    /// Path to the NormProof JSON file for the aggregated gradients (Fix 4).
    /// If omitted, norm_proof_commit = Fr::from(0) (no norm binding).
    #[arg(long)]
    norm_proof_file: Option<PathBuf>,
    #[arg(long)]
    output: Option<PathBuf>,
}

#[derive(Args, Debug)]
struct VerifyRoundArgs {
    #[arg(long)]
    proof_file: PathBuf,
}

#[derive(Args, Debug)]
struct ProveNormArgs {
    #[arg(long)]
    gradients_file: PathBuf,
    #[arg(long, default_value = "10.0")]
    bound: f64,
    /// Sub-vector challenge size. Defaults to max(1024, ceil(0.20 * d)).
    /// Override only if you need a specific size.
    #[arg(long)]
    challenge_size: Option<usize>,
    #[arg(long)]
    output: Option<PathBuf>,
}

#[derive(Args, Debug)]
struct VerifyNormArgs {
    #[arg(long)]
    proof_file: PathBuf,
}

#[derive(Args, Debug)]
struct AccumulateArgs {
    #[arg(long, default_value = "./proofs")]
    proofs_dir: PathBuf,
    #[arg(long)]
    rounds: u64,
    #[arg(
        long,
        default_value = "0000000000000000000000000000000000000000000000000000000000000000"
    )]
    initial_hash: String,
    /// Directory containing ivc_pk.bin and ivc_vk.bin (Fix 2).
    #[arg(long, default_value = "./keys")]
    keys_dir: PathBuf,
    #[arg(long)]
    output: Option<PathBuf>,
}

#[derive(Args, Debug)]
struct ExportVkArgs {
    #[arg(long, default_value = "./keys")]
    keys_dir: PathBuf,
    #[arg(long, default_value = "vk_cardano.json")]
    output: PathBuf,
}

// ─── Key metadata ─────────────────────────────────────────────────────────────

#[derive(Serialize, Deserialize)]
struct KeyMeta {
    norm_bound: f64,
    vk_hex:     String,
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

fn load_gradients(path: &Path) -> Result<Vec<f64>, String> {
    let data = fs::read_to_string(path)
        .map_err(|e| format!("Read {:?}: {}", path, e))?;
    if let Ok(v) = serde_json::from_str::<Vec<f64>>(&data) {
        return Ok(v);
    }
    #[derive(serde::Deserialize)]
    struct GradDict { gradients: Vec<f64> }
    serde_json::from_str::<GradDict>(&data)
        .map(|d| d.gradients)
        .map_err(|e| format!("Cannot parse gradients JSON in {:?}: {}", path, e))
}

fn ensure_dir(path: &Path) -> Result<(), String> {
    fs::create_dir_all(path).map_err(|e| format!("Create dir {:?}: {}", path, e))
}

fn decode_prev_hash(hex_str: &str) -> Result<Fr, String> {
    let bytes = hex::decode(hex_str)
        .map_err(|e| format!("prev_hash hex decode: {}", e))?;
    if bytes.len() != 32 {
        return Err(format!("prev_hash must be 64 hex chars, got {} bytes", bytes.len()));
    }
    if let Ok(fr) = Fr::deserialize_compressed(bytes.as_slice()) {
        return Ok(fr);
    }
    Ok(bytes_to_fr(&bytes))
}

// ─── Subcommand implementations ───────────────────────────────────────────────

fn cmd_setup(args: SetupArgs) -> Result<(), String> {
    println!("Running FL-round Groth16 setup (norm_bound={}, OsRng)…", args.norm_bound);
    ensure_dir(&args.keys_dir)?;

    let prover = FLRoundProver::setup(args.norm_bound)?;
    prover.save_keys(&args.keys_dir.join("pk.bin"), &args.keys_dir.join("vk.bin"))?;

    let vk_hex = prover.export_vk_hex()?;
    let meta_json = serde_json::to_string_pretty(&KeyMeta {
        norm_bound: args.norm_bound,
        vk_hex:     vk_hex.clone(),
    }).map_err(|e| format!("Serialise meta: {}", e))?;
    fs::write(args.keys_dir.join("key_meta.json"), &meta_json)
        .map_err(|e| format!("Write meta: {}", e))?;

    println!("FL-round keys saved to {:?}", args.keys_dir);
    println!("  pk.bin  — proving key (keep private)");
    println!("  vk.bin  — verification key");
    println!("VK (first 64 chars): {}…", &vk_hex[..64.min(vk_hex.len())]);
    Ok(())
}

fn cmd_ivc_setup(args: IvcSetupArgs) -> Result<(), String> {
    println!(
        "Running IVC summary Groth16 setup (MAX_ROUNDS={}, OsRng)…",
        zkfl_prover::circuits::ivc_accumulator::MAX_ROUNDS
    );
    println!("This is a ONE-TIME operation. Pin ivc_vk.bin on-chain after this step.");
    ensure_dir(&args.keys_dir)?;

    let keys = IVCKeys::setup_and_save(&args.keys_dir)?;
    println!("IVC VK (first 64 chars): {}…", &keys.vk_hex()[..64.min(keys.vk_hex().len())]);
    println!("Next steps:");
    println!("  1. Publish ivc_vk.bin to your on-chain registry.");
    println!("  2. Never run ivc-setup again — doing so breaks VK pinning.");
    Ok(())
}

fn cmd_prove_round(args: ProveRoundArgs) -> Result<(), String> {
    let pk_path = args.keys_dir.join("pk.bin");
    let vk_path = args.keys_dir.join("vk.bin");

    let norm_bound = if args.keys_dir.join("key_meta.json").exists() {
        let data = fs::read_to_string(args.keys_dir.join("key_meta.json"))
            .map_err(|e| format!("Read key_meta.json: {}", e))?;
        let meta: KeyMeta = serde_json::from_str(&data)
            .map_err(|e| format!("Parse key_meta: {}", e))?;
        meta.norm_bound
    } else {
        args.norm_bound
    };

    let prover = FLRoundProver::load_keys(&pk_path, &vk_path, norm_bound)?;
    let prev_hash_fr = decode_prev_hash(&args.prev_hash)?;
    let gradients    = load_gradients(&args.gradients_file)?;

    // Gradient root bytes (Fix 3).
    let gradient_root_bytes: Vec<u8> = if args.gradient_root.is_empty() {
        Vec::new()
    } else {
        hex::decode(&args.gradient_root)
            .map_err(|e| format!("gradient_root hex: {}", e))?
    };

    // Norm proof bytes (Fix 4).
    let norm_proof_bytes: Vec<u8> = match &args.norm_proof_file {
        Some(p) => fs::read(p).map_err(|e| format!("Read norm proof {:?}: {}", p, e))?,
        None    => Vec::new(),
    };

    println!(
        "Proving FL round {} ({} components, norm_bound={})…",
        args.round_id, gradients.len(), norm_bound
    );
    if gradient_root_bytes.is_empty() {
        println!("  WARNING: --gradient-root not provided; gradient content unbound (Fix 3).");
    }
    if norm_proof_bytes.is_empty() {
        println!("  WARNING: --norm-proof-file not provided; norm proof unlinked (Fix 4).");
    }

    let proof = prover.prove_round(
        args.round_id, prev_hash_fr, &gradients, norm_bound, args.clients,
        &gradient_root_bytes, &norm_proof_bytes,
    )?;

    let output_path = args.output.unwrap_or_else(|| {
        PathBuf::from(format!("proof_round_{}.json", args.round_id))
    });
    let json = serde_json::to_string_pretty(&proof)
        .map_err(|e| format!("Serialise proof: {}", e))?;
    fs::write(&output_path, &json).map_err(|e| format!("Write proof: {}", e))?;

    println!("Proof written to {:?}", output_path);
    println!("New model hash:       {}", proof.new_model_hash);
    println!("Gradient root commit: {}", proof.gradient_root_commit);
    println!("Norm proof commit:    {}", proof.norm_proof_commit);
    Ok(())
}

fn cmd_verify_round(args: VerifyRoundArgs) -> Result<(), String> {
    let data  = fs::read_to_string(&args.proof_file)
        .map_err(|e| format!("Read proof file: {}", e))?;
    let proof: FLProof = serde_json::from_str(&data)
        .map_err(|e| format!("Parse proof: {}", e))?;

    println!("Verifying round {} proof…", proof.round_id);
    let valid = FLRoundProver::verify_proof(&proof)?;
    if valid { println!("✓ Round proof is VALID"); }
    else      { println!("✗ Round proof is INVALID"); }
    Ok(())
}

fn cmd_prove_norm(args: ProveNormArgs) -> Result<(), String> {
    let gradients = load_gradients(&args.gradients_file)?;
    let d = gradients.len();

    // Use dynamic challenge size (20% of d, min 1024) unless overridden.
    let prover = match args.challenge_size {
        Some(k) => NormProver::new_with_challenge_size(d, k),
        None    => NormProver::new(d),
    };
    let k = prover.challenge_size();

    println!(
        "Generating Bulletproof norm proof (d={}, k={} = {:.1}% challenge, bound={})…",
        d, k, 100.0 * k as f64 / d as f64, args.bound
    );
    println!("  Committing {} components (Pedersen/OsRng)…", d);
    println!("  Deriving Fiat-Shamir challenge indices…");
    println!("  Proving aggregated Bulletproof over {} components…", k);

    let proof = prover.prove(&gradients, args.bound)?;

    let output_path = args.output.unwrap_or_else(|| PathBuf::from("norm_proof.json"));
    let json = serde_json::to_string_pretty(&proof)
        .map_err(|e| format!("Serialise norm proof: {}", e))?;
    fs::write(&output_path, &json).map_err(|e| format!("Write norm proof: {}", e))?;

    println!("Norm proof written to {:?}", output_path);
    println!(
        "  Challenge: [{}, … {}] ({} indices)",
        proof.challenge_indices.first().unwrap_or(&0),
        proof.challenge_indices.last().unwrap_or(&0),
        proof.challenge_indices.len()
    );
    Ok(())
}

fn cmd_verify_norm(args: VerifyNormArgs) -> Result<(), String> {
    let data  = fs::read_to_string(&args.proof_file)
        .map_err(|e| format!("Read norm proof: {}", e))?;
    let proof: NormProof = serde_json::from_str(&data)
        .map_err(|e| format!("Parse norm proof: {}", e))?;

    println!(
        "Verifying norm proof (d={}, k={}, bound={})…",
        proof.dimension, proof.challenge_size, proof.bound
    );
    let valid = verify_norm_proof(&proof);
    if valid { println!("✓ Norm proof is VALID"); }
    else      { println!("✗ Norm proof is INVALID"); }
    Ok(())
}

fn cmd_accumulate(args: AccumulateArgs) -> Result<(), String> {
    let initial_hash_fr = decode_prev_hash(&args.initial_hash)?;
    let mut state = IVCState::new(&initial_hash_fr);

    for r in 0..args.rounds {
        let proof_path = args.proofs_dir.join(format!("proof_round_{}.json", r));
        let data  = fs::read_to_string(&proof_path)
            .map_err(|e| format!("Read {:?}: {}", proof_path, e))?;
        let proof: FLProof = serde_json::from_str(&data)
            .map_err(|e| format!("Parse proof: {}", e))?;
        state.fold_round(proof)?;
        println!("Round {}: verified and folded ✓", r);
    }

    println!("Generating Groth16 IVC summary proof ({} rounds)…", args.rounds);
    println!("Loading IVC keys from {:?}…", args.keys_dir);

    let final_proof = state.finalize(&args.keys_dir)?;

    let output_path = args.output.unwrap_or_else(|| PathBuf::from("ivc_proof.json"));
    let json = serde_json::to_string_pretty(&final_proof)
        .map_err(|e| format!("Serialise IVC proof: {}", e))?;
    fs::write(&output_path, &json).map_err(|e| format!("Write IVC proof: {}", e))?;

    println!("Final IVC proof written to {:?}", output_path);
    println!("On-chain anchor: {}", final_proof.on_chain_anchor);

    // Verify against embedded VK (quick self-check).
    let valid = final_proof.verify()?;
    if valid { println!("✓ IVC summary proof VERIFIED"); }
    else      { println!("✗ IVC summary proof INVALID"); }

    // Load and verify against pinned VK (production-grade check).
    let ivc_vk_path = args.keys_dir.join("ivc_vk.bin");
    if ivc_vk_path.exists() {
        let vk_bytes = fs::read(&ivc_vk_path)
            .map_err(|e| format!("Read ivc_vk.bin: {}", e))?;
        let pinned_hex = hex::encode(&vk_bytes);
        let valid2 = final_proof.verify_with_pinned_vk(&pinned_hex)?;
        if valid2 { println!("✓ IVC proof VERIFIED against pinned VK (ivc_vk.bin)"); }
        else       { println!("✗ IVC proof INVALID against pinned VK"); }
    }
    Ok(())
}

fn cmd_export_vk(args: ExportVkArgs) -> Result<(), String> {
    let vk_hex = if args.keys_dir.join("key_meta.json").exists() {
        let data = fs::read_to_string(args.keys_dir.join("key_meta.json"))
            .map_err(|e| format!("Read key_meta.json: {}", e))?;
        let meta: KeyMeta = serde_json::from_str(&data)
            .map_err(|e| format!("Parse meta: {}", e))?;
        meta.vk_hex
    } else {
        fs::read_to_string(args.keys_dir.join("vk.hex"))
            .map_err(|e| format!("Read vk.hex: {}", e))?
            .trim()
            .to_string()
    };

    // Also export IVC VK if present.
    let ivc_vk_hex = {
        let p = args.keys_dir.join("ivc_vk.bin");
        if p.exists() {
            let bytes = fs::read(&p).map_err(|e| format!("Read ivc_vk.bin: {}", e))?;
            Some(hex::encode(&bytes))
        } else {
            None
        }
    };

    #[derive(Serialize)]
    struct VkExport<'a> {
        curve:        &'static str,
        scheme:       &'static str,
        fl_round_vk:  &'a str,
        ivc_vk:       Option<String>,
        note:         &'static str,
    }
    let export = VkExport {
        curve:       "BN254",
        scheme:      "Groth16",
        fl_round_vk: &vk_hex,
        ivc_vk:      ivc_vk_hex,
        note:        "Pin ivc_vk on-chain; use fl_round_vk in Plutus groth16_verify",
    };
    let json = serde_json::to_string_pretty(&export)
        .map_err(|e| format!("Serialise VK export: {}", e))?;
    fs::write(&args.output, &json).map_err(|e| format!("Write VK export: {}", e))?;
    println!("VKs exported to {:?}", args.output);
    Ok(())
}

// ─── main ─────────────────────────────────────────────────────────────────────

fn main() {
    let cli = Cli::parse();
    let result = match cli.command {
        Commands::Setup(a)       => cmd_setup(a),
        Commands::IvcSetup(a)    => cmd_ivc_setup(a),
        Commands::ProveRound(a)  => cmd_prove_round(a),
        Commands::VerifyRound(a) => cmd_verify_round(a),
        Commands::ProveNorm(a)   => cmd_prove_norm(a),
        Commands::VerifyNorm(a)  => cmd_verify_norm(a),
        Commands::Accumulate(a)  => cmd_accumulate(a),
        Commands::ExportVk(a)    => cmd_export_vk(a),
    };
    if let Err(e) = result {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}
