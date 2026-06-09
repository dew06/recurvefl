#!/usr/bin/env python3
"""
run_fl_round.py — Execute one complete Federated Learning round.

Pipeline:
  1. Load MNIST and partition data among N clients.
  2. Initialise (or load) the global model.
  3. Each client trains locally and produces a gradient update.
  4. Each client saves its gradients JSON for the Rust ZK prover.
  5. Aggregator runs FedAvg and produces a new global model.
  6. Aggregation metadata and Merkle-tree commitments are saved.

Output files (in --output-dir):
  global_model_round_<N>.pt       — New global model checkpoint
  client_<id>_gradients.json      — Per-client gradient JSON for ZK prover
  aggregation_metadata.json       — FedAvg round metadata + hashes
  merkle_trees.json               — Participant and gradient Merkle roots + proofs

Usage:
  python run_fl_round.py --round-id 1 --num-clients 3 --epochs 1 --output-dir ./round_output/
  python run_fl_round.py --round-id 2 --num-clients 3 --model-path ./round_output/global_model_round_1.pt
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table

# Ensure fl-core root is on sys.path when run directly.
sys.path.insert(0, str(Path(__file__).parent))

from model.mlp import MNISTMlp, get_model_hash, load_model, save_model
from data.mnist_data import load_mnist, partition_data
from client.fl_client import FLClient
from aggregator.fedavg import FLAggregator
from aggregator.merkle import (
    MerkleTree,
    build_gradient_hash_tree,
    build_participant_tree,
    gradient_hash,
)

console = Console()


@click.command()
@click.option("--round-id", default=1, show_default=True, type=int, help="FL round number.")
@click.option("--num-clients", default=3, show_default=True, type=int, help="Number of FL clients.")
@click.option("--epochs", default=1, show_default=True, type=int, help="Local training epochs per client.")
@click.option("--lr", default=0.01, show_default=True, type=float, help="Client learning rate.")
@click.option("--output-dir", default="./round_output", show_default=True, help="Directory for output files.")
@click.option("--model-path", default=None, help="Path to existing global model .pt (resume from previous round).")
@click.option("--data-dir", default="./data/raw", show_default=True, help="Directory for MNIST data download.")
@click.option("--data-seed", default=42, show_default=True, type=int, help="Seed for data partitioning.")
def main(
    round_id: int,
    num_clients: int,
    epochs: int,
    lr: float,
    output_dir: str,
    model_path: str | None,
    data_dir: str,
    data_seed: int,
) -> None:
    """Run one FL round and save all outputs for the ZK prover."""
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    console.rule(f"[bold cyan]FL Round {round_id}[/bold cyan]")

    # ------------------------------------------------------------------
    # 1. Load MNIST and partition
    # ------------------------------------------------------------------
    console.print("[bold]Step 1:[/bold] Loading MNIST dataset...")
    train_dataset, test_dataset = load_mnist(data_dir=data_dir)
    shards = partition_data(train_dataset, num_clients, seed=data_seed)
    console.print(
        f"  Partitioned {len(train_dataset)} samples into {num_clients} shards "
        f"of {len(shards[0])} samples each."
    )

    # ------------------------------------------------------------------
    # 2. Initialise / load global model
    # ------------------------------------------------------------------
    console.print("[bold]Step 2:[/bold] Initialising global model...")
    if model_path is not None and Path(model_path).exists():
        global_model = load_model(model_path)
        console.print(f"  Loaded model from [green]{model_path}[/green]")
    else:
        global_model = MNISTMlp()
        console.print("  Created fresh MNISTMlp.")

    console.print(f"  Model hash: [dim]{get_model_hash(global_model)}[/dim]")
    console.print(
        f"  Parameters: {sum(p.numel() for p in global_model.parameters()):,}"
    )

    # ------------------------------------------------------------------
    # 3. Client local training
    # ------------------------------------------------------------------
    console.print(f"[bold]Step 3:[/bold] Running local training ({epochs} epoch(s) each)...")
    clients: list[FLClient] = []
    updates: list[dict] = []
    signatures: list[str] = []

    for i in range(num_clients):
        client = FLClient(client_id=i, data_subset=shards[i], device="cpu")
        client.set_global_model(global_model.state_dict())
        update = client.local_train(epochs=epochs, lr=lr)
        sig = client.sign_update_self(update)

        clients.append(client)
        updates.append(update)
        signatures.append(sig)

        console.print(
            f"  Client {i}: norm={update['gradient_norm']:.4f}, "
            f"samples={update['num_samples']}"
        )

    # ------------------------------------------------------------------
    # 4. Save client gradient JSONs
    # ------------------------------------------------------------------
    console.print("[bold]Step 4:[/bold] Saving client gradient JSON files...")
    for i, (client, update) in enumerate(zip(clients, updates)):
        grad_path = out / f"client_{i}_gradients.json"
        client.save_gradients_json(update, str(grad_path))
        console.print(f"  Saved [green]{grad_path}[/green]")

    # ------------------------------------------------------------------
    # 5. FedAvg aggregation
    # ------------------------------------------------------------------
    console.print("[bold]Step 5:[/bold] Running FedAvg aggregation...")
    aggregator = FLAggregator(model_template=global_model, num_clients=num_clients)

    for i, (client, update, sig) in enumerate(zip(clients, updates, signatures)):
        aggregator.receive_update(
            client_id=i,
            gradient_update=update["gradient_update"],
            norm_proof_path="",           # ZK prover not yet available in this stage
            signature=sig,
            public_key=client.get_public_key(),
            extra_metadata={
                "model_hash_before": update["model_hash_before"],
                "model_hash_after": update["model_hash_after"],
                "data_hash": update["data_hash"],
                "num_samples": update["num_samples"],
            },
        )

    new_global_model, agg_meta = aggregator.run_fedavg(global_model)
    agg_meta["round_id"] = round_id  # Honour CLI round-id

    console.print(f"  New model hash: [green]{agg_meta['new_model_hash']}[/green]")
    console.print(f"  Aggregated norm: {agg_meta['aggregated_norm']:.6f}")

    # ------------------------------------------------------------------
    # 6. Evaluate global model
    # ------------------------------------------------------------------
    console.print("[bold]Step 6:[/bold] Evaluating new global model...")
    # Use new model for evaluation — update model_template reference.
    aggregator.model_template = new_global_model
    eval_results = aggregator.evaluate_global_model(test_dataset)
    agg_meta["evaluation"] = eval_results
    console.print(
        f"  Accuracy: [bold]{eval_results['accuracy'] * 100:.2f}%[/bold]  "
        f"Loss: {eval_results['loss']:.4f}"
    )

    # ------------------------------------------------------------------
    # 7. Save new global model
    # ------------------------------------------------------------------
    model_out = out / f"global_model_round_{round_id}.pt"
    save_model(new_global_model, model_out)
    console.print(f"[bold]Step 7:[/bold] Saved model to [green]{model_out}[/green]")

    # ------------------------------------------------------------------
    # 8. Save aggregation metadata
    # ------------------------------------------------------------------
    meta_path = out / "aggregation_metadata.json"
    aggregator.save_aggregation_metadata(agg_meta, str(meta_path))
    console.print(f"  Aggregation metadata → [green]{meta_path}[/green]")

    # ------------------------------------------------------------------
    # 9. Build and save Merkle trees
    # ------------------------------------------------------------------
    console.print("[bold]Step 8:[/bold] Building Merkle commitment trees...")

    participant_tree = build_participant_tree(updates)
    grad_hashes = [gradient_hash(u["gradient_update"]) for u in updates]
    gradient_tree = build_gradient_hash_tree(grad_hashes)

    merkle_data: dict = {
        "round_id": round_id,
        "participant_tree": {
            "root": participant_tree.root().hex(),
            "num_leaves": len(updates),
            "proofs": {
                str(i): [h.hex() for h in participant_tree.proof(i)]
                for i in range(len(updates))
            },
        },
        "gradient_hash_tree": {
            "root": gradient_tree.root().hex(),
            "num_leaves": len(grad_hashes),
            "leaf_hashes": grad_hashes,
            "proofs": {
                str(i): [h.hex() for h in gradient_tree.proof(i)]
                for i in range(len(grad_hashes))
            },
        },
    }

    merkle_path = out / "merkle_trees.json"
    with open(merkle_path, "w", encoding="utf-8") as fh:
        json.dump(merkle_data, fh, indent=2)
    console.print(f"  Participant tree root: [dim]{merkle_data['participant_tree']['root']}[/dim]")
    console.print(f"  Gradient hash tree root: [dim]{merkle_data['gradient_hash_tree']['root']}[/dim]")
    console.print(f"  Merkle trees → [green]{merkle_path}[/green]")

    # ------------------------------------------------------------------
    # Summary table
    # ------------------------------------------------------------------
    console.rule("[bold cyan]Round Summary[/bold cyan]")
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Field", style="dim")
    table.add_column("Value")
    table.add_row("Round ID", str(round_id))
    table.add_row("Num Clients", str(num_clients))
    table.add_row("Epochs / client", str(epochs))
    table.add_row("LR", str(lr))
    table.add_row("Accuracy", f"{eval_results['accuracy'] * 100:.2f}%")
    table.add_row("Loss", f"{eval_results['loss']:.4f}")
    table.add_row("New Model Hash", agg_meta["new_model_hash"][:16] + "...")
    table.add_row("Participant Root", merkle_data["participant_tree"]["root"][:16] + "...")
    table.add_row("Output Dir", str(out.resolve()))
    console.print(table)

    console.print("[bold green]Round complete.[/bold green]")


if __name__ == "__main__":
    main()
