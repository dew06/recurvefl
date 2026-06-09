#!/usr/bin/env python3
"""
evaluate.py — Evaluate global models from FL rounds and print an accuracy table.

Loads saved model checkpoints from a model directory, evaluates each on the
MNIST test set, and renders a Rich table showing accuracy and loss per round.

Usage:
  python evaluate.py --model-dir ./round_output/ --rounds 1 2 3
  python evaluate.py --model-dir ./round_output/ --rounds 1 2 3 --data-dir ./data/raw
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click
import torch
import torch.nn as nn
from torch.utils.data import DataLoader
from rich.console import Console
from rich.table import Table

sys.path.insert(0, str(Path(__file__).parent))

from model.mlp import MNISTMlp, get_model_hash, load_model
from data.mnist_data import load_mnist

console = Console()


def evaluate_model(model: MNISTMlp, test_dataset) -> dict:
    """Evaluate *model* on *test_dataset* and return accuracy + loss."""
    model.eval()
    loader = DataLoader(test_dataset, batch_size=256, shuffle=False)
    criterion = nn.NLLLoss()

    total_loss = 0.0
    correct = 0
    total = 0

    with torch.no_grad():
        for images, labels in loader:
            output = model(images)
            loss = criterion(output, labels)
            total_loss += loss.item() * labels.size(0)
            preds = output.argmax(dim=1)
            correct += (preds == labels).sum().item()
            total += labels.size(0)

    return {
        "accuracy": correct / total if total > 0 else 0.0,
        "loss": total_loss / total if total > 0 else float("inf"),
        "correct": correct,
        "total": total,
    }


@click.command()
@click.option(
    "--model-dir",
    default="./round_output",
    show_default=True,
    help="Directory containing global_model_round_N.pt files.",
)
@click.option(
    "--rounds",
    multiple=True,
    type=int,
    default=[1],
    show_default=True,
    help="Round numbers to evaluate (repeatable: --rounds 1 --rounds 2 ...).",
)
@click.option(
    "--data-dir",
    default="./data/raw",
    show_default=True,
    help="MNIST data directory.",
)
@click.option(
    "--show-hash",
    is_flag=True,
    default=False,
    help="Include model hash column in the output table.",
)
def main(model_dir: str, rounds: tuple, data_dir: str, show_hash: bool) -> None:
    """Evaluate FL global models across rounds and print a summary table."""
    model_dir_path = Path(model_dir)

    console.rule("[bold cyan]FL Model Evaluation[/bold cyan]")
    console.print(f"Model directory: [green]{model_dir_path.resolve()}[/green]")
    console.print(f"Rounds to evaluate: {list(rounds)}")

    # Load test dataset once.
    console.print("\nLoading MNIST test set...")
    _, test_dataset = load_mnist(data_dir=data_dir)
    console.print(f"  Test samples: {len(test_dataset):,}\n")

    # Build results table.
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Round", style="bold", justify="right")
    table.add_column("Accuracy", justify="right")
    table.add_column("Loss", justify="right")
    table.add_column("Correct / Total", justify="right")
    if show_hash:
        table.add_column("Model Hash (first 16)", style="dim")

    results = []
    missing = []

    for round_id in sorted(rounds):
        model_path = model_dir_path / f"global_model_round_{round_id}.pt"
        if not model_path.exists():
            console.print(f"  [yellow]Round {round_id}: model not found at {model_path}[/yellow]")
            missing.append(round_id)
            continue

        model = load_model(str(model_path))
        metrics = evaluate_model(model, test_dataset)
        results.append({"round": round_id, **metrics, "model_hash": get_model_hash(model)})

        acc_str = f"{metrics['accuracy'] * 100:.2f}%"
        loss_str = f"{metrics['loss']:.4f}"
        ct_str = f"{metrics['correct']:,} / {metrics['total']:,}"

        row = [str(round_id), acc_str, loss_str, ct_str]
        if show_hash:
            row.append(get_model_hash(model)[:16] + "...")
        table.add_row(*row)

    console.print(table)

    # Also load aggregation_metadata.json if present (for cross-reference).
    meta_path = model_dir_path / "aggregation_metadata.json"
    if meta_path.exists():
        with open(meta_path, encoding="utf-8") as fh:
            meta = json.load(fh)
        console.print(
            f"\n[dim]Aggregation metadata found: round {meta.get('round_id')}, "
            f"clients={meta.get('num_clients')}, "
            f"aggregated_norm={meta.get('aggregated_norm', 0):.4f}[/dim]"
        )

    if missing:
        console.print(
            f"\n[yellow]Missing model files for rounds: {missing}[/yellow]"
        )

    if results:
        best = max(results, key=lambda r: r["accuracy"])
        console.print(
            f"\n[bold green]Best accuracy:[/bold green] Round {best['round']} — "
            f"{best['accuracy'] * 100:.2f}% (loss={best['loss']:.4f})"
        )

    console.rule()


if __name__ == "__main__":
    main()
