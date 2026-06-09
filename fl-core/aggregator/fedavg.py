"""
FedAvg aggregator for the zkFL system.

Responsibilities:
  - Collect client gradient updates (weight deltas).
  - Optionally verify norm proofs via the Rust `zkfl-prover` binary.
  - Run FedAvg to produce the new global model.
  - Evaluate the global model on a held-out test set.
  - Persist aggregation metadata (JSON) for the ZK prover and Cardano coordinator.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import numpy as np
import torch
import torch.nn as nn
from torch.utils.data import DataLoader

from model.mlp import (
    MNISTMlp,
    flat_array_to_model,
    get_model_hash,
    model_to_flat_array,
)


class FLAggregator:
    """FedAvg aggregator with optional ZK norm-proof verification."""

    def __init__(self, model_template: MNISTMlp, num_clients: int):
        """
        Args:
            model_template: An (initialised) MNISTMlp — used to infer parameter shapes.
            num_clients:    Expected number of participating clients this round.
        """
        self.model_template = model_template
        self.num_clients = num_clients
        self._round_id: int = 0

        # Accumulated updates keyed by client_id.
        self._updates: Dict[int, np.ndarray] = {}
        self._norm_verified: Dict[int, bool] = {}
        self._signatures: Dict[int, str] = {}
        self._public_keys: Dict[int, str] = {}
        self._client_metadata: Dict[int, dict] = {}

    # ------------------------------------------------------------------
    # Receiving updates
    # ------------------------------------------------------------------

    def receive_update(
        self,
        client_id: int,
        gradient_update: np.ndarray,
        norm_proof_path: str = "",
        signature: str = "",
        public_key: str = "",
        extra_metadata: Optional[dict] = None,
    ) -> None:
        """Accept a gradient update from a client.

        Args:
            client_id:       Unique client integer.
            gradient_update: Flat float32 array of weight deltas.
            norm_proof_path: Path to the ZK norm proof JSON (may be empty if not yet proven).
            signature:       Hex Ed25519 signature from the client.
            public_key:      Hex Ed25519 public key of the client.
            extra_metadata:  Any additional metadata to store (e.g., hashes).
        """
        self._updates[client_id] = gradient_update.astype(np.float32)
        self._signatures[client_id] = signature
        self._public_keys[client_id] = public_key
        self._client_metadata[client_id] = extra_metadata or {}

        if norm_proof_path:
            verified = self.verify_norm_proof(norm_proof_path)
            self._norm_verified[client_id] = verified
        else:
            # No proof provided — mark as unverified (acceptable in dev mode).
            self._norm_verified[client_id] = False

    # ------------------------------------------------------------------
    # Norm proof verification (Rust prover subprocess)
    # ------------------------------------------------------------------

    def verify_norm_proof(self, norm_proof_path: str) -> bool:
        """Call the Rust ZK prover to verify a gradient norm proof.

        Executes: ``zkfl-prover verify-norm --proof <path>``

        Returns True if the prover exits with code 0, False otherwise.
        If the binary is not found, returns False and logs a warning.
        """
        try:
            result = subprocess.run(
                ["zkfl-prover", "verify-norm", "--proof", norm_proof_path],
                capture_output=True,
                timeout=30,
            )
            return result.returncode == 0
        except FileNotFoundError:
            # zkfl-prover binary not yet compiled — acceptable during FL-core-only testing.
            print(
                f"[WARN] zkfl-prover binary not found; skipping proof verification for {norm_proof_path}"
            )
            return False
        except subprocess.TimeoutExpired:
            print(f"[WARN] zkfl-prover timed out verifying {norm_proof_path}")
            return False

    # ------------------------------------------------------------------
    # FedAvg
    # ------------------------------------------------------------------

    def run_fedavg(
        self, global_model: MNISTMlp
    ) -> Tuple[MNISTMlp, dict]:
        """Run FedAvg over all received updates.

        Implements uniform averaging (equal weight per client, IID assumption).
        Each client contributed ``num_samples`` ≈ equal, so uniform averaging
        is equivalent to sample-count-weighted averaging in the IID case.

        Args:
            global_model: The current global model (before this round).

        Returns:
            (new_global_model, aggregation_metadata)
        """
        if not self._updates:
            raise RuntimeError("No client updates received.")

        self._round_id += 1
        prev_hash = get_model_hash(global_model)

        # --- FedAvg: average the weight deltas and apply to global model ---
        stacked = np.stack(list(self._updates.values()), axis=0)  # (K, D)
        mean_delta = stacked.mean(axis=0)                          # (D,)
        aggregated_norm = float(np.linalg.norm(mean_delta))

        global_flat = model_to_flat_array(global_model)
        new_flat = global_flat + mean_delta
        new_model = flat_array_to_model(new_flat, global_model)

        new_hash = get_model_hash(new_model)

        # Gradient norm bound: max norm across clients (for ZK constraint).
        per_client_norms = [float(np.linalg.norm(g)) for g in self._updates.values()]
        gradient_norm_bound = float(max(per_client_norms))

        metadata: dict = {
            "round_id": self._round_id,
            "num_clients": len(self._updates),
            "prev_model_hash": prev_hash,
            "new_model_hash": new_hash,
            "gradient_norm_bound": gradient_norm_bound,
            "client_ids": sorted(self._updates.keys()),
            "aggregated_norm": aggregated_norm,
            "per_client_norms": {str(k): v for k, v in zip(self._updates.keys(), per_client_norms)},
            "norm_proofs_verified": {str(k): v for k, v in self._norm_verified.items()},
            "public_keys": {str(k): v for k, v in self._public_keys.items()},
            "signatures": {str(k): v for k, v in self._signatures.items()},
        }

        # Reset state for next round.
        self._updates.clear()
        self._norm_verified.clear()
        self._signatures.clear()
        self._public_keys.clear()
        self._client_metadata.clear()

        return new_model, metadata

    # ------------------------------------------------------------------
    # Hashing and persistence
    # ------------------------------------------------------------------

    def compute_aggregation_hash(self, metadata: dict) -> str:
        """SHA-256 hash of the aggregation metadata (for ZK proof input).

        Only stable fields are included — signatures and per-client norms are
        excluded so the hash can be recomputed deterministically from public data.
        """
        stable = {
            "round_id": metadata["round_id"],
            "num_clients": metadata["num_clients"],
            "prev_model_hash": metadata["prev_model_hash"],
            "new_model_hash": metadata["new_model_hash"],
            "gradient_norm_bound": metadata["gradient_norm_bound"],
            "client_ids": sorted(metadata["client_ids"]),
            "aggregated_norm": metadata["aggregated_norm"],
        }
        canonical = json.dumps(stable, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode()).hexdigest()

    def save_aggregation_metadata(self, metadata: dict, path: str) -> None:
        """Save aggregation metadata JSON for ZK prover and Cardano coordinator."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        # Augment with aggregation hash for convenience.
        output = dict(metadata)
        output["aggregation_hash"] = self.compute_aggregation_hash(metadata)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(output, fh, indent=2)

    # ------------------------------------------------------------------
    # Evaluation
    # ------------------------------------------------------------------

    def evaluate_global_model(self, test_dataset) -> dict:
        """Evaluate the current global model on *test_dataset*.

        Args:
            test_dataset: A torch Dataset (e.g., MNIST test split).

        Returns:
            {"accuracy": float, "loss": float}
        """
        model = self.model_template
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
        }
