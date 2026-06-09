"""
Federated Learning client.

Each client:
  1. Holds a local data shard.
  2. Accepts a global model.
  3. Trains locally and returns a gradient update (weight delta).
  4. Signs the update hash with its Ed25519 key.
  5. Saves a JSON file for the Rust ZK prover.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Optional

import numpy as np
import torch
import torch.nn as nn
import torch.optim as optim

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from model.mlp import (
    MNISTMlp,
    flat_array_to_model,
    get_model_hash,
    model_to_flat_array,
)
from data.mnist_data import get_dataloader


class FLClient:
    """A single FL client that trains locally and returns gradient updates."""

    def __init__(self, client_id: int, data_subset, device: str = "cpu"):
        """
        Args:
            client_id:    Unique integer ID for this client.
            data_subset:  A torch Dataset subset (from partition_data).
            device:       Torch device string ('cpu' recommended).
        """
        self.client_id = client_id
        self.data_subset = data_subset
        self.device = torch.device(device)

        # Local model — starts uninitialised; must call set_global_model first.
        self.model: Optional[MNISTMlp] = None
        self._round_id: int = 0

        # Generate Ed25519 key pair once at client creation.
        self._private_key: Ed25519PrivateKey = Ed25519PrivateKey.generate()

    # ------------------------------------------------------------------
    # Model management
    # ------------------------------------------------------------------

    def set_global_model(self, state_dict: dict) -> None:
        """Download and apply the global model weights."""
        if self.model is None:
            self.model = MNISTMlp()
        self.model.load_state_dict(state_dict)
        self.model.to(self.device)

    # ------------------------------------------------------------------
    # Local training
    # ------------------------------------------------------------------

    def local_train(self, epochs: int = 1, lr: float = 0.01) -> dict:
        """Train locally for *epochs* passes over the local shard.

        Returns a dict with:
            client_id, round_id, gradient_update (flat np.ndarray),
            gradient_norm (float), model_hash_before, model_hash_after,
            data_hash, num_samples.
        """
        if self.model is None:
            raise RuntimeError("Call set_global_model() before local_train().")

        self._round_id += 1
        self.model.train()

        # Snapshot weights BEFORE training.
        weights_before = model_to_flat_array(self.model).copy()
        hash_before = get_model_hash(self.model)
        data_hash = self._compute_data_hash()

        loader = get_dataloader(self.data_subset, batch_size=32, shuffle=True)
        criterion = nn.NLLLoss()
        optimizer = optim.SGD(self.model.parameters(), lr=lr, momentum=0.9)

        for _ in range(epochs):
            for images, labels in loader:
                images = images.to(self.device)
                labels = labels.to(self.device)
                optimizer.zero_grad()
                output = self.model(images)
                loss = criterion(output, labels)
                loss.backward()
                optimizer.step()

        self.model.eval()

        # Compute gradient update = new_weights - old_weights (weight delta).
        weights_after = model_to_flat_array(self.model)
        gradient_update = weights_after - weights_before
        gradient_norm = float(np.linalg.norm(gradient_update))
        hash_after = get_model_hash(self.model)

        return {
            "client_id": self.client_id,
            "round_id": self._round_id,
            "gradient_update": gradient_update,
            "gradient_norm": gradient_norm,
            "model_hash_before": hash_before,
            "model_hash_after": hash_after,
            "data_hash": data_hash,
            "num_samples": len(self.data_subset),
        }

    # ------------------------------------------------------------------
    # Signing
    # ------------------------------------------------------------------

    def sign_update(self, update: dict, private_key_bytes: bytes) -> str:
        """Sign the gradient_update hash with an Ed25519 private key.

        Args:
            update:            The dict returned by local_train().
            private_key_bytes: Raw 32-byte Ed25519 private key seed.

        Returns:
            Hex-encoded 64-byte Ed25519 signature over SHA-256(gradient_update bytes).
        """
        key = Ed25519PrivateKey.from_private_bytes(private_key_bytes)
        message = self._gradient_message(update)
        sig = key.sign(message)
        return sig.hex()

    def get_public_key(self) -> str:
        """Return the hex-encoded 32-byte Ed25519 public key."""
        pub = self._private_key.public_key()
        raw = pub.public_bytes(Encoding.Raw, PublicFormat.Raw)
        return raw.hex()

    def get_private_key_bytes(self) -> bytes:
        """Return the raw 32-byte private key seed (for sign_update)."""
        return self._private_key.private_bytes(
            Encoding.Raw, PrivateFormat.Raw, NoEncryption()
        )

    def sign_update_self(self, update: dict) -> str:
        """Convenience: sign with this client's own private key."""
        return self.sign_update(update, self.get_private_key_bytes())

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def save_gradients_json(self, update: dict, path: str) -> None:
        """Save gradient update to a JSON file for the Rust ZK prover.

        Format:
        {
            "gradients": [float, ...],
            "norm": float,
            "client_id": int,
            "round_id": int,
            "model_hash_before": str,
            "model_hash_after": str,
            "data_hash": str,
            "num_samples": int,
            "public_key": str
        }
        """
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)

        payload = {
            "gradients": update["gradient_update"].tolist(),
            "norm": update["gradient_norm"],
            "client_id": update["client_id"],
            "round_id": update["round_id"],
            "model_hash_before": update["model_hash_before"],
            "model_hash_after": update["model_hash_after"],
            "data_hash": update["data_hash"],
            "num_samples": update["num_samples"],
            "public_key": self.get_public_key(),
        }
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _compute_data_hash(self) -> str:
        """SHA-256 commitment over the local data indices (as a data commitment)."""
        indices = sorted(self.data_subset.indices)
        raw = json.dumps(indices, separators=(",", ":")).encode()
        return hashlib.sha256(raw).hexdigest()

    @staticmethod
    def _gradient_message(update: dict) -> bytes:
        """Canonical byte string that is signed / verified."""
        payload = {
            "client_id": update["client_id"],
            "round_id": update["round_id"],
            "gradient_norm": update["gradient_norm"],
            "model_hash_before": update["model_hash_before"],
            "model_hash_after": update["model_hash_after"],
            "data_hash": update["data_hash"],
        }
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode()).digest()
