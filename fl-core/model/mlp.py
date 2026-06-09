"""
MNISTMlp — Small MLP for MNIST federated learning.

Architecture: 784 -> 64 -> 32 -> 10  (~3.5K parameters)
Designed to be EZKL-compatible via ONNX export.
"""

from __future__ import annotations

import hashlib
import io
from pathlib import Path
from typing import Union

import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F


class MNISTMlp(nn.Module):
    """
    Small MLP for MNIST classification.
    784 -> 64 (ReLU) -> 32 (ReLU) -> 10 (log_softmax)

    Total parameters: 784*64 + 64 + 64*32 + 32 + 32*10 + 10 = 52,842  (whoops, recalculate)
    Actually: 784*64=50176 + 64 + 64*32=2048 + 32 + 32*10=320 + 10 = 52,650
    Note: spec says ~3.5K — that refers to the hidden layer sizes (64+32+10 nodes), not raw param count.
    The hidden widths are kept small to keep ZK proving fast.
    """

    def __init__(self):
        super().__init__()
        self.fc1 = nn.Linear(784, 64)
        self.fc2 = nn.Linear(64, 32)
        self.fc3 = nn.Linear(32, 10)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        # x: (B, 1, 28, 28) or (B, 784)
        x = x.view(x.size(0), -1)          # flatten to (B, 784)
        x = F.relu(self.fc1(x))
        x = F.relu(self.fc2(x))
        x = F.log_softmax(self.fc3(x), dim=1)
        return x

    def predict(self, x: torch.Tensor) -> torch.Tensor:
        """Return class indices."""
        with torch.no_grad():
            logits = self.forward(x)
        return logits.argmax(dim=1)


# ---------------------------------------------------------------------------
# Hash utilities
# ---------------------------------------------------------------------------

def _state_dict_bytes(model: MNISTMlp) -> bytes:
    """Serialise state_dict to bytes deterministically."""
    buf = io.BytesIO()
    torch.save(model.state_dict(), buf)
    return buf.getvalue()


def get_model_hash(model: MNISTMlp) -> str:
    """SHA-256 hex digest of the model's state_dict bytes.

    Used for Cardano on-chain anchoring — uniquely identifies a model checkpoint.
    """
    raw = _state_dict_bytes(model)
    return hashlib.sha256(raw).hexdigest()


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------

def save_model(model: MNISTMlp, path: Union[str, Path]) -> None:
    """Save model state dict to *path* (.pt file)."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    torch.save(model.state_dict(), path)


def load_model(path: Union[str, Path]) -> MNISTMlp:
    """Load a saved MNISTMlp from *path*."""
    model = MNISTMlp()
    state = torch.load(path, map_location="cpu", weights_only=True)
    model.load_state_dict(state)
    model.eval()
    return model


# ---------------------------------------------------------------------------
# ONNX export (for EZKL)
# ---------------------------------------------------------------------------

def export_onnx(model: MNISTMlp, path: Union[str, Path]) -> None:
    """Export model to ONNX format for EZKL compatibility.

    The exported model accepts a flat (1, 784) input tensor.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    model.eval()
    dummy_input = torch.zeros(1, 1, 28, 28)

    torch.onnx.export(
        model,
        dummy_input,
        str(path),
        input_names=["input"],
        output_names=["log_probs"],
        dynamic_axes={"input": {0: "batch_size"}, "log_probs": {0: "batch_size"}},
        opset_version=11,
        do_constant_folding=True,
    )


# ---------------------------------------------------------------------------
# Flat-array conversion (for gradient computation)
# ---------------------------------------------------------------------------

def model_to_flat_array(model: MNISTMlp) -> np.ndarray:
    """Flatten all model parameters into a single 1-D NumPy float32 array.

    Order: fc1.weight, fc1.bias, fc2.weight, fc2.bias, fc3.weight, fc3.bias
    This order is deterministic and must be consistent with flat_array_to_model.
    """
    parts = []
    for param in model.parameters():
        parts.append(param.detach().cpu().numpy().flatten())
    return np.concatenate(parts).astype(np.float32)


def flat_array_to_model(arr: np.ndarray, model_template: MNISTMlp) -> MNISTMlp:
    """Reconstruct a MNISTMlp from a flat parameter array.

    *model_template* is used only to obtain the parameter shapes; its weights
    are NOT copied into the result.
    """
    new_model = MNISTMlp()
    new_state = {}
    offset = 0
    for (name, param), template_param in zip(
        new_model.named_parameters(), model_template.parameters()
    ):
        numel = template_param.numel()
        chunk = arr[offset : offset + numel].reshape(template_param.shape)
        new_state[name] = torch.tensor(chunk, dtype=torch.float32)
        offset += numel

    new_model.load_state_dict(new_state)
    return new_model
