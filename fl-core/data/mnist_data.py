"""
MNIST data loading and client partitioning for federated learning.

Provides non-overlapping IID shards for each client.
"""

from __future__ import annotations

from typing import List

import torch
from torch.utils.data import DataLoader, Subset
from torchvision import datasets, transforms


# ---------------------------------------------------------------------------
# Default transform: normalise to [-1, 1] (common for MNIST)
# ---------------------------------------------------------------------------
_MNIST_TRANSFORM = transforms.Compose([
    transforms.ToTensor(),
    transforms.Normalize((0.1307,), (0.3081,)),   # MNIST mean / std
])


def load_mnist(data_dir: str = "./data/raw") -> tuple:
    """Download (if needed) and return (train_dataset, test_dataset).

    Uses standard MNIST normalisation.
    """
    train_dataset = datasets.MNIST(
        root=data_dir,
        train=True,
        download=True,
        transform=_MNIST_TRANSFORM,
    )
    test_dataset = datasets.MNIST(
        root=data_dir,
        train=False,
        download=True,
        transform=_MNIST_TRANSFORM,
    )
    return train_dataset, test_dataset


def partition_data(
    dataset,
    num_clients: int,
    seed: int = 42,
) -> List[Subset]:
    """Partition *dataset* into *num_clients* non-overlapping equal-sized shards.

    Args:
        dataset:     A torchvision Dataset (e.g., the training set from load_mnist).
        num_clients: Number of FL clients.
        seed:        Random seed for reproducible shuffling.

    Returns:
        List of ``torch.utils.data.Subset`` objects, one per client.
        Each subset has ``len(dataset) // num_clients`` samples (remainder is discarded).
    """
    rng = torch.Generator()
    rng.manual_seed(seed)

    n = len(dataset)
    shard_size = n // num_clients

    # Shuffle indices
    perm = torch.randperm(n, generator=rng).tolist()

    subsets: List[Subset] = []
    for i in range(num_clients):
        start = i * shard_size
        end = start + shard_size
        indices = perm[start:end]
        subsets.append(Subset(dataset, indices))

    return subsets


def get_dataloader(
    subset: Subset,
    batch_size: int = 32,
    shuffle: bool = True,
    num_workers: int = 0,
) -> DataLoader:
    """Wrap a dataset subset in a DataLoader.

    Args:
        subset:      A Subset returned by partition_data (or any Dataset).
        batch_size:  Mini-batch size.
        shuffle:     Whether to shuffle each epoch.
        num_workers: Number of worker processes (0 = single-threaded, safe on all platforms).

    Returns:
        A ready-to-iterate DataLoader.
    """
    return DataLoader(
        subset,
        batch_size=batch_size,
        shuffle=shuffle,
        num_workers=num_workers,
        pin_memory=False,
    )
