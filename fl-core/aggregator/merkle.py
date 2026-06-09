"""
Simple binary Merkle tree for Cardano datum construction.

Used to commit to the set of participating clients and their gradient hashes
in each FL round. The Merkle root is embedded in the Cardano on-chain datum.

All hashing uses SHA-256 with a domain-separation prefix to prevent
second-preimage attacks (following Bitcoin/RFC 6962 conventions):
  - Leaf nodes:  H(0x00 || data)
  - Inner nodes: H(0x01 || left || right)
"""

from __future__ import annotations

import hashlib
import math
from typing import List


# ---------------------------------------------------------------------------
# Low-level hashing helpers
# ---------------------------------------------------------------------------

def _leaf_hash(data: bytes) -> bytes:
    """SHA-256 leaf hash: H(0x00 || data)."""
    return hashlib.sha256(b"\x00" + data).digest()


def _inner_hash(left: bytes, right: bytes) -> bytes:
    """SHA-256 inner-node hash: H(0x01 || left || right)."""
    return hashlib.sha256(b"\x01" + left + right).digest()


# ---------------------------------------------------------------------------
# MerkleTree
# ---------------------------------------------------------------------------

class MerkleTree:
    """Binary Merkle tree with inclusion proofs.

    Leaves are hashed internally; you provide raw bytes (the pre-image).
    If the number of leaves is odd the last leaf is duplicated to form a
    complete binary tree (standard practice).
    """

    def __init__(self, leaves: List[bytes]):
        """
        Args:
            leaves: Raw byte values for each leaf (pre-images).
                    At least one leaf is required.
        """
        if not leaves:
            raise ValueError("MerkleTree requires at least one leaf.")

        self._leaves_raw = list(leaves)
        self._tree: List[List[bytes]] = []  # _tree[0] = leaf level, _tree[-1] = [root]
        self._build()

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def root(self) -> bytes:
        """Return the 32-byte Merkle root."""
        return self._tree[-1][0]

    def proof(self, index: int) -> List[bytes]:
        """Compute a Merkle inclusion proof for the leaf at *index*.

        Returns a list of sibling hashes from leaf level up to (but not
        including) the root.  The verifier reconstructs the root by
        combining the leaf hash with each sibling in order.

        Args:
            index: 0-based index of the leaf.

        Returns:
            List of (sibling_hash, position) — but we return flat bytes here
            and let verify() infer direction from the index.
        """
        n = len(self._tree[0])
        if index < 0 or index >= len(self._leaves_raw):
            raise IndexError(f"Leaf index {index} out of range [0, {len(self._leaves_raw)}).")

        proof_hashes: List[bytes] = []
        idx = index
        for level in self._tree[:-1]:   # exclude root level
            sibling_idx = idx ^ 1       # XOR with 1 flips last bit → sibling
            if sibling_idx < len(level):
                proof_hashes.append(level[sibling_idx])
            else:
                # Odd level — sibling is the node itself (duplication)
                proof_hashes.append(level[idx])
            idx //= 2

        return proof_hashes

    @staticmethod
    def verify(root: bytes, leaf: bytes, proof: List[bytes], index: int) -> bool:
        """Verify a Merkle inclusion proof.

        Args:
            root:  Expected 32-byte Merkle root.
            leaf:  Raw leaf pre-image (bytes).
            proof: List of sibling hashes returned by proof().
            index: 0-based leaf index.

        Returns:
            True if the proof is valid (reconstructed root matches *root*).
        """
        current = _leaf_hash(leaf)
        idx = index
        for sibling in proof:
            if idx % 2 == 0:
                current = _inner_hash(current, sibling)
            else:
                current = _inner_hash(sibling, current)
            idx //= 2
        return current == root

    # ------------------------------------------------------------------
    # Internal build
    # ------------------------------------------------------------------

    def _build(self) -> None:
        """Build the full tree bottom-up."""
        # Leaf level
        level = [_leaf_hash(leaf) for leaf in self._leaves_raw]
        self._tree = [level]

        while len(level) > 1:
            next_level: List[bytes] = []
            # Pad with duplicate if odd
            nodes = level if len(level) % 2 == 0 else level + [level[-1]]
            for i in range(0, len(nodes), 2):
                next_level.append(_inner_hash(nodes[i], nodes[i + 1]))
            self._tree.append(next_level)
            level = next_level


# ---------------------------------------------------------------------------
# Convenience builders
# ---------------------------------------------------------------------------

def build_participant_tree(client_updates: List[dict]) -> MerkleTree:
    """Build a Merkle tree from a list of client update dicts.

    The leaf pre-image for each client is:
        SHA-256(client_id_bytes || model_hash_after_bytes || data_hash_bytes)
    This binds the client identity to their specific gradient contribution.

    Args:
        client_updates: List of dicts as returned by FLClient.local_train(),
                        sorted by client_id for determinism.

    Returns:
        A MerkleTree whose root commits to all participant update hashes.
    """
    sorted_updates = sorted(client_updates, key=lambda u: u["client_id"])
    leaves: List[bytes] = []
    for upd in sorted_updates:
        cid_bytes = upd["client_id"].to_bytes(4, "big")
        after_bytes = upd["model_hash_after"].encode()
        data_bytes = upd["data_hash"].encode()
        leaf_preimage = hashlib.sha256(cid_bytes + after_bytes + data_bytes).digest()
        leaves.append(leaf_preimage)
    return MerkleTree(leaves)


def build_gradient_hash_tree(gradient_hashes: List[str]) -> MerkleTree:
    """Build a Merkle tree from a list of hex-encoded gradient commitment hashes.

    Args:
        gradient_hashes: List of hex strings (SHA-256 of each client's gradient bytes),
                         in client order.

    Returns:
        A MerkleTree whose root commits to all gradient hashes.
    """
    leaves = [bytes.fromhex(h) for h in gradient_hashes]
    return MerkleTree(leaves)


def gradient_hash(gradient_update) -> str:
    """SHA-256 hex hash of a flat gradient array (for use in gradient hash trees)."""
    import numpy as np
    arr = np.asarray(gradient_update, dtype=np.float32)
    return hashlib.sha256(arr.tobytes()).hexdigest()
