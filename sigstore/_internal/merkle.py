# Copyright 2022 The Sigstore Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Utilities for verifying proof-of-inclusion within Rekor's Merkle Tree.

This code is based off Google's Trillian Merkle Tree implementation which Cosign uses to validate
Rekor entries.

The data format for the Merkle tree nodes is described in IETF's RFC 6962.
"""

from __future__ import annotations

import hashlib

from sigstore.errors import VerificationError

_LEAF_HASH_PREFIX = b"\x00"
_NODE_HASH_PREFIX = b"\x01"
_SHA256_DIGEST_SIZE = hashlib.sha256().digest_size


def _decomp_inclusion_proof(index: int, size: int) -> tuple[int, int]:
    """
    Breaks down inclusion proof for a leaf at the specified |index| in a tree of the specified
    |size| into 2 components. The splitting point between them is where paths to leaves |index| and
    |size-1| diverge.

    Returns lengths of the bottom and upper proof parts correspondingly. The sum of the two
    determines the correct length of the inclusion proof.
    """

    inner = (index ^ (size - 1)).bit_length()
    border = (index >> inner).bit_count()
    return inner, border


def _chain_inner(seed: bytes, hashes: list[bytes], log_index: int) -> bytes:
    """
    Computes a subtree hash for a node on or below the tree's right border. Assumes |proof| hashes
    are ordered from lower levels to upper, and |seed| is the initial subtree/leaf hash on the path
    located at the specified |index| on its level.
    """

    for i, h in enumerate(hashes):
        if (log_index >> i) & 1 == 0:
            seed = hash_children(seed, h)
        else:
            seed = hash_children(h, seed)
    return seed


def _chain_border_right(seed: bytes, hashes: list[bytes]) -> bytes:
    """
    Chains proof hashes along tree borders. This differs from inner chaining because |proof|
    contains only left-side subtree hashes.
    """

    for h in hashes:
        seed = hash_children(h, seed)
    return seed


def hash_children(lhs: bytes, rhs: bytes) -> bytes:
    """
    Compute the RFC 6962 interior node hash ``SHA256(0x01 || lhs || rhs)``.
    """
    return hashlib.sha256(_NODE_HASH_PREFIX + lhs + rhs).digest()


def hash_leaf(leaf: bytes) -> bytes:
    """
    Compute the RFC 6962 leaf node hash ``SHA256(0x00 || leaf)``.
    """
    return hashlib.sha256(_LEAF_HASH_PREFIX + leaf).digest()


def verify_merkle_inclusion(
    *,
    log_index: int,
    tree_size: int,
    leaf_hash: bytes,
    hashes: list[bytes],
    root_hash: bytes,
) -> None:
    """
    Verify an RFC 6962 Merkle inclusion proof for ``leaf_hash`` at ``log_index``
    against ``tree_size`` and ``root_hash``.
    """
    if len(leaf_hash) != _SHA256_DIGEST_SIZE:
        raise VerificationError(
            f"inclusion proof: leaf_hash must be 32 bytes, got {len(leaf_hash)}"
        )
    if len(root_hash) != _SHA256_DIGEST_SIZE:
        raise VerificationError(
            f"inclusion proof: root_hash must be 32 bytes, got {len(root_hash)}"
        )
    if tree_size <= 0 or log_index < 0 or log_index >= tree_size:
        raise VerificationError(
            f"inclusion proof: index {log_index} out of bounds for tree size {tree_size}"
        )

    inner, border = _decomp_inclusion_proof(log_index, tree_size)
    if len(hashes) != (inner + border):
        raise VerificationError(
            f"inclusion proof has wrong size: expected {inner + border}, got "
            f"{len(hashes)}"
        )

    intermediate_result = _chain_inner(leaf_hash, hashes[:inner], log_index)
    calc_hash = _chain_border_right(intermediate_result, hashes[inner:])

    if calc_hash != root_hash:
        raise VerificationError(
            "inclusion proof contains invalid root hash: "
            f"expected {root_hash.hex()}, calculated {calc_hash.hex()}"
        )
