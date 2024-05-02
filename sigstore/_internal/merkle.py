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

import base64
import hashlib
import struct
import typing
from typing import List, Tuple

from sigstore._utils import HexStr
from sigstore.errors import VerificationError

if typing.TYPE_CHECKING:
    from sigstore.models import LogEntry


_LEAF_HASH_PREFIX = 0
_NODE_HASH_PREFIX = 1


def _decomp_inclusion_proof(index: int, size: int) -> Tuple[int, int]:
    """
    Breaks down inclusion proof for a leaf at the specified |index| in a tree of the specified
    |size| into 2 components. The splitting point between them is where paths to leaves |index| and
    |size-1| diverge.

    Returns lengths of the bottom and upper proof parts correspondingly. The sum of the two
    determines the correct length of the inclusion proof.
    """

    inner = (index ^ (size - 1)).bit_length()
    border = bin(index >> inner).count("1")
    return inner, border


def _chain_inner(seed: bytes, hashes: List[str], log_index: int) -> bytes:
    """
    Computes a subtree hash for a node on or below the tree's right border. Assumes |proof| hashes
    are ordered from lower levels to upper, and |seed| is the initial subtree/leaf hash on the path
    located at the specified |index| on its level.
    """

    for i in range(len(hashes)):
        h = bytes.fromhex(hashes[i])
        if (log_index >> i) & 1 == 0:
            seed = _hash_children(seed, h)
        else:
            seed = _hash_children(h, seed)
    return seed


def _chain_border_right(seed: bytes, hashes: List[str]) -> bytes:
    """
    Chains proof hashes along tree borders. This differs from inner chaining because |proof|
    contains only left-side subtree hashes.
    """

    for h in hashes:
        seed = _hash_children(bytes.fromhex(h), seed)
    return seed


def _hash_children(lhs: bytes, rhs: bytes) -> bytes:
    pattern = f"B{len(lhs)}s{len(rhs)}s"
    data = struct.pack(pattern, _NODE_HASH_PREFIX, lhs, rhs)
    return hashlib.sha256(data).digest()


def _hash_leaf(leaf: bytes) -> bytes:
    pattern = f"B{len(leaf)}s"
    data = struct.pack(pattern, _LEAF_HASH_PREFIX, leaf)
    return hashlib.sha256(data).digest()


def verify_merkle_inclusion(entry: LogEntry) -> None:
    """Verify the Merkle Inclusion Proof for a given Rekor entry."""
    inclusion_proof = entry.inclusion_proof

    # Figure out which subset of hashes corresponds to the inner and border nodes.
    inner, border = _decomp_inclusion_proof(
        inclusion_proof.log_index, inclusion_proof.tree_size
    )

    # Check against the number of hashes.
    if len(inclusion_proof.hashes) != (inner + border):
        raise VerificationError(
            f"inclusion proof has wrong size: expected {inner + border}, got "
            f"{len(inclusion_proof.hashes)}"
        )

    # The new entry's hash isn't included in the inclusion proof so we should calculate this
    # ourselves.
    leaf_hash: bytes = _hash_leaf(base64.b64decode(entry.body))

    # Now chain the hashes belonging to the inner and border portions. We should expect the
    # calculated hash to match the root hash.
    intermediate_result: bytes = _chain_inner(
        leaf_hash, inclusion_proof.hashes[:inner], inclusion_proof.log_index
    )

    calc_hash: HexStr = HexStr(
        _chain_border_right(intermediate_result, inclusion_proof.hashes[inner:]).hex()
    )

    if calc_hash != inclusion_proof.root_hash:
        raise VerificationError(
            f"inclusion proof contains invalid root hash: expected {inclusion_proof}, calculated "
            f"{calc_hash}"
        )
