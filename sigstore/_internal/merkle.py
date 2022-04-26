"""
Utilities for verifying proof-of-inclusion within Rekor's Merkle Tree.
"""

import base64
import hashlib
import struct
from typing import List, Tuple

from sigstore._internal.rekor import RekorEntry, RekorInclusionProof


class InvalidInclusionProofError(Exception):
    pass


LEAF_HASH_PREFIX = 0
NODE_HASH_PREFIX = 1


def _decomp_inclusion_proof(index: int, size: int) -> Tuple[int, int]:
    inner = (index ^ (size - 1)).bit_length()
    border = bin(index >> inner).count("1")
    return inner, border


def _chain_inner(seed: bytes, hashes: List[str], log_index: int) -> bytes:
    for i in range(len(hashes)):
        h = bytes.fromhex(hashes[i])
        if (log_index >> i) & 1 == 0:
            seed = _hash_children(seed, h)
        else:
            seed = _hash_children(h, seed)
    return seed


def _chain_border_right(seed: bytes, hashes: List[str]) -> bytes:
    for h in hashes:
        seed = _hash_children(bytes.fromhex(h), seed)
    return seed


def _hash_children(lhs: bytes, rhs: bytes) -> bytes:
    pattern = f"B{len(lhs)}s{len(rhs)}s"
    data = struct.pack(pattern, NODE_HASH_PREFIX, lhs, rhs)
    return hashlib.sha256(data).digest()


def _hash_leaf(leaf: bytes) -> bytes:
    pattern = f"B{len(leaf)}s"
    data = struct.pack(pattern, LEAF_HASH_PREFIX, leaf)
    return hashlib.sha256(data).digest()


def verify_merkle_inclusion(
    inclusion_proof: RekorInclusionProof, entry: RekorEntry
) -> None:
    """Verify the Merkle Inclusion Proof for a given Rekor entry"""

    inner, border = _decomp_inclusion_proof(
        inclusion_proof.log_index, inclusion_proof.tree_size
    )

    if len(inclusion_proof.hashes) != (inner + border):
        raise InvalidInclusionProofError(
            f"Inclusion proof has wrong size: expected {inner + border}, got "
            f"{len(inclusion_proof.hashes)}"
        )

    leaf_hash: bytes = _hash_leaf(base64.b64decode(entry.body))

    intermediate_result: bytes = _chain_inner(
        leaf_hash, inclusion_proof.hashes[:inner], inclusion_proof.log_index
    )

    calc_hash: str = _chain_border_right(
        intermediate_result, inclusion_proof.hashes[inner:]
    ).hex()

    if calc_hash != inclusion_proof.root_hash:
        raise InvalidInclusionProofError(
            f"Inclusion proof contains invalid root hash: expected {inclusion_proof}, calculated "
            f"{calc_hash}"
        )
