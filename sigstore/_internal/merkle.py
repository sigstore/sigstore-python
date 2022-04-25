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


def _decomp_inclusion_proof(index: int, size: int) -> Tuple[int, int]:
    inner = (index ^ (size - 1)).bit_length()
    border = bin(index >> inner).count("1")
    return inner, border


def _chain_inner(seed: bytes, hashes: List[str], log_index: int) -> bytes:
    for i in range(len(hashes)):
        h = bytes.fromhex(hashes[i])
        if (log_index >> i) & 1:
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
    data = struct.pack(pattern, 1, lhs, rhs)
    return hashlib.sha256(data).digest()


def verify_merkle_inclusion(
    inclusion_proof: RekorInclusionProof, entry: RekorEntry
) -> None:
    """Verify the Merkle Inclusion Proof for a given Rekor entry"""
    leaf_hash = hashlib.sha256(base64.b64decode(entry.body)).digest()

    # TODO(alex): Use pydantic for this
    if inclusion_proof.log_index < 0:
        raise InvalidInclusionProofError(
            f"Inclusion proof has invalid log index: {inclusion_proof.log_index} < 0"
        )

    if inclusion_proof.tree_size < 0:
        raise InvalidInclusionProofError(
            f"Inclusion proof has invalid tree size: {inclusion_proof.tree_size} < 0"
        )

    if inclusion_proof.log_index >= inclusion_proof.tree_size:
        raise InvalidInclusionProofError(
            f"Inclusion proof has log index greater than tree size: {inclusion_proof.log_index} >= "
            f"{inclusion_proof.tree_size}"
        )

    inner, border = _decomp_inclusion_proof(
        inclusion_proof.log_index, inclusion_proof.tree_size
    )

    if len(inclusion_proof.hashes) != (inner + border):
        raise InvalidInclusionProofError(
            f"Inclusion proof has wrong size: expected {inner + border}, got "
            f"{len(inclusion_proof.hashes)}"
        )

    result = _chain_inner(
        leaf_hash, inclusion_proof.hashes[:inner], inclusion_proof.log_index
    )
    result = _chain_border_right(result, inclusion_proof.hashes[inner:])
    print(f"Calculated a root hash of {result.hex()}")
    print(f"Proof: {inclusion_proof}")
