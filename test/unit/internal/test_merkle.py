# Copyright 2026 The Sigstore Authors
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

import hashlib
from typing import Any

import pytest

from sigstore._internal.merkle import (
    _chain_border_right,
    _chain_inner,
    _decomp_inclusion_proof,
    hash_children,
    hash_leaf,
    verify_merkle_inclusion,
)
from sigstore.errors import VerificationError
from sigstore.models import Bundle


def test_hash_leaf_and_children() -> None:
    leaf_data = b"some leaf data"
    l0 = hash_leaf(leaf_data)
    assert l0 == hashlib.sha256(b"\x00" + leaf_data).digest()

    l1 = hash_leaf(b"other leaf data")
    node = hash_children(l0, l1)
    assert node == hashlib.sha256(b"\x01" + l0 + l1).digest()


@pytest.mark.parametrize(
    ("index", "size", "expected"),
    [
        (0, 1, (0, 0)),
        (0, 2, (1, 0)),
        (1, 2, (0, 1)),
        (0, 3, (2, 0)),
        (1, 3, (2, 0)),
        (2, 3, (0, 1)),
        (2, 4, (1, 1)),
        (4, 5, (0, 1)),
        (5, 6, (0, 2)),
        (6, 7, (0, 2)),
    ],
)
def test_decomp_inclusion_proof(
    index: int, size: int, expected: tuple[int, int]
) -> None:
    assert _decomp_inclusion_proof(index, size) == expected


def test_chain_inner_and_border_right() -> None:
    # Build a 3-leaf tree:
    #       root
    #      /    \
    #    n01     l2
    #   /   \
    #  l0   l1
    l0 = hash_leaf(b"leaf-0")
    l1 = hash_leaf(b"leaf-1")
    l2 = hash_leaf(b"leaf-2")
    n01 = hash_children(l0, l1)
    root = hash_children(n01, l2)

    # Leaf 1 (index=1, size=3): inner=2, border=0
    inner, border = _decomp_inclusion_proof(1, 3)
    assert (inner, border) == (2, 0)
    assert _chain_border_right(_chain_inner(l1, [l0, l2], 1), []) == root

    # Leaf 2 (index=2, size=3): inner=0, border=1
    inner, border = _decomp_inclusion_proof(2, 3)
    assert (inner, border) == (0, 1)
    assert _chain_border_right(_chain_inner(l2, [], 2), [n01]) == root


def test_verify_merkle_inclusion() -> None:
    l0 = hash_leaf(b"leaf-0")
    l1 = hash_leaf(b"leaf-1")
    root = hash_children(l0, l1)

    verify_merkle_inclusion(
        log_index=0,
        tree_size=2,
        leaf_hash=l0,
        hashes=[l1],
        root_hash=root,
    )

    with pytest.raises(VerificationError, match="leaf_hash must be 32 bytes"):
        verify_merkle_inclusion(
            log_index=0,
            tree_size=2,
            leaf_hash=b"short",
            hashes=[l1],
            root_hash=root,
        )

    with pytest.raises(VerificationError, match="root_hash must be 32 bytes"):
        verify_merkle_inclusion(
            log_index=0,
            tree_size=2,
            leaf_hash=l0,
            hashes=[l1],
            root_hash=b"short",
        )

    with pytest.raises(VerificationError, match="out of bounds"):
        verify_merkle_inclusion(
            log_index=2,
            tree_size=2,
            leaf_hash=l0,
            hashes=[l1],
            root_hash=root,
        )


def test_transparency_log_entry_verify_merkle_inclusion_valid(asset: Any) -> None:
    bundle = Bundle.from_json(asset("bundle.txt.sigstore").read_bytes())
    bundle.log_entry._verify_merkle_inclusion()


def test_transparency_log_entry_verify_merkle_inclusion_wrong_size(asset: Any) -> None:
    bundle = Bundle.from_json(asset("bundle.txt.sigstore").read_bytes())
    bundle.log_entry._inner.inclusion_proof.hashes.pop()

    with pytest.raises(VerificationError, match="inclusion proof has wrong size"):
        bundle.log_entry._verify_merkle_inclusion()


def test_transparency_log_entry_verify_merkle_inclusion_invalid_root_hash(
    asset: Any,
) -> None:
    bundle = Bundle.from_json(asset("bundle.txt.sigstore").read_bytes())
    bundle.log_entry._inner.inclusion_proof.root_hash = b"\x00" * 32

    with pytest.raises(
        VerificationError, match="inclusion proof contains invalid root hash"
    ):
        bundle.log_entry._verify_merkle_inclusion()
