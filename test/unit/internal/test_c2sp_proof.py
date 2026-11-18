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

import base64
import hashlib

import pytest

from sigstore._internal.c2sp.proof import (
    TLogProof,
    decode_extra_claims,
    encode_extra_claims,
)
from sigstore._internal.merkle import hash_children, hash_leaf
from sigstore.errors import VerificationError

_SAMPLE_CHECKPOINT = (
    b"example.com/fancylog\n"
    b"109482\n"
    b"sFodV/vSp5O8n9a8QpW6PRY97tfOSW5bsc2Xl/EQi08=\n"
    b"\n"
    b"\xe2\x80\x94 example.com/fancylog hI2DJw1roloI=\n"
)


def test_tlog_proof_roundtrip_with_extra() -> None:
    h1 = hashlib.sha256(b"h1").digest()
    h2 = hashlib.sha256(b"h2").digest()
    extra = encode_extra_claims(
        {
            "issuer": "https://accounts.example.com",
            "identity": "alice@example.com",
        }
    )

    proof = TLogProof(
        index=73894,
        hashes=[h1, h2],
        checkpoint=_SAMPLE_CHECKPOINT,
        extra_data=extra,
    )

    serialized = proof.to_bytes()
    assert serialized.startswith(b"c2sp.org/tlog-proof@v1\nextra ")
    parsed = TLogProof.from_bytes(serialized)
    assert parsed == proof
    assert parsed.decode_extra_claims() == {
        "issuer": "https://accounts.example.com",
        "identity": "alice@example.com",
    }


def test_tlog_proof_roundtrip_without_extra_or_hashes() -> None:
    proof = TLogProof(
        index=0,
        hashes=[],
        checkpoint=_SAMPLE_CHECKPOINT,
    )

    serialized = proof.to_bytes()
    assert b"\nextra " not in serialized
    assert b"\nindex 0\n\n" in serialized

    parsed = TLogProof.from_bytes(serialized)
    assert parsed == proof
    assert parsed.extra_data == b""
    assert parsed.decode_extra_claims() == {}


def test_extra_claims_hex_context() -> None:
    ctx_hex = hashlib.sha256(b"some-context").hexdigest()
    extra = encode_extra_claims({"context": ctx_hex})
    decoded = decode_extra_claims(extra)
    assert decoded == {"context": ctx_hex}


@pytest.mark.parametrize("bad_key", ["", "a:b", "a\nb", "a\rb"])
def test_encode_extra_claims_invalid_key(bad_key: str) -> None:
    with pytest.raises(ValueError, match="invalid extra claim key"):
        encode_extra_claims({bad_key: "val"})


def test_encode_extra_claims_invalid_value() -> None:
    with pytest.raises(ValueError, match="empty extra claim value"):
        encode_extra_claims({"key": ""})

    with pytest.raises(ValueError, match="invalid newline character"):
        encode_extra_claims({"key": "val\ninjected:1"})

    with pytest.raises(ValueError, match="invalid newline character"):
        encode_extra_claims({"key": "val\rinjected:1"})


@pytest.mark.parametrize(
    ("raw_extra", "err_match"),
    [
        (b"no-colon-line", "missing ':' separator"),
        (b"k:val\n", "missing ':' separator"),
        (b"k1:val\n\nk2:val", "missing ':' separator"),
        (b"k1:val\r\nk2:val", "unexpected carriage return"),
        (b":val", "empty claim key"),
        (b"\xff:val", "non-UTF-8 claim key"),
        (b"k:\xff", "non-UTF-8 claim value"),
        (b"k:val\nk:val", "duplicate claim key"),
        (b"k:", "empty claim value"),
    ],
)
def test_decode_extra_claims_invalid(raw_extra: bytes, err_match: str) -> None:
    with pytest.raises(VerificationError, match=err_match):
        decode_extra_claims(raw_extra)


@pytest.mark.parametrize(
    ("raw_proof", "err_match"),
    [
        (b"c2sp.org/tlog-proof@v1\nindex 0\n", "missing blank line"),
        (b"c2sp.org/tlog-proof@v1\nindex 0\n\n", "empty checkpoint"),
        (b"c2sp.org/tlog-proof@v1\n\ncheckpoint\n", "too few lines"),
        (b"c2sp.org/tlog-proof@v2\nindex 0\n\ncheckpoint\n", "unexpected header"),
        (
            b"c2sp.org/tlog-proof@v1\nextra \nindex 0\n\ncheckpoint\n",
            "empty extra data",
        ),
        (
            b"c2sp.org/tlog-proof@v1\nextra !!!\nindex 0\n\ncheckpoint\n",
            "invalid base64 in extra data",
        ),
        (
            b"c2sp.org/tlog-proof@v1\nextra dGVzdA==\n\ncheckpoint\n",
            "missing index line",
        ),
        (
            b"c2sp.org/tlog-proof@v1\nnot-index 0\n\ncheckpoint\n",
            "missing index line",
        ),
        (
            b"c2sp.org/tlog-proof@v1\nindex 01\n\ncheckpoint\n",
            "invalid index",
        ),
        (
            b"c2sp.org/tlog-proof@v1\nindex -1\n\ncheckpoint\n",
            "invalid index",
        ),
        (
            b"c2sp.org/tlog-proof@v1\nindex \n\ncheckpoint\n",
            "invalid index",
        ),
        (
            b"c2sp.org/tlog-proof@v1\nindex 18446744073709551616\n\ncheckpoint\n",
            "invalid index",
        ),
        (
            b"c2sp.org/tlog-proof@v1\nindex 0\n"
            + base64.b64encode(b"short-hash")
            + b"\n\ncheckpoint\n",
            "inclusion proof hash must be 32 bytes",
        ),
    ],
)
def test_tlog_proof_from_bytes_invalid(raw_proof: bytes, err_match: str) -> None:
    with pytest.raises(VerificationError, match=err_match):
        TLogProof.from_bytes(raw_proof)


def test_tlog_proof_init_validation() -> None:
    with pytest.raises(VerificationError, match="index out of uint64 range"):
        TLogProof(index=-1, hashes=[], checkpoint=_SAMPLE_CHECKPOINT)

    with pytest.raises(VerificationError, match="expected 32-byte proof hash"):
        TLogProof(index=0, hashes=[b"short"], checkpoint=_SAMPLE_CHECKPOINT)

    with pytest.raises(VerificationError, match="empty checkpoint"):
        TLogProof(index=0, hashes=[], checkpoint=b"")


def test_tlog_proof_verify_inclusion() -> None:
    # Build a 3-leaf RFC 6962 Merkle tree:
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

    # Proof for leaf 1 (index=1, tree_size=3): sibling l0 (inner), sibling l2 (inner)
    proof_leaf_1 = TLogProof(
        index=1,
        hashes=[l0, l2],
        checkpoint=_SAMPLE_CHECKPOINT,
    )
    proof_leaf_1.verify_inclusion(leaf_hash=l1, tree_size=3, root_hash=root)

    # Proof for leaf 2 (index=2, tree_size=3): left border n01
    proof_leaf_2 = TLogProof(
        index=2,
        hashes=[n01],
        checkpoint=_SAMPLE_CHECKPOINT,
    )
    proof_leaf_2.verify_inclusion(leaf_hash=l2, tree_size=3, root_hash=root)

    # Single-leaf tree (index=0, tree_size=1, hashes=[])
    proof_single = TLogProof(
        index=0,
        hashes=[],
        checkpoint=_SAMPLE_CHECKPOINT,
    )
    proof_single.verify_inclusion(leaf_hash=l0, tree_size=1, root_hash=l0)


def test_tlog_proof_verify_inclusion_errors() -> None:
    l0 = hash_leaf(b"leaf-0")
    l1 = hash_leaf(b"leaf-1")
    root = hash_children(l0, l1)

    proof = TLogProof(index=0, hashes=[l1], checkpoint=_SAMPLE_CHECKPOINT)

    with pytest.raises(VerificationError, match="leaf_hash must be 32 bytes"):
        proof.verify_inclusion(leaf_hash=b"short", tree_size=2, root_hash=root)

    with pytest.raises(VerificationError, match="root_hash must be 32 bytes"):
        proof.verify_inclusion(leaf_hash=l0, tree_size=2, root_hash=b"short")

    with pytest.raises(VerificationError, match="out of bounds"):
        proof.verify_inclusion(leaf_hash=l0, tree_size=0, root_hash=root)

    with pytest.raises(VerificationError, match="wrong size"):
        proof.verify_inclusion(leaf_hash=l0, tree_size=1, root_hash=l0)

    with pytest.raises(VerificationError, match="invalid root hash"):
        proof.verify_inclusion(leaf_hash=l1, tree_size=2, root_hash=root)
