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

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, mldsa

from sigstore._internal.c2sp.identity import (
    CONTEXT_KEY_NAME,
    IDENTITY_TRANSPARENCY_DOMAIN_SEPARATOR,
    LEAF_VERSION,
    _compute_oidc_leaf,
    _compute_public_key_leaf,
    compute_oidc_leaf_hash,
    compute_public_key_leaf_hash,
    compute_signature_payload,
)
from sigstore._internal.merkle import hash_leaf
from sigstore.errors import VerificationError


def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _double_sha256(data: bytes) -> bytes:
    return _sha256(_sha256(data))


def test_compute_signature_payload_with_context() -> None:
    msg_hash = _sha256(b"test message")
    ctx_hash = _sha256(b"val1")

    payload = compute_signature_payload(msg_hash, context=ctx_hash)

    expected = (
        IDENTITY_TRANSPARENCY_DOMAIN_SEPARATOR
        + _sha256(msg_hash)
        + _double_sha256(CONTEXT_KEY_NAME.encode("utf-8"))
        + _sha256(ctx_hash)
    )
    assert payload == expected


def test_compute_signature_payload_no_context() -> None:
    msg_hash = _sha256(b"test message")

    payload = compute_signature_payload(msg_hash)

    expected = IDENTITY_TRANSPARENCY_DOMAIN_SEPARATOR + _sha256(msg_hash)
    assert payload == expected


def test_compute_signature_payload_errors() -> None:
    msg_hash = _sha256(b"test message")

    with pytest.raises(VerificationError, match="message_digest must be 32 bytes"):
        compute_signature_payload(b"short")

    with pytest.raises(VerificationError, match="context must be 32 bytes"):
        compute_signature_payload(msg_hash, context=b"short")

    with pytest.raises(VerificationError, match="context must be 32 bytes"):
        compute_signature_payload(msg_hash, context=b"")


def test_compute_public_key_leaf_ed25519_with_context() -> None:
    # Mirrors TestToLogEntry in rekor-tiles/pkg/types/identity_v1/identity_v1_test.go
    priv = ed25519.Ed25519PrivateKey.generate()
    pub = priv.public_key()
    pub_der = pub.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    msg_hash = _sha256(b"test message")
    ctx_hash = _sha256(b"val1")
    payload = compute_signature_payload(msg_hash, context=ctx_hash)
    sig = priv.sign(payload)

    leaf = _compute_public_key_leaf(
        public_key=pub_der,
        signature=sig,
        message_digest=msg_hash,
        context=ctx_hash,
    )
    assert len(leaf) == 1 + 5 * 32
    assert leaf[:1] == LEAF_VERSION
    assert leaf[1:33] == _sha256(b"Ed25519" + pub_der)
    assert leaf[33:65] == _sha256(msg_hash)
    assert leaf[65:97] == _double_sha256(b"context")
    assert leaf[97:129] == _sha256(ctx_hash)
    assert leaf[129:161] == _sha256(sig)

    # Passing the parsed PublicKey object produces the exact same leaf hash
    leaf_hash = compute_public_key_leaf_hash(
        public_key=pub,
        signature=sig,
        message_digest=msg_hash,
        context=ctx_hash,
    )
    assert leaf_hash == hash_leaf(leaf)


def test_compute_public_key_leaf_ed25519_no_context() -> None:
    # Mirrors TestToLogEntry_NoContext in rekor-tiles/pkg/types/identity_v1/identity_v1_test.go
    priv = ed25519.Ed25519PrivateKey.generate()
    pub = priv.public_key()
    pub_der = pub.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    msg_hash = _sha256(b"test message")
    payload = compute_signature_payload(msg_hash)
    sig = priv.sign(payload)

    leaf = _compute_public_key_leaf(
        public_key=pub_der,
        signature=sig,
        message_digest=msg_hash,
    )
    assert len(leaf) == 1 + 3 * 32
    assert leaf[:1] == LEAF_VERSION
    assert leaf[1:33] == _sha256(b"Ed25519" + pub_der)
    assert leaf[33:65] == _sha256(msg_hash)
    assert leaf[65:97] == _sha256(sig)


def test_compute_public_key_leaf_mldsa44() -> None:
    # Mirrors TestToLogEntry_MLDSA in rekor-tiles/pkg/types/identity_v1/identity_v1_test.go
    priv = mldsa.MLDSA44PrivateKey.generate()
    pub = priv.public_key()
    pub_der = pub.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    msg_hash = _sha256(b"test message")
    ctx_hash = _sha256(b"val1")
    payload = compute_signature_payload(msg_hash, context=ctx_hash)
    sig = priv.sign(payload)

    leaf = _compute_public_key_leaf(
        public_key=pub_der,
        signature=sig,
        message_digest=msg_hash,
        context=ctx_hash,
    )
    assert len(leaf) == 1 + 5 * 32
    assert leaf[:1] == LEAF_VERSION
    assert leaf[1:33] == _sha256(b"ML-DSA-44" + pub_der)
    assert leaf[33:65] == _sha256(msg_hash)
    assert leaf[65:97] == _double_sha256(b"context")
    assert leaf[97:129] == _sha256(ctx_hash)
    assert leaf[129:161] == _sha256(sig)


def test_compute_public_key_leaf_errors() -> None:
    msg_hash = _sha256(b"test message")
    priv = ed25519.Ed25519PrivateKey.generate()
    pub = priv.public_key()

    with pytest.raises(VerificationError, match="signature is empty"):
        compute_public_key_leaf_hash(
            public_key=pub,
            signature=b"",
            message_digest=msg_hash,
        )

    with pytest.raises(VerificationError, match="public key is empty"):
        compute_public_key_leaf_hash(
            public_key=b"",
            signature=b"sig",
            message_digest=msg_hash,
        )

    with pytest.raises(
        VerificationError, match="could not load DER-formatted public key"
    ):
        compute_public_key_leaf_hash(
            public_key=b"not-valid-der",
            signature=b"sig",
            message_digest=msg_hash,
        )

    ec_pub = ec.generate_private_key(ec.SECP256R1()).public_key()
    with pytest.raises(VerificationError, match="unsupported public key type"):
        compute_public_key_leaf_hash(
            public_key=ec_pub,
            signature=b"sig",
            message_digest=msg_hash,
        )

    mldsa65_pub = mldsa.MLDSA65PrivateKey.generate().public_key()
    with pytest.raises(VerificationError, match="unsupported public key type"):
        compute_public_key_leaf_hash(
            public_key=mldsa65_pub,
            signature=b"sig",
            message_digest=msg_hash,
        )

    with pytest.raises(VerificationError, match="context must be 32 bytes"):
        compute_public_key_leaf_hash(
            public_key=pub,
            signature=b"sig",
            message_digest=msg_hash,
            context=b"short",
        )

    with pytest.raises(VerificationError, match="context must be 32 bytes"):
        compute_public_key_leaf_hash(
            public_key=pub,
            signature=b"sig",
            message_digest=msg_hash,
            context=b"",
        )


def test_compute_oidc_leaf_and_hash() -> None:
    # Mirrors TestToLogEntry_OidcValid & TestToOIDCEntryHash in
    # rekor-tiles/pkg/types/identity_v1/identity_v1_test.go
    issuer = "https://accounts.example.com"
    msg_hash = _sha256(b"test message")
    claims = {
        "identity": "foo@example.com",
        "issuer": issuer,
        "subject": "test-sub",
    }

    leaf = _compute_oidc_leaf(
        issuer=issuer,
        message_digest=msg_hash,
        claims=claims,
    )
    assert len(leaf) == 1 + 32 + 32 + len(claims) * 64 + 32
    assert leaf[:1] == LEAF_VERSION
    assert leaf[1:33] == _sha256(issuer.encode("utf-8"))
    assert leaf[33:65] == _sha256(msg_hash)

    expected_pairs = sorted(
        (
            _double_sha256(k.encode("utf-8")),
            _double_sha256(v.encode("utf-8")),
        )
        for k, v in claims.items()
    )
    offset = 65
    for k_dh, v_dh in expected_pairs:
        assert leaf[offset : offset + 32] == k_dh
        assert leaf[offset + 32 : offset + 64] == v_dh
        offset += 64

    assert leaf[offset : offset + 32] == b"\x00" * 32

    assert compute_oidc_leaf_hash(
        issuer=issuer,
        message_digest=msg_hash,
        claims=claims,
    ) == hash_leaf(leaf)


def test_compute_oidc_leaf_empty_claims() -> None:
    issuer = "https://accounts.example.com"
    msg_hash = _sha256(b"test message")

    leaf = _compute_oidc_leaf(
        issuer=issuer,
        message_digest=msg_hash,
        claims={},
    )
    assert len(leaf) == 1 + 32 + 32 + 32
    assert leaf == (
        LEAF_VERSION
        + _sha256(issuer.encode("utf-8"))
        + _sha256(msg_hash)
        + b"\x00" * 32
    )


def test_compute_oidc_leaf_errors() -> None:
    msg_hash = _sha256(b"test message")

    with pytest.raises(VerificationError, match="issuer is empty"):
        compute_oidc_leaf_hash(issuer="", message_digest=msg_hash, claims={})

    with pytest.raises(VerificationError, match="claim key is empty"):
        compute_oidc_leaf_hash(
            issuer="https://accounts.example.com",
            message_digest=msg_hash,
            claims={"": "val"},
        )

    with pytest.raises(VerificationError, match="claim value is empty"):
        compute_oidc_leaf_hash(
            issuer="https://accounts.example.com",
            message_digest=msg_hash,
            claims={"identity": ""},
        )

    with pytest.raises(VerificationError, match="message_digest must be 32 bytes"):
        compute_oidc_leaf_hash(
            issuer="https://accounts.example.com",
            message_digest=b"short",
            claims={},
        )


def test_rekor_tiles_v2_interop_vectors() -> None:
    # Independent vectors generated by sigstore/rekor-tiles v2.4.2
    # (pkg/types/identity_v1.ToEntryHash and ToOIDCEntryHash).
    ed25519_priv_pem = (
        b"-----BEGIN PRIVATE KEY-----\n"
        b"MC4CAQAwBQYDK2VwBCIEIGuZ8UWTFmXi/26ZgF4VYL8HfLSuW12TN5XMFQRt1Loc\n"
        b"-----END PRIVATE KEY-----\n"
    )
    priv = serialization.load_pem_private_key(ed25519_priv_pem, password=None)
    assert isinstance(priv, ed25519.Ed25519PrivateKey)
    pub = priv.public_key()
    pub_der = pub.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    assert (
        pub_der.hex()
        == "302a300506032b6570032100444bc9c8d6468d7e81dc3008b83dc14e0f6b230574d0663c5e0e4553e2050d44"
    )

    msg_hash = _sha256(b"test message")
    ctx_hash = _sha256(b"val1")
    sig = priv.sign(compute_signature_payload(msg_hash, context=ctx_hash))
    assert (
        sig.hex() == "ce219034f77dd0b0a30fa41bc0712dc0fad4ecc9fee6c02c757bee06f18498cf"
        "86cc5dfd6305ac7974c328b1f18fb670491149cf86c2ceb187ee351a1ad78a04"
    )

    pk_leaf_hash = compute_public_key_leaf_hash(
        public_key=pub,
        signature=sig,
        message_digest=msg_hash,
        context=ctx_hash,
    )
    assert (
        pk_leaf_hash.hex()
        == "1142c6b17fde10c0e460a8ff1056ff34c8ebd77744f06f71364c571a185b332c"
    )

    oidc_leaf_hash = compute_oidc_leaf_hash(
        issuer="https://accounts.example.com",
        message_digest=msg_hash,
        claims={
            "identity": "foo@example.com",
            "issuer": "https://accounts.example.com",
            "subject": "test-sub",
        },
    )
    assert (
        oidc_leaf_hash.hex()
        == "b3710b1b1a71cd1efab749f785040140e8cef29f14a01ad36d43a4c56f7529f3"
    )
