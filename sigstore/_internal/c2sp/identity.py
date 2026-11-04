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

"""
Signature payload and binary leaf hash computation for
``c2sp.org/identity-transparency/v1``.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable, Mapping

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, mldsa

from sigstore._internal.merkle import hash_leaf
from sigstore._utils import PublicKey, load_der_public_key
from sigstore.errors import VerificationError

IDENTITY_TRANSPARENCY_DOMAIN_SEPARATOR = b"c2sp.org/identity-transparency/v1\x00"
LEAF_VERSION = b"\x01"
CONTEXT_KEY_NAME = "context"

_SHA256_DIGEST_SIZE = hashlib.sha256().digest_size
_ZERO_RECEIPT = b"\x00" * _SHA256_DIGEST_SIZE


def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _double_sha256(data: bytes) -> bytes:
    return _sha256(_sha256(data))


_CONTEXT_KEY_DOUBLE_HASH = _double_sha256(CONTEXT_KEY_NAME.encode("utf-8"))


def _validate_digest(digest: bytes, name: str) -> None:
    if len(digest) != _SHA256_DIGEST_SIZE:
        raise VerificationError(
            f"identity-transparency: {name} must be {_SHA256_DIGEST_SIZE} bytes, "
            f"got {len(digest)}"
        )


def _build_leaf(
    *,
    root_of_trust_hash: bytes,
    message_digest: bytes,
    hashed_claim_pairs: Iterable[tuple[bytes, bytes]],
    receipt_hash: bytes,
) -> bytes:
    """
    Construct the unhashed ``c2sp.org/identity-transparency/v1`` binary leaf:

        ``0x01 || root_of_trust_hash || SHA256(message_digest)``
        ``|| sorted(k_double_hash || v_double_hash) || receipt_hash``
    """
    _validate_digest(message_digest, "message_digest")
    buf = bytearray(LEAF_VERSION)
    buf.extend(root_of_trust_hash)
    buf.extend(_sha256(message_digest))

    for k_double_hash, v_double_hash in sorted(
        hashed_claim_pairs, key=lambda pair: pair[0]
    ):
        buf.extend(k_double_hash)
        buf.extend(v_double_hash)

    buf.extend(receipt_hash)
    return bytes(buf)


def compute_signature_payload(
    message_digest: bytes,
    *,
    context: bytes | None = None,
) -> bytes:
    """
    Compute the domain-separated payload to be signed/verified for a logged
    Sigstore v2 public-key signature (``tlog_proof`` verification material):

        ``"c2sp.org/identity-transparency/v1\\x00" || SHA256(message_digest)``
        ``[|| SHA256(SHA256("context")) || SHA256(context)]``
    """
    # NOTE: Supporting unlogged v2 bundles (`public_key` or `cert` verification
    # material without a transparency log entry) would require using the
    # `b"sigstore.dev/v1\x00"` domain separator with `context` disallowed.
    _validate_digest(message_digest, "message_digest")
    buf = bytearray(IDENTITY_TRANSPARENCY_DOMAIN_SEPARATOR)
    buf.extend(_sha256(message_digest))

    if context is not None:
        _validate_digest(context, "context")
        buf.extend(_CONTEXT_KEY_DOUBLE_HASH)
        buf.extend(_sha256(context))

    return bytes(buf)


def _public_key_root_of_trust_hash(public_key: PublicKey | bytes) -> bytes:
    """
    Compute the 32-byte root-of-trust hash ``SHA256(alg_prefix || canonical_spki_der)``
    for an ``Ed25519`` or ``ML-DSA-44`` public key.
    """
    if isinstance(public_key, bytes):
        if not public_key:
            raise VerificationError("identity-transparency: public key is empty")
        key = load_der_public_key(public_key)
    else:
        key = public_key

    if isinstance(key, ed25519.Ed25519PublicKey):
        alg_prefix = b"Ed25519"
    elif isinstance(key, mldsa.MLDSA44PublicKey):
        alg_prefix = b"ML-DSA-44"
    else:
        raise VerificationError(
            f"identity-transparency: unsupported public key type {type(key).__name__}"
        )

    canonical_spki = key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return _sha256(alg_prefix + canonical_spki)


def _compute_public_key_leaf(
    *,
    public_key: PublicKey | bytes,
    signature: bytes,
    message_digest: bytes,
    context: bytes | None = None,
) -> bytes:
    """
    Construct the unhashed ``c2sp.org/identity-transparency/v1`` binary leaf for
    a public-key credential.
    """
    if not signature:
        raise VerificationError("identity-transparency: signature is empty")

    root_hash = _public_key_root_of_trust_hash(public_key)
    hashed_claim_pairs: list[tuple[bytes, bytes]] = []
    if context is not None:
        _validate_digest(context, "context")
        hashed_claim_pairs.append((_CONTEXT_KEY_DOUBLE_HASH, _sha256(context)))

    return _build_leaf(
        root_of_trust_hash=root_hash,
        message_digest=message_digest,
        hashed_claim_pairs=hashed_claim_pairs,
        receipt_hash=_sha256(signature),
    )


def compute_public_key_leaf_hash(
    *,
    public_key: PublicKey | bytes,
    signature: bytes,
    message_digest: bytes,
    context: bytes | None = None,
) -> bytes:
    """
    Compute the RFC 6962 Merkle leaf hash ``SHA256(0x00 || leaf)`` for a
    public-key identity log entry.
    """
    leaf = _compute_public_key_leaf(
        public_key=public_key,
        signature=signature,
        message_digest=message_digest,
        context=context,
    )
    return hash_leaf(leaf)


def _compute_oidc_leaf(
    *,
    issuer: str | bytes,
    message_digest: bytes,
    claims: Mapping[str, str | bytes],
) -> bytes:
    """
    Construct the unhashed ``c2sp.org/identity-transparency/v1`` binary leaf for
    an OIDC credential.
    """
    issuer_bytes = issuer.encode("utf-8") if isinstance(issuer, str) else issuer
    if not issuer_bytes:
        raise VerificationError("identity-transparency: issuer is empty")

    hashed_claim_pairs = (
        (
            _double_sha256(k.encode("utf-8")),
            _double_sha256(v.encode("utf-8") if isinstance(v, str) else v),
        )
        for k, v in claims.items()
    )

    return _build_leaf(
        root_of_trust_hash=_sha256(issuer_bytes),
        message_digest=message_digest,
        hashed_claim_pairs=hashed_claim_pairs,
        receipt_hash=_ZERO_RECEIPT,
    )


def compute_oidc_leaf_hash(
    *,
    issuer: str | bytes,
    message_digest: bytes,
    claims: Mapping[str, str | bytes],
) -> bytes:
    """
    Compute the RFC 6962 Merkle leaf hash ``SHA256(0x00 || leaf)`` for an OIDC
    identity log entry.
    """
    leaf = _compute_oidc_leaf(
        issuer=issuer,
        message_digest=message_digest,
        claims=claims,
    )
    return hash_leaf(leaf)
