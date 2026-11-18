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
Parser, serializer, and Merkle inclusion verifier for ``c2sp.org/tlog-proof@v1``.

See: <https://c2sp.org/tlog-proof>
"""

from __future__ import annotations

import base64
import binascii
import hashlib
from collections.abc import Mapping
from dataclasses import dataclass, field

from sigstore._internal.merkle import verify_merkle_inclusion
from sigstore.errors import VerificationError

TLOG_PROOF_HEADER = b"c2sp.org/tlog-proof@v1"
_EXTRA_PREFIX = b"extra "
_INDEX_PREFIX = b"index "
_SHA256_DIGEST_SIZE = hashlib.sha256().digest_size
_MAX_UINT64 = (1 << 64) - 1


def _is_canonical_ascii_uint64(raw: bytes) -> bool:
    """
    Return True if ``raw`` is an ASCII decimal integer in ``[0, 2^64 - 1]``
    with no leading zeroes (unless the value is ``0``).
    """
    if not raw:
        return False
    if raw == b"0":
        return True
    if raw.startswith(b"0"):
        return False
    return raw.isascii() and raw.isdigit() and int(raw) <= _MAX_UINT64


def _b64decode_strict(data: bytes, description: str) -> bytes:
    """
    Strictly decode standard RFC 4648 Base64 bytes, raising ``VerificationError``
    on any non-alphabet characters or invalid padding.
    """
    if not data:
        raise VerificationError(f"malformed tlog-proof: empty {description}")
    try:
        return base64.b64decode(data, validate=True)
    except binascii.Error as exc:
        raise VerificationError(
            f"malformed tlog-proof: invalid base64 in {description}: {exc}"
        ) from exc


def encode_extra_claims(claims: Mapping[str, str]) -> bytes:
    """
    Encode a mapping of ``extra`` key-value claims into the newline-separated
    ``key:value`` UTF-8 format used by Sigstore v2 ``tlog-proof`` entries.
    """
    lines: list[bytes] = []
    for key, value in claims.items():
        if not key or ":" in key or "\n" in key or "\r" in key:
            raise ValueError(f"invalid extra claim key: {key!r}")
        if not value:
            raise ValueError(f"empty extra claim value for key: {key!r}")
        if "\n" in value or "\r" in value:
            raise ValueError(
                f"invalid newline character in extra claim value for key: {key!r}"
            )
        lines.append(f"{key}:{value}".encode())
    return b"\n".join(lines)


def decode_extra_claims(extra_data: bytes) -> dict[str, str]:
    """
    Decode the newline-separated ``key:value`` UTF-8 lines from a Sigstore v2
    ``tlog-proof`` ``extra`` section into a dictionary of ``{key: value}``.
    """
    claims: dict[str, str] = {}
    if not extra_data:
        return claims

    if b"\r" in extra_data:
        raise VerificationError(
            "malformed tlog-proof extra data: unexpected carriage return"
        )

    for line in extra_data.split(b"\n"):
        if b":" not in line:
            raise VerificationError(
                "malformed tlog-proof extra data: line missing ':' separator"
            )
        raw_key, raw_val = line.split(b":", 1)
        if not raw_key:
            raise VerificationError("malformed tlog-proof extra data: empty claim key")
        if not raw_val:
            raise VerificationError(
                "malformed tlog-proof extra data: empty claim value"
            )
        try:
            key = raw_key.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise VerificationError(
                f"malformed tlog-proof extra data: non-UTF-8 claim key: {exc}"
            ) from exc
        try:
            val = raw_val.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise VerificationError(
                f"malformed tlog-proof extra data: non-UTF-8 claim value for {key!r}: {exc}"
            ) from exc

        if key in claims:
            raise VerificationError(
                f"malformed tlog-proof extra data: duplicate claim key {key!r}"
            )

        claims[key] = val

    return claims


@dataclass(frozen=True)
class TLogProof:
    """
    Represents a parsed ``c2sp.org/tlog-proof@v1`` transparency log inclusion proof.
    """

    index: int
    hashes: list[bytes]
    checkpoint: bytes
    extra_data: bytes = field(default=b"")

    def __post_init__(self) -> None:
        """
        Validate structural invariants on ``TLogProof`` fields.
        """
        if self.index < 0 or self.index > _MAX_UINT64:
            raise VerificationError(
                f"malformed tlog-proof: index out of uint64 range: {self.index}"
            )
        for h in self.hashes:
            if len(h) != _SHA256_DIGEST_SIZE:
                raise VerificationError(
                    f"malformed tlog-proof: expected 32-byte proof hash, got {len(h)} bytes"
                )
        if not self.checkpoint:
            raise VerificationError("malformed tlog-proof: empty checkpoint")

    @classmethod
    def from_bytes(cls, data: bytes) -> TLogProof:
        """
        Parse a ``TLogProof`` from its ``c2sp.org/tlog-proof@v1`` wire encoding.
        """
        parts = data.split(b"\n\n", 1)
        if len(parts) != 2:
            raise VerificationError(
                "malformed tlog-proof: missing blank line separating proof from checkpoint"
            )

        proof_section, checkpoint = parts
        if not checkpoint:
            raise VerificationError("malformed tlog-proof: empty checkpoint")

        lines = proof_section.split(b"\n")
        if len(lines) < 2:
            raise VerificationError("malformed tlog-proof: too few lines in header")

        if lines[0] != TLOG_PROOF_HEADER:
            raise VerificationError(
                f"malformed tlog-proof: unexpected header {lines[0]!r}"
            )

        line_idx = 1
        extra_data = b""
        if lines[line_idx].startswith(_EXTRA_PREFIX):
            raw_extra_b64 = lines[line_idx][len(_EXTRA_PREFIX) :]
            extra_data = _b64decode_strict(raw_extra_b64, "extra data")
            line_idx += 1

        if line_idx >= len(lines) or not lines[line_idx].startswith(_INDEX_PREFIX):
            raise VerificationError("malformed tlog-proof: missing index line")

        raw_index = lines[line_idx][len(_INDEX_PREFIX) :]
        if not _is_canonical_ascii_uint64(raw_index):
            raise VerificationError(
                f"malformed tlog-proof: invalid index {raw_index!r}"
            )
        index = int(raw_index)
        line_idx += 1

        hashes: list[bytes] = []
        for raw_hash in lines[line_idx:]:
            decoded_hash = _b64decode_strict(raw_hash, "inclusion proof hash")
            if len(decoded_hash) != _SHA256_DIGEST_SIZE:
                raise VerificationError(
                    "malformed tlog-proof: inclusion proof hash must be 32 bytes, "
                    f"got {len(decoded_hash)}"
                )
            hashes.append(decoded_hash)

        return cls(
            index=index,
            hashes=hashes,
            checkpoint=checkpoint,
            extra_data=extra_data,
        )

    def to_bytes(self) -> bytes:
        """
        Serialize this ``TLogProof`` into ``c2sp.org/tlog-proof@v1`` wire format.
        """
        lines: list[bytes] = [TLOG_PROOF_HEADER]
        if self.extra_data:
            lines.append(_EXTRA_PREFIX + base64.b64encode(self.extra_data))
        lines.append(_INDEX_PREFIX + str(self.index).encode("ascii"))
        for h in self.hashes:
            lines.append(base64.b64encode(h))
        return b"\n".join(lines) + b"\n\n" + self.checkpoint

    def decode_extra_claims(self) -> dict[str, str]:
        """
        Decode ``self.extra_data`` as newline-separated ``key:value`` UTF-8
        claims into a ``dict[str, str]``.
        """
        return decode_extra_claims(self.extra_data)

    def verify_inclusion(
        self,
        leaf_hash: bytes,
        tree_size: int,
        root_hash: bytes,
    ) -> None:
        """
        Verify the RFC 6962 Merkle inclusion proof for ``leaf_hash`` at
        ``self.index`` against ``tree_size`` and ``root_hash``.
        """
        verify_merkle_inclusion(
            log_index=self.index,
            tree_size=tree_size,
            leaf_hash=leaf_hash,
            hashes=self.hashes,
            root_hash=root_hash,
        )
