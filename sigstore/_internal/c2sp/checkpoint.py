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
Parsers and verifiers for ``c2sp.org/signed-note``, ``c2sp.org/tlog-checkpoint``,
and ``c2sp.org/tlog-cosignature`` (including ``subtree/v1`` ML-DSA-44 and
``cosignature/v1`` Ed25519 signatures).
"""

from __future__ import annotations

import base64
import hashlib
import struct
from collections.abc import Iterable
from dataclasses import dataclass, field

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, mldsa, padding, rsa

from sigstore._internal.c2sp.proof import _b64decode_strict, _is_canonical_ascii_uint64
from sigstore._utils import KeyID, PublicKey
from sigstore.errors import VerificationError

ALG_ED25519 = 0x01
ALG_ED25519_COSIGNATURE_V1 = 0x04
ALG_MLDSA44_COSIGNATURE_V1 = 0x06
ALG_UNDEF = 0xFF

# rekor-tiles-specific identifier under signed-note type 0xff
_RSA_ID = b"PKIX-RSA-PKCS#1v1.5"
_EM_DASH_PREFIX = "— "
_SUBTREE_V1_LABEL = b"subtree/v1\n\x00"
_COSIGNATURE_V1_HEADER = b"cosignature/v1\ntime "
_SHA256_DIGEST_SIZE = hashlib.sha256().digest_size
_MAX_UINT64 = (1 << 64) - 1
_MAX_POSIX_TIMESTAMP = (1 << 63) - 1
_MAX_NAME_BYTES = 255
_MAX_SIGNATURES = 64
_ED25519_SIG_SIZE = 64
_MLDSA44_SIG_SIZE = 2420


def is_valid_note_name(name: str) -> bool:
    """
    Return True if ``name`` is a valid ``c2sp.org/signed-note`` key name / origin
    (non-empty, containing no Unicode whitespace, control characters, or ``+``).
    """
    if not name or "+" in name:
        return False
    return not any(ch.isspace() or ord(ch) < 0x20 for ch in name)


def _validate_tlog_name(name: str, label: str) -> bytes:
    """
    Validate ``name`` per ``c2sp.org/tlog-cosignature`` / ``c2sp.org/tlog-checkpoint``
    (valid note name with UTF-8 length in ``[1, 255]``) and return its UTF-8 bytes.
    """
    if not is_valid_note_name(name):
        raise VerificationError(f"c2sp checkpoint: invalid {label} {name!r}")
    encoded = name.encode("utf-8")
    if len(encoded) > _MAX_NAME_BYTES:
        raise VerificationError(
            f"c2sp checkpoint: invalid {label} length {len(encoded)} "
            f"(max {_MAX_NAME_BYTES})"
        )
    return encoded


def _ecdsa_hash_algorithm(
    public_key: ec.EllipticCurvePublicKey,
) -> hashes.HashAlgorithm:
    # Curve-matched digest selection follows rekor-tiles / Sigstore's
    # signature.Verifier (P-256 -> SHA-256, P-384 -> SHA-384, P-521 -> SHA-512),
    # rather than transparency-dev/witness's fixed SHA-256.
    if isinstance(public_key.curve, ec.SECP256R1):
        return hashes.SHA256()
    if isinstance(public_key.curve, ec.SECP384R1):
        return hashes.SHA384()
    if isinstance(public_key.curve, ec.SECP521R1):
        return hashes.SHA512()
    raise VerificationError(
        f"c2sp checkpoint: unsupported ECDSA curve {public_key.curve.name}"
    )


def _validate_verifier_key(public_key: PublicKey, *, cosignature: bool) -> None:
    """
    Validate that ``public_key`` and ``cosignature`` represent a supported
    checkpoint/cosignature key configuration.
    """
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        if cosignature:
            raise VerificationError(
                "c2sp checkpoint: ECDSA keys do not support tlog-cosignature"
            )
        _ecdsa_hash_algorithm(public_key)
        return
    if isinstance(public_key, ed25519.Ed25519PublicKey | mldsa.MLDSA44PublicKey):
        return
    if isinstance(public_key, rsa.RSAPublicKey):
        if cosignature:
            raise VerificationError(
                "c2sp checkpoint: RSA keys do not support tlog-cosignature"
            )
        return
    raise VerificationError(
        f"c2sp checkpoint: unsupported public key type {type(public_key).__name__}"
    )


def compute_note_key_id(
    origin: str,
    public_key: PublicKey,
    *,
    cosignature: bool = False,
) -> KeyID:
    """
    Compute the 32-byte key hash (whose first 4 bytes are the big-endian uint32
    ``c2sp.org/signed-note`` key ID) for ``(origin, public_key)``.

    Matches ``KeyHash`` in ``rekor-tiles/pkg/note/note.go`` and
    ``c2sp.org/tlog-cosignature``:
    - ``Ed25519``: ``SHA256(origin || "\\n" || (0x04 if cosignature else 0x01) || raw_pub)``
    - ``ML-DSA-44``: ``SHA256(origin || "\\n" || 0x06 || raw_pub)``
    - ``ECDSA``: ``SHA256(spki_der)``
    - ``RSA``: ``SHA256(origin || "\\n" || 0xff || "PKIX-RSA-PKCS#1v1.5" || spki_der)``
    """
    origin_bytes = _validate_tlog_name(origin, "key name")
    _validate_verifier_key(public_key, cosignature=cosignature)

    if isinstance(public_key, ec.EllipticCurvePublicKey):
        spki_der = public_key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return KeyID(hashlib.sha256(spki_der).digest())

    origin_prefix = origin_bytes + b"\n"
    if isinstance(public_key, ed25519.Ed25519PublicKey):
        alg_byte = bytes([ALG_ED25519_COSIGNATURE_V1 if cosignature else ALG_ED25519])
        raw_bytes = public_key.public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
        return KeyID(hashlib.sha256(origin_prefix + alg_byte + raw_bytes).digest())

    if isinstance(public_key, mldsa.MLDSA44PublicKey):
        raw_bytes = public_key.public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
        return KeyID(
            hashlib.sha256(
                origin_prefix + bytes([ALG_MLDSA44_COSIGNATURE_V1]) + raw_bytes
            ).digest()
        )

    if isinstance(public_key, rsa.RSAPublicKey):
        spki_der = public_key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return KeyID(
            hashlib.sha256(
                origin_prefix + bytes([ALG_UNDEF]) + _RSA_ID + spki_der
            ).digest()
        )

    raise VerificationError(
        f"c2sp checkpoint: unsupported public key type {type(public_key).__name__}"
    )


def format_subtree_v1_message(
    *,
    cosigner_name: str,
    timestamp: int,
    log_origin: str,
    tree_size: int,
    root_hash: bytes,
    start: int = 0,
) -> bytes:
    """
    Format a ``c2sp.org/tlog-cosignature`` ``subtree/v1`` binary message:

        ``"subtree/v1\\n\\x00" || uint8(len(cosigner_name)) || cosigner_name``
        ``|| uint64_be(timestamp) || uint8(len(log_origin)) || log_origin``
        ``|| uint64_be(start) || uint64_be(tree_size) || root_hash``
    """
    cosigner_bytes = _validate_tlog_name(cosigner_name, "cosigner name")
    origin_bytes = _validate_tlog_name(log_origin, "log origin")
    if len(root_hash) != _SHA256_DIGEST_SIZE:
        raise VerificationError(
            f"c2sp checkpoint: root_hash must be 32 bytes, got {len(root_hash)}"
        )
    if timestamp < 0 or timestamp > _MAX_POSIX_TIMESTAMP:
        raise VerificationError(
            f"c2sp checkpoint: invalid cosignature timestamp {timestamp}"
        )
    if start < 0 or tree_size < 0 or start > tree_size or tree_size > _MAX_UINT64:
        raise VerificationError(
            f"c2sp checkpoint: invalid subtree range [{start}, {tree_size})"
        )
    if start != 0 and timestamp != 0:
        raise VerificationError(
            "c2sp checkpoint: subtree cosignature with non-zero start must have zero timestamp"
        )

    return (
        _SUBTREE_V1_LABEL
        + struct.pack(">B", len(cosigner_bytes))
        + cosigner_bytes
        + struct.pack(">QB", timestamp, len(origin_bytes))
        + origin_bytes
        + struct.pack(">QQ", start, tree_size)
        + root_hash
    )


def format_cosignature_v1_message(timestamp: int, note_text: str | bytes) -> bytes:
    """
    Format a ``c2sp.org/tlog-cosignature`` Ed25519 ``cosignature/v1`` message:

        ``"cosignature/v1\\ntime <timestamp>\\n" || note_text``
    """
    if timestamp < 0 or timestamp > _MAX_POSIX_TIMESTAMP:
        raise VerificationError(
            f"c2sp checkpoint: invalid cosignature timestamp {timestamp}"
        )
    raw_note = note_text.encode("utf-8") if isinstance(note_text, str) else note_text
    return _COSIGNATURE_V1_HEADER + str(timestamp).encode("ascii") + b"\n" + raw_note


@dataclass(frozen=True)
class NoteSignature:
    """
    Represents a single signature line in a ``c2sp.org/signed-note``:
    ``— <name> <base64(key_id_4_bytes || raw_signature)>\\n``.
    """

    name: str
    key_id: bytes
    signature: bytes


@dataclass(frozen=True)
class Checkpoint:
    """
    Represents the parsed body of a ``c2sp.org/tlog-checkpoint`` note.
    """

    origin: str
    tree_size: int
    root_hash: bytes
    extension_lines: list[str] = field(default_factory=list)
    """
    Optional opaque extension lines from the checkpoint body.

    NOTE: Per ``c2sp.org/tlog-checkpoint``, extension lines are NOT covered by
    ML-DSA-44 (``0x06``) signatures and MUST NOT be trusted unless covered by a
    verified full-text signature.
    """

    @classmethod
    def from_text(cls, text: str) -> Checkpoint:
        """
        Parse a ``Checkpoint`` from the note text body (which must end with ``\\n``).
        """
        if not text.endswith("\n"):
            raise VerificationError(
                "c2sp checkpoint: note text must end with a newline"
            )

        lines = text[:-1].split("\n")
        if len(lines) < 3:
            raise VerificationError("c2sp checkpoint: too few lines in note text")

        origin = lines[0]
        _validate_tlog_name(origin, "origin")

        raw_size = lines[1].encode("utf-8")
        if not _is_canonical_ascii_uint64(raw_size):
            raise VerificationError(f"c2sp checkpoint: invalid tree size {lines[1]!r}")
        tree_size = int(raw_size)

        try:
            raw_root_b64 = lines[2].encode("ascii")
        except UnicodeEncodeError as exc:
            raise VerificationError(
                f"c2sp checkpoint: invalid base64 in root hash: {exc}"
            ) from exc
        root_hash = _b64decode_strict(
            raw_root_b64, "root hash", error_prefix="c2sp checkpoint"
        )

        if len(root_hash) != _SHA256_DIGEST_SIZE:
            raise VerificationError(
                f"c2sp checkpoint: root hash must be 32 bytes, got {len(root_hash)}"
            )

        extension_lines = lines[3:]
        if any(ext == "" for ext in extension_lines):
            raise VerificationError("c2sp checkpoint: empty extension line")
        if any(ord(ch) < 0x20 for ext in extension_lines for ch in ext):
            raise VerificationError(
                "c2sp checkpoint: extension line contains disallowed control characters"
            )

        return cls(
            origin=origin,
            tree_size=tree_size,
            root_hash=root_hash,
            extension_lines=extension_lines,
        )

    def to_text(self) -> str:
        """
        Serialize this ``Checkpoint`` into ``c2sp.org/tlog-checkpoint`` note text
        (ending with ``\\n``).
        """
        b64_hash = base64.b64encode(self.root_hash).decode("ascii")
        lines = [self.origin, str(self.tree_size), b64_hash, *self.extension_lines]
        return "\n".join(lines) + "\n"


@dataclass(frozen=True)
class NoteVerifier:
    """
    A configured ``c2sp.org/signed-note`` and ``c2sp.org/tlog-cosignature``
    verifier for a specific ``(origin, public_key)`` pair.
    """

    origin: str
    public_key: PublicKey
    key_id: KeyID
    cosignature: bool = False

    def __post_init__(self) -> None:
        """
        Validate ``NoteVerifier`` fields eagerly so misconfigured keys fail fast.
        """
        _validate_tlog_name(self.origin, "key name")
        _validate_verifier_key(self.public_key, cosignature=self.cosignature)
        if len(self.key_id) < 4:
            raise VerificationError(
                f"c2sp checkpoint: key_id must be at least 4 bytes, got {len(self.key_id)}"
            )

    @classmethod
    def from_public_key(
        cls,
        origin: str,
        public_key: PublicKey,
        *,
        cosignature: bool = False,
        key_id: KeyID | None = None,
    ) -> NoteVerifier:
        """
        Create a ``NoteVerifier`` for ``(origin, public_key)``, computing the
        C2SP key ID automatically unless an explicit ``key_id`` is supplied.
        """
        computed_id = (
            key_id
            if key_id is not None
            else compute_note_key_id(origin, public_key, cosignature=cosignature)
        )
        return cls(
            origin=origin,
            public_key=public_key,
            key_id=computed_id,
            cosignature=cosignature,
        )

    @property
    def key_hint(self) -> bytes:
        """
        Return the 4-byte note signature key ID hint.
        """
        return self.key_id[:4]

    def verify_checkpoint_signature(
        self,
        checkpoint: Checkpoint,
        note_text: str,
        raw_signature: bytes,
    ) -> None:
        """
        Verify ``raw_signature`` (the signature bytes after the 4-byte key hint)
        against ``checkpoint`` / ``note_text``.
        """
        if isinstance(self.public_key, mldsa.MLDSA44PublicKey):
            expected_sig_len = 8 + _MLDSA44_SIG_SIZE
            if len(raw_signature) != expected_sig_len:
                raise VerificationError(
                    f"c2sp checkpoint: invalid ML-DSA-44 signature length {len(raw_signature)}, "
                    f"expected {expected_sig_len}"
                )
            (timestamp,) = struct.unpack(">Q", raw_signature[:8])
            if timestamp == 0:
                raise VerificationError(
                    "c2sp checkpoint: ML-DSA-44 checkpoint cosignature timestamp must not be zero"
                )
            sig = raw_signature[8:]
            msg = format_subtree_v1_message(
                cosigner_name=self.origin,
                timestamp=timestamp,
                log_origin=checkpoint.origin,
                tree_size=checkpoint.tree_size,
                root_hash=checkpoint.root_hash,
            )
            try:
                self.public_key.verify(sig, msg)
            except InvalidSignature as exc:
                raise VerificationError(
                    f"c2sp checkpoint: invalid ML-DSA-44 signature for {self.origin!r}"
                ) from exc
            return

        if isinstance(self.public_key, ed25519.Ed25519PublicKey):
            if self.cosignature:
                if len(raw_signature) != 8 + _ED25519_SIG_SIZE:
                    raise VerificationError(
                        "c2sp checkpoint: invalid Ed25519 cosignature length "
                        f"{len(raw_signature)}, expected {8 + _ED25519_SIG_SIZE}"
                    )
                (timestamp,) = struct.unpack(">Q", raw_signature[:8])
                if timestamp == 0:
                    raise VerificationError(
                        "c2sp checkpoint: Ed25519 cosignature timestamp must not be zero"
                    )
                sig = raw_signature[8:]
                msg = format_cosignature_v1_message(timestamp, note_text)
            else:
                if len(raw_signature) != _ED25519_SIG_SIZE:
                    raise VerificationError(
                        f"c2sp checkpoint: invalid Ed25519 signature length {len(raw_signature)}"
                    )
                sig = raw_signature
                msg = note_text.encode("utf-8")

            try:
                self.public_key.verify(sig, msg)
            except InvalidSignature as exc:
                raise VerificationError(
                    f"c2sp checkpoint: invalid Ed25519 signature for {self.origin!r}"
                ) from exc
            return

        if isinstance(self.public_key, ec.EllipticCurvePublicKey):
            hash_alg = _ecdsa_hash_algorithm(self.public_key)
            try:
                self.public_key.verify(
                    raw_signature,
                    note_text.encode("utf-8"),
                    ec.ECDSA(hash_alg),
                )
            except InvalidSignature as exc:
                raise VerificationError(
                    f"c2sp checkpoint: invalid ECDSA signature for {self.origin!r}"
                ) from exc
            return

        if isinstance(self.public_key, rsa.RSAPublicKey):
            try:
                self.public_key.verify(
                    raw_signature,
                    note_text.encode("utf-8"),
                    padding.PKCS1v15(),
                    hashes.SHA256(),
                )
            except InvalidSignature as exc:
                raise VerificationError(
                    f"c2sp checkpoint: invalid RSA signature for {self.origin!r}"
                ) from exc
            return

        raise VerificationError(
            f"c2sp checkpoint: unsupported public key type {type(self.public_key).__name__}"
        )


@dataclass(frozen=True)
class SignedCheckpoint:
    """
    Represents a parsed ``c2sp.org/tlog-checkpoint`` signed note containing the
    raw note text, parsed ``Checkpoint``, and ``NoteSignature`` lines.
    """

    note_text: str
    checkpoint: Checkpoint
    signatures: list[NoteSignature]

    @classmethod
    def from_bytes(cls, data: bytes) -> SignedCheckpoint:
        """
        Parse a ``SignedCheckpoint`` from raw UTF-8 signed note bytes.
        """
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise VerificationError(
                f"c2sp checkpoint: note is not valid UTF-8: {exc}"
            ) from exc
        return cls.from_text(text)

    @classmethod
    def from_text(cls, text: str) -> SignedCheckpoint:
        """
        Parse a ``SignedCheckpoint`` from its UTF-8 string representation.
        """
        # Per c2sp.org/signed-note: Signed notes MUST NOT contain any ASCII
        # control characters (below U+0020) other than newline (\n).
        if any(ord(ch) < 0x20 and ch != "\n" for ch in text):
            raise VerificationError(
                "c2sp checkpoint: note contains disallowed control characters"
            )

        separator = "\n\n"
        if separator not in text:
            raise VerificationError(
                "c2sp checkpoint: note must contain a blank line separating text from signatures"
            )

        # Per c2sp.org/signed-note: the text is separated from the signatures by
        # the last empty line in the note (and for tlog-checkpoint, extension lines
        # cannot be empty, so there is exactly one blank line).
        split_idx = text.rindex(separator)
        note_text = text[: split_idx + 1]
        sig_block = text[split_idx + len(separator) :]

        if not sig_block:
            raise VerificationError(
                "c2sp checkpoint: note must contain at least one signature"
            )
        if not sig_block.endswith("\n"):
            raise VerificationError(
                "c2sp checkpoint: signature section must end with a newline"
            )

        checkpoint = Checkpoint.from_text(note_text)

        sig_lines = sig_block[:-1].split("\n")
        if len(sig_lines) > _MAX_SIGNATURES:
            raise VerificationError(
                f"c2sp checkpoint: too many signature lines "
                f"({len(sig_lines)}, max {_MAX_SIGNATURES})"
            )

        signatures: list[NoteSignature] = []
        seen_signers: set[tuple[str, bytes]] = set()
        for line in sig_lines:
            if not line.startswith(_EM_DASH_PREFIX):
                raise VerificationError(
                    "c2sp checkpoint: malformed signature line (missing em dash prefix)"
                )
            rest = line[len(_EM_DASH_PREFIX) :]
            parts = rest.split(" ")
            if len(parts) != 2:
                raise VerificationError(
                    "c2sp checkpoint: malformed signature line (expected '<name> <base64>')"
                )
            name, b64_sig = parts
            if not is_valid_note_name(name) or not b64_sig:
                raise VerificationError(
                    f"c2sp checkpoint: invalid signature line name or empty signature for {name!r}"
                )
            try:
                raw_b64_sig = b64_sig.encode("ascii")
            except UnicodeEncodeError as exc:
                raise VerificationError(
                    f"c2sp checkpoint: invalid base64 in signature line: {exc}"
                ) from exc
            sig_bytes = _b64decode_strict(
                raw_b64_sig, "signature line", error_prefix="c2sp checkpoint"
            )

            if len(sig_bytes) < 5:
                raise VerificationError(
                    "c2sp checkpoint: signature contains too few bytes"
                )
            sig_key_id = sig_bytes[:4]
            signer_key = (name, sig_key_id)
            if signer_key in seen_signers:
                raise VerificationError(
                    f"c2sp checkpoint: duplicate signature line for {name!r} "
                    f"(key ID {sig_key_id.hex()})"
                )
            seen_signers.add(signer_key)
            signatures.append(
                NoteSignature(
                    name=name,
                    key_id=sig_key_id,
                    signature=sig_bytes[4:],
                )
            )

        return cls(
            note_text=note_text,
            checkpoint=checkpoint,
            signatures=signatures,
        )

    def verify(
        self,
        log_verifiers: Iterable[NoteVerifier],
        *,
        witness_verifiers: Iterable[NoteVerifier] = (),
        witness_threshold: int = 0,
    ) -> None:
        """
        Verify this ``SignedCheckpoint`` against the configured ``log_verifiers``
        and optional ``witness_verifiers``.

        Per ``c2sp.org/signed-note`` and ``c2sp.org/tlog-checkpoint``:
        - The log's signature name must match ``self.checkpoint.origin`` and its
          ``(name, key_id)`` must match a known log verifier for that origin.
        - Signatures from unknown ``(name, key_id)`` pairs are ignored.
        - If a signature matches a known verifier's ``(name, key_id)`` and fails
          cryptographic verification, the entire checkpoint is rejected.
        - At least one known log verifier must verify the checkpoint, and at
          least ``witness_threshold`` distinct known witnesses must verify it.
        """
        if witness_threshold < 0:
            raise VerificationError(
                f"c2sp checkpoint: invalid witness_threshold {witness_threshold}"
            )

        log_map: dict[tuple[str, bytes], list[NoteVerifier]] = {}
        for lv in log_verifiers:
            if lv.origin == self.checkpoint.origin:
                log_map.setdefault((lv.origin, lv.key_hint), []).append(lv)

        witness_map: dict[tuple[str, bytes], list[NoteVerifier]] = {}
        for wv in witness_verifiers:
            if not (
                isinstance(wv.public_key, mldsa.MLDSA44PublicKey)
                or (
                    isinstance(wv.public_key, ed25519.Ed25519PublicKey)
                    and wv.cosignature
                )
            ):
                raise VerificationError(
                    f"c2sp checkpoint: witness verifier for {wv.origin!r} must be "
                    "ML-DSA-44 or Ed25519 with cosignature=True"
                )
            # A log cannot witness itself; skip any verifier whose name matches
            # the checkpoint's log origin so a log signature never satisfies a
            # witness quorum slot.
            if wv.origin == self.checkpoint.origin:
                continue
            witness_map.setdefault((wv.origin, wv.key_hint), []).append(wv)

        log_verified = False
        verified_witnesses: set[str] = set()

        for sig in self.signatures:
            lookup = (sig.name, sig.key_id)
            if lookup in log_map:
                err = self._verify_any(log_map[lookup], sig.signature)
                if err is not None:
                    raise VerificationError(
                        f"c2sp checkpoint: invalid log signature from {sig.name!r} "
                        f"(key ID {sig.key_id.hex()}): {err}"
                    ) from err
                log_verified = True

            if lookup in witness_map:
                err = self._verify_any(witness_map[lookup], sig.signature)
                if err is not None:
                    raise VerificationError(
                        f"c2sp checkpoint: invalid witness cosignature from {sig.name!r} "
                        f"(key ID {sig.key_id.hex()}): {err}"
                    ) from err
                verified_witnesses.add(sig.name)

        if not log_verified:
            raise VerificationError(
                f"c2sp checkpoint: no valid log signature found for origin {self.checkpoint.origin!r}"
            )

        if len(verified_witnesses) < witness_threshold:
            raise VerificationError(
                f"c2sp checkpoint: witness quorum not met: expected {witness_threshold}, "
                f"got {len(verified_witnesses)}"
            )

    def _verify_any(
        self,
        verifiers: list[NoteVerifier],
        raw_signature: bytes,
    ) -> VerificationError | None:
        last_err: VerificationError | None = None
        for verifier in verifiers:
            try:
                verifier.verify_checkpoint_signature(
                    self.checkpoint,
                    self.note_text,
                    raw_signature,
                )
                return None
            except VerificationError as exc:
                last_err = exc
        return last_err
