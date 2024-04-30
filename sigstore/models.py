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
Common models shared between signing and verification.
"""

from __future__ import annotations

import base64
import logging
import typing
from textwrap import dedent
from typing import Any, List, Optional

import rfc8785
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509 import (
    Certificate,
    load_der_x509_certificate,
)
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictInt,
    StrictStr,
    TypeAdapter,
    ValidationInfo,
    field_validator,
)
from pydantic.dataclasses import dataclass
from rekor_types import Dsse, Hashedrekord, ProposedEntry
from sigstore_protobuf_specs.dev.sigstore.bundle import v1 as bundle_v1
from sigstore_protobuf_specs.dev.sigstore.bundle.v1 import (
    Bundle as _Bundle,
)
from sigstore_protobuf_specs.dev.sigstore.common import v1 as common_v1
from sigstore_protobuf_specs.dev.sigstore.rekor import v1 as rekor_v1
from sigstore_protobuf_specs.dev.sigstore.rekor.v1 import (
    InclusionProof,
)

from sigstore import dsse
from sigstore._internal.merkle import verify_merkle_inclusion
from sigstore._internal.rekor.checkpoint import verify_checkpoint
from sigstore._utils import (
    B64Str,
    BundleType,
    KeyID,
    cert_is_leaf,
    cert_is_root_ca,
)
from sigstore.errors import Error, VerificationError

if typing.TYPE_CHECKING:
    from sigstore._internal.trustroot import RekorKeyring


_logger = logging.getLogger(__name__)


class LogInclusionProof(BaseModel):
    """
    Represents an inclusion proof for a transparency log entry.
    """

    model_config = ConfigDict(populate_by_name=True)

    checkpoint: StrictStr = Field(..., alias="checkpoint")
    hashes: List[StrictStr] = Field(..., alias="hashes")
    log_index: StrictInt = Field(..., alias="logIndex")
    root_hash: StrictStr = Field(..., alias="rootHash")
    tree_size: StrictInt = Field(..., alias="treeSize")

    @field_validator("log_index")
    def _log_index_positive(cls, v: int) -> int:
        if v < 0:
            raise ValueError(f"Inclusion proof has invalid log index: {v} < 0")
        return v

    @field_validator("tree_size")
    def _tree_size_positive(cls, v: int) -> int:
        if v < 0:
            raise ValueError(f"Inclusion proof has invalid tree size: {v} < 0")
        return v

    @field_validator("tree_size")
    def _log_index_within_tree_size(
        cls, v: int, info: ValidationInfo, **kwargs: Any
    ) -> int:
        if "log_index" in info.data and v <= info.data["log_index"]:
            raise ValueError(
                "Inclusion proof has log index greater than or equal to tree size: "
                f"{v} <= {info.data['log_index']}"
            )
        return v


@dataclass(frozen=True)
class LogEntry:
    """
    Represents a transparency log entry.

    Log entries are retrieved from the transparency log after signing or verification events,
    or loaded from "Sigstore" bundles provided by the user.

    This representation allows for either a missing inclusion promise or a missing
    inclusion proof, but not both: attempting to construct a `LogEntry` without
    at least one will fail.
    """

    uuid: Optional[str]
    """
    This entry's unique ID in the log instance it was retrieved from.

    For sharded log deployments, IDs are unique per-shard.

    Not present for `LogEntry` instances loaded from Sigstore bundles.
    """

    body: B64Str
    """
    The base64-encoded body of the transparency log entry.
    """

    integrated_time: int
    """
    The UNIX time at which this entry was integrated into the transparency log.
    """

    log_id: str
    """
    The log's ID (as the SHA256 hash of the DER-encoded public key for the log
    at the time of entry inclusion).
    """

    log_index: int
    """
    The index of this entry within the log.
    """

    inclusion_proof: LogInclusionProof
    """
    An inclusion proof for this log entry.
    """

    inclusion_promise: Optional[B64Str]
    """
    An inclusion promise for this log entry, if present.

    Internally, this is a base64-encoded Signed Entry Timestamp (SET) for this
    log entry.
    """

    @classmethod
    def _from_response(cls, dict_: dict[str, Any]) -> LogEntry:
        """
        Create a new `LogEntry` from the given API response.
        """

        # Assumes we only get one entry back
        entries = list(dict_.items())
        if len(entries) != 1:
            raise ValueError("Received multiple entries in response")

        uuid, entry = entries[0]
        return LogEntry(
            uuid=uuid,
            body=entry["body"],
            integrated_time=entry["integratedTime"],
            log_id=entry["logID"],
            log_index=entry["logIndex"],
            inclusion_proof=LogInclusionProof.model_validate(
                entry["verification"]["inclusionProof"]
            ),
            inclusion_promise=entry["verification"]["signedEntryTimestamp"],
        )

    @classmethod
    def _from_dict_rekor(cls, dict_: dict[str, Any]) -> LogEntry:
        """
        Create a new `LogEntry` from the given Rekor TransparencyLogEntry.
        """
        tlog_entry = rekor_v1.TransparencyLogEntry()
        tlog_entry.from_dict(dict_)

        inclusion_proof: InclusionProof | None = tlog_entry.inclusion_proof
        # This check is required by us as the client, not the
        # protobuf-specs themselves.
        if inclusion_proof is None or inclusion_proof.checkpoint.envelope is None:
            raise InvalidBundle("entry must contain inclusion proof")

        parsed_inclusion_proof = LogInclusionProof(
            checkpoint=inclusion_proof.checkpoint.envelope,
            hashes=[h.hex() for h in inclusion_proof.hashes],
            log_index=inclusion_proof.log_index,
            root_hash=inclusion_proof.root_hash.hex(),
            tree_size=inclusion_proof.tree_size,
        )

        return LogEntry(
            uuid=None,
            body=B64Str(base64.b64encode(tlog_entry.canonicalized_body).decode()),
            integrated_time=tlog_entry.integrated_time,
            log_id=tlog_entry.log_id.key_id.hex(),
            log_index=tlog_entry.log_index,
            inclusion_proof=parsed_inclusion_proof,
            inclusion_promise=B64Str(
                base64.b64encode(
                    tlog_entry.inclusion_promise.signed_entry_timestamp
                ).decode()
            ),
        )

    def _to_dict_rekor(self) -> dict[str, Any]:
        inclusion_promise: rekor_v1.InclusionPromise | None = None
        if self.inclusion_promise:
            inclusion_promise = rekor_v1.InclusionPromise(
                signed_entry_timestamp=base64.b64decode(self.inclusion_promise)
            )

        inclusion_proof = rekor_v1.InclusionProof(
            log_index=self.inclusion_proof.log_index,
            root_hash=bytes.fromhex(self.inclusion_proof.root_hash),
            tree_size=self.inclusion_proof.tree_size,
            hashes=[bytes.fromhex(hash_) for hash_ in self.inclusion_proof.hashes],
            checkpoint=rekor_v1.Checkpoint(envelope=self.inclusion_proof.checkpoint),
        )

        tlog_entry = rekor_v1.TransparencyLogEntry(
            log_index=self.log_index,
            log_id=common_v1.LogId(key_id=bytes.fromhex(self.log_id)),
            integrated_time=self.integrated_time,
            inclusion_promise=inclusion_promise,
            inclusion_proof=inclusion_proof,
            canonicalized_body=base64.b64decode(self.body),
        )

        # Fill in the appropriate kind
        body_entry = TypeAdapter(ProposedEntry).validate_json(
            tlog_entry.canonicalized_body
        )
        if not isinstance(body_entry, (Hashedrekord, Dsse)):
            raise InvalidBundle("log entry is not of expected type")

        tlog_entry.kind_version = rekor_v1.KindVersion(
            kind=body_entry.kind, version=body_entry.api_version
        )

        tlog_entry_dict: dict[str, Any] = tlog_entry.to_dict()
        return tlog_entry_dict

    def encode_canonical(self) -> bytes:
        """
        Returns a canonicalized JSON (RFC 8785) representation of the transparency log entry.

        This encoded representation is suitable for verification against
        the Signed Entry Timestamp.
        """
        payload: dict[str, int | str] = {
            "body": self.body,
            "integratedTime": self.integrated_time,
            "logID": self.log_id,
            "logIndex": self.log_index,
        }

        return rfc8785.dumps(payload)

    def _verify_set(self, keyring: RekorKeyring) -> None:
        """
        Verify the inclusion promise (Signed Entry Timestamp) for a given transparency log
        `entry` using the given `keyring`.

        Fails if the given log entry does not contain an inclusion promise.
        """

        if self.inclusion_promise is None:
            raise VerificationError("SET: invalid inclusion promise: missing")

        signed_entry_ts = base64.b64decode(self.inclusion_promise)

        try:
            keyring.verify(
                key_id=KeyID(bytes.fromhex(self.log_id)),
                signature=signed_entry_ts,
                data=self.encode_canonical(),
            )
        except VerificationError as exc:
            raise VerificationError(f"SET: invalid inclusion promise: {exc}")

    def _verify(self, keyring: RekorKeyring) -> None:
        """
        Verifies this log entry.

        This method performs steps (5), (6), and optionally (7) in
        the top-level verify API:

        * Verifies the consistency of the entry with the given bundle;
        * Verifies the Merkle inclusion proof and its signed checkpoint;
        * Verifies the inclusion promise, if present.
        """

        verify_merkle_inclusion(self)
        verify_checkpoint(keyring, self)

        _logger.debug(f"successfully verified inclusion proof: index={self.log_index}")

        if self.inclusion_promise:
            self._verify_set(keyring)
            _logger.debug(
                f"successfully verified inclusion promise: index={self.log_index}"
            )


class InvalidBundle(Error):
    """
    Raised when the associated `Bundle` is invalid in some way.
    """

    def diagnostics(self) -> str:
        """Returns diagnostics for the error."""

        return dedent(
            f"""\
        An issue occurred while parsing the Sigstore bundle.

        The provided bundle is malformed and may have been modified maliciously.

        Additional context:

        {self}
        """
        )


class Bundle:
    """
    Represents a Sigstore bundle.
    """

    def __init__(self, inner: _Bundle) -> None:
        """
        Creates a new bundle. This is not a public API; use
        `from_json` instead.

        @private
        """
        self._inner = inner
        self._verify_bundle()

    def _verify_bundle(self) -> None:
        """
        Performs various feats of heroism to ensure the bundle is well-formed
        and upholds invariants, including:

        * The "leaf" (signing) certificate is present;
        * There is a inclusion proof present, even if the Bundle's version
           predates a mandatory inclusion proof.
        """

        # The bundle must have a recognized media type.
        try:
            media_type = BundleType(self._inner.media_type)
        except ValueError:
            raise InvalidBundle(f"unsupported bundle format: {self._inner.media_type}")

        # Extract the signing certificate.
        if media_type in (BundleType.BUNDLE_0_3, BundleType.BUNDLE_0_3_ALT):
            # For "v3" bundles, the signing certificate is the only one present.
            leaf_cert = load_der_x509_certificate(
                self._inner.verification_material.certificate.raw_bytes
            )
        else:
            # In older bundles, there is an entire pool (misleadingly called
            # a chain) of certificates, the first of which is the signing
            # certificate.
            certs = (
                self._inner.verification_material.x509_certificate_chain.certificates
            )

            if len(certs) == 0:
                raise InvalidBundle("expected non-empty certificate chain in bundle")

            # Per client policy in protobuf-specs: the first entry in the chain
            # MUST be a leaf certificate, and the rest of the chain MUST NOT
            # include a root CA or any intermediate CAs that appear in an
            # independent root of trust.
            #
            # We expect some old bundles to violate the rules around root
            # and intermediate CAs, so we issue warnings and not hard errors
            # in those cases.
            leaf_cert, *chain_certs = [
                load_der_x509_certificate(cert.raw_bytes) for cert in certs
            ]
            if not cert_is_leaf(leaf_cert):
                raise InvalidBundle(
                    "bundle contains an invalid leaf or non-leaf certificate in the leaf position"
                )

            for chain_cert in chain_certs:
                # TODO: We should also retrieve the root of trust here and
                # cross-check against it.
                if cert_is_root_ca(chain_cert):
                    _logger.warning(
                        "this bundle contains a root CA, making it subject to misuse"
                    )

        self._signing_certificate = leaf_cert

        # Extract the log entry. For the time being, we expect
        # bundles to only contain a single log entry.
        tlog_entries = self._inner.verification_material.tlog_entries
        if len(tlog_entries) != 1:
            raise InvalidBundle("expected exactly one log entry in bundle")
        tlog_entry = tlog_entries[0]

        # Handling of inclusion promises and proofs varies between bundle
        # format versions:
        #
        # * For 0.1, an inclusion promise is required; the client
        #   MUST verify the inclusion promise.
        #   The inclusion proof is NOT required. If provided, it might NOT
        #   contain a checkpoint; in this case, we ignore it (since it's
        #   useless without one).
        #
        # * For 0.2+, an inclusion proof is required; the client MUST
        #   verify the inclusion proof. The inclusion prof MUST contain
        #   a checkpoint.
        #   The inclusion promise is NOT required; if present, the client
        #   SHOULD verify it.
        #
        # Before all of this, we require that the inclusion proof be present
        # (when constructing the LogEntry).
        log_entry = LogEntry._from_dict_rekor(tlog_entry.to_dict())

        if media_type == BundleType.BUNDLE_0_1:
            if not log_entry.inclusion_promise:
                raise InvalidBundle("bundle must contain an inclusion promise")
            if not log_entry.inclusion_proof.checkpoint:
                _logger.debug(
                    "0.1 bundle contains inclusion proof without checkpoint; ignoring"
                )
        else:
            if not log_entry.inclusion_proof.checkpoint:
                raise InvalidBundle("expected checkpoint in inclusion proof")

        self._log_entry = log_entry

    @property
    def signing_certificate(self) -> Certificate:
        """Returns the bundle's contained signing (i.e. leaf) certificate."""
        return self._signing_certificate

    @property
    def log_entry(self) -> LogEntry:
        """
        Returns the bundle's log entry, containing an inclusion proof
        (with checkpoint) and an inclusion promise (if the latter is present).
        """
        return self._log_entry

    @property
    def _dsse_envelope(self) -> dsse.Envelope | None:
        """
        Returns the DSSE envelope within this Bundle as a `dsse.Envelope`.

        @private
        """
        if self._inner.dsse_envelope:
            return dsse.Envelope(self._inner.dsse_envelope)
        return None

    @classmethod
    def from_json(cls, raw: bytes | str) -> Bundle:
        """
        Deserialize the given Sigstore bundle.
        """
        inner = _Bundle().from_json(raw)
        return cls(inner)

    def to_json(self) -> str:
        """
        Return a JSON encoding of this bundle.
        """
        # TODO: Unclear why mypy doesn't like this.
        return self._inner.to_json()  # type: ignore[no-any-return]

    @classmethod
    def from_parts(cls, cert: Certificate, sig: bytes, log_entry: LogEntry) -> Bundle:
        """
        Construct a Sigstore bundle (of `hashedrekord` type) from its
        constituent parts.
        """

        return cls._from_parts(
            cert, common_v1.MessageSignature(signature=sig), log_entry
        )

    @classmethod
    def _from_parts(
        cls,
        cert: Certificate,
        content: common_v1.MessageSignature | dsse.Envelope,
        log_entry: LogEntry,
    ) -> Bundle:
        """
        @private
        """

        inner = _Bundle(
            media_type=BundleType.BUNDLE_0_3.value,
            verification_material=bundle_v1.VerificationMaterial(
                certificate=common_v1.X509Certificate(cert.public_bytes(Encoding.DER)),
            ),
        )

        # Fill in the appropriate variants.
        if isinstance(content, common_v1.MessageSignature):
            inner.message_signature = content
        else:
            inner.dsse_envelope = content._inner

        tlog_entry = rekor_v1.TransparencyLogEntry()
        tlog_entry.from_dict(log_entry._to_dict_rekor())
        inner.verification_material.tlog_entries = [tlog_entry]

        return cls(inner)
