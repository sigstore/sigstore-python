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
from enum import Enum
from textwrap import dedent
from typing import Any

import rfc8785
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509 import (
    Certificate,
    load_der_x509_certificate,
)
from pydantic import TypeAdapter
from rekor_types import Dsse, Hashedrekord, ProposedEntry
from rfc3161_client import TimeStampResponse, decode_timestamp_response
from sigstore_models.bundle import v1 as bundle_v1
from sigstore_models.bundle.v1 import Bundle as _Bundle
from sigstore_models.bundle.v1 import (
    TimestampVerificationData as _TimestampVerificationData,
)
from sigstore_models.bundle.v1 import VerificationMaterial as _VerificationMaterial
from sigstore_models.common import v1 as common_v1
from sigstore_models.common.v1 import MessageSignature, RFC3161SignedTimestamp
from sigstore_models.rekor import v1 as rekor_v1
from sigstore_models.rekor.v1 import TransparencyLogEntry as _TransparencyLogEntry

from sigstore import dsse
from sigstore._internal.merkle import verify_merkle_inclusion
from sigstore._internal.rekor.checkpoint import verify_checkpoint
from sigstore._utils import (
    KeyID,
    cert_is_leaf,
    cert_is_root_ca,
)
from sigstore.errors import Error, VerificationError

if typing.TYPE_CHECKING:
    from sigstore._internal.trust import RekorKeyring

from pathlib import Path

from sigstore_models.trustroot import v1 as trustroot_v1

from sigstore._internal.trust import SigningConfig, TrustedRoot
from sigstore._internal.tuf import DEFAULT_TUF_URL, STAGING_TUF_URL, TrustUpdater
from sigstore.errors import TUFError

_logger = logging.getLogger(__name__)


class TransparencyLogEntry:
    """
    Represents a transparency log entry.
    """

    def __init__(self, inner: _TransparencyLogEntry) -> None:
        """
        Creates a new `TransparencyLogEntry` from the given inner object.

        @private
        """
        self._inner = inner
        self._validate()

    def _validate(self) -> None:
        """
        Ensure this transparency log entry is well-formed and upholds our
        client invariants.
        """

        inclusion_proof: rekor_v1.InclusionProof | None = self._inner.inclusion_proof
        # This check is required by us as the client, not the
        # protobuf-specs themselves.
        if not inclusion_proof or not inclusion_proof.checkpoint:
            raise InvalidBundle("entry must contain inclusion proof, with checkpoint")

    def __eq__(self, value: object) -> bool:
        """
        Compares this `TransparencyLogEntry` with another object for equality.

        Two `TransparencyLogEntry` instances are considered equal if their
        inner contents are equal.
        """
        if not isinstance(value, TransparencyLogEntry):
            return NotImplemented
        return self._inner == value._inner

    @classmethod
    def _from_v1_response(cls, dict_: dict[str, Any]) -> TransparencyLogEntry:
        """
        Create a new `TransparencyLogEntry` from the given API response.
        """

        # Assumes we only get one entry back
        entries = list(dict_.items())
        if len(entries) != 1:
            raise ValueError("Received multiple entries in response")
        _, entry = entries[0]

        # Fill in the appropriate kind
        body_entry: ProposedEntry = TypeAdapter(ProposedEntry).validate_json(
            base64.b64decode(entry["body"])
        )
        if not isinstance(body_entry, (Hashedrekord, Dsse)):
            raise InvalidBundle("log entry is not of expected type")

        raw_inclusion_proof = entry["verification"]["inclusionProof"]

        # NOTE: The type ignores below are a consequence of our Pydantic
        # modeling: mypy and other typecheckers see `ProtoU64` as `int`,
        # but it gets coerced from a string due to Protobuf's JSON serialization.
        inner = _TransparencyLogEntry(
            log_index=str(entry["logIndex"]),  # type: ignore[arg-type]
            log_id=common_v1.LogId(
                key_id=base64.b64encode(bytes.fromhex(entry["logID"]))
            ),
            kind_version=rekor_v1.KindVersion(
                kind=body_entry.kind, version=body_entry.api_version
            ),
            integrated_time=str(entry["integratedTime"]),  # type: ignore[arg-type]
            inclusion_promise=rekor_v1.InclusionPromise(
                signed_entry_timestamp=entry["verification"]["signedEntryTimestamp"]
            ),
            inclusion_proof=rekor_v1.InclusionProof(
                log_index=str(raw_inclusion_proof["logIndex"]),  # type: ignore[arg-type]
                root_hash=base64.b64encode(
                    bytes.fromhex(raw_inclusion_proof["rootHash"])
                ),
                tree_size=str(raw_inclusion_proof["treeSize"]),  # type: ignore[arg-type]
                hashes=[
                    base64.b64encode(bytes.fromhex(h))
                    for h in raw_inclusion_proof["hashes"]
                ],
                checkpoint=rekor_v1.Checkpoint(
                    envelope=raw_inclusion_proof["checkpoint"]
                ),
            ),
            canonicalized_body=entry["body"],
        )

        return cls(inner)

    def _encode_canonical(self) -> bytes:
        """
        Returns a canonicalized JSON (RFC 8785) representation of the transparency log entry.

        This encoded representation is suitable for verification against
        the Signed Entry Timestamp.
        """
        # We might not have an integrated time if our log entry is from rekor
        # v2, i.e. was integrated synchronously instead of via an
        # inclusion promise.
        if self._inner.integrated_time is None:
            raise ValueError(
                "can't encode canonical form for SET without integrated time"
            )

        payload: dict[str, int | str] = {
            "body": base64.b64encode(self._inner.canonicalized_body).decode(),
            "integratedTime": self._inner.integrated_time,
            "logID": self._inner.log_id.key_id.hex(),
            "logIndex": self._inner.log_index,
        }

        return rfc8785.dumps(payload)

    def _verify_set(self, keyring: RekorKeyring) -> None:
        """
        Verify the inclusion promise (Signed Entry Timestamp) for a given transparency log
        `entry` using the given `keyring`.

        Fails if the given log entry does not contain an inclusion promise.
        """

        if self._inner.inclusion_promise is None:
            raise VerificationError("SET: invalid inclusion promise: missing")

        signed_entry_ts = self._inner.inclusion_promise.signed_entry_timestamp

        try:
            keyring.verify(
                key_id=KeyID(self._inner.log_id.key_id),
                signature=signed_entry_ts,
                data=self._encode_canonical(),
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

        _logger.debug(
            f"successfully verified inclusion proof: index={self._inner.log_index}"
        )

        if self._inner.inclusion_promise and self._inner.integrated_time:
            self._verify_set(keyring)
            _logger.debug(
                f"successfully verified inclusion promise: index={self._inner.log_index}"
            )


class TimestampVerificationData:
    """
    Represents a TimestampVerificationData structure.

    @private
    """

    def __init__(self, inner: _TimestampVerificationData) -> None:
        """Init method."""
        self._inner = inner
        self._verify()

    def _verify(self) -> None:
        """
        Verifies the TimestampVerificationData.

        It verifies that TimeStamp Responses embedded in the bundle are correctly
        formed.
        """
        if not (timestamps := self._inner.rfc3161_timestamps):
            timestamps = []

        try:
            self._signed_ts = [
                decode_timestamp_response(ts.signed_timestamp) for ts in timestamps
            ]
        except ValueError:
            raise VerificationError("Invalid Timestamp Response")

    @property
    def rfc3161_timestamps(self) -> list[TimeStampResponse]:
        """Returns a list of signed timestamp."""
        return self._signed_ts

    @classmethod
    def from_json(cls, raw: str | bytes) -> TimestampVerificationData:
        """
        Deserialize the given timestamp verification data.
        """
        inner = _TimestampVerificationData.from_json(raw)
        return cls(inner)


class VerificationMaterial:
    """
    Represents a VerificationMaterial structure.
    """

    def __init__(self, inner: _VerificationMaterial) -> None:
        """Init method."""
        self._inner = inner

    @property
    def timestamp_verification_data(self) -> TimestampVerificationData | None:
        """
        Returns the Timestamp Verification Data, if present.
        """
        if (
            self._inner.timestamp_verification_data
            and self._inner.timestamp_verification_data.rfc3161_timestamps
        ):
            return TimestampVerificationData(self._inner.timestamp_verification_data)
        return None


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

    class BundleType(str, Enum):
        """
        Known Sigstore bundle media types.
        """

        BUNDLE_0_1 = "application/vnd.dev.sigstore.bundle+json;version=0.1"
        BUNDLE_0_2 = "application/vnd.dev.sigstore.bundle+json;version=0.2"
        BUNDLE_0_3_ALT = "application/vnd.dev.sigstore.bundle+json;version=0.3"
        BUNDLE_0_3 = "application/vnd.dev.sigstore.bundle.v0.3+json"

        def __str__(self) -> str:
            """Returns the variant's string value."""
            return self.value

    def __init__(self, inner: _Bundle) -> None:
        """
        Creates a new bundle. This is not a public API; use
        `from_json` instead.

        @private
        """
        self._inner = inner
        self._verify()

    def _verify(self) -> None:
        """
        Performs various feats of heroism to ensure the bundle is well-formed
        and upholds invariants, including:

        * The "leaf" (signing) certificate is present;
        * There is a inclusion proof present, even if the Bundle's version
           predates a mandatory inclusion proof.
        """

        # The bundle must have a recognized media type.
        try:
            media_type = Bundle.BundleType(self._inner.media_type)
        except ValueError:
            raise InvalidBundle(f"unsupported bundle format: {self._inner.media_type}")

        # Extract the signing certificate.
        if media_type in (
            Bundle.BundleType.BUNDLE_0_3,
            Bundle.BundleType.BUNDLE_0_3_ALT,
        ):
            # For "v3" bundles, the signing certificate is the only one present.
            if not self._inner.verification_material.certificate:
                raise InvalidBundle("expected certificate in bundle")

            leaf_cert = load_der_x509_certificate(
                self._inner.verification_material.certificate.raw_bytes
            )
        else:
            # In older bundles, there is an entire pool (misleadingly called
            # a chain) of certificates, the first of which is the signing
            # certificate.
            if not self._inner.verification_material.x509_certificate_chain:
                raise InvalidBundle("expected certificate chain in bundle")

            chain = self._inner.verification_material.x509_certificate_chain
            if not chain.certificates:
                raise InvalidBundle("expected non-empty certificate chain in bundle")

            # Per client policy in protobuf-specs: the first entry in the chain
            # MUST be a leaf certificate, and the rest of the chain MUST NOT
            # include a root CA or any intermediate CAs that appear in an
            # independent root of trust.
            #
            # We expect some old bundles to violate the rules around root
            # and intermediate CAs, so we issue warnings and not hard errors
            # in those cases.
            leaf_cert, *chain_certs = (
                load_der_x509_certificate(cert.raw_bytes) for cert in chain.certificates
            )
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
        #
        #   The inclusion promise is NOT required if another source of signed
        #   time (such as a signed timestamp) is present. If no other source
        #   of signed time is present, then the inclusion promise MUST be
        #   present.
        #
        # Before all of this, we require that the inclusion proof be present
        # (when constructing the LogEntry).
        log_entry = TransparencyLogEntry(tlog_entry)

        if media_type == Bundle.BundleType.BUNDLE_0_1:
            if not log_entry._inner.inclusion_promise:
                raise InvalidBundle("bundle must contain an inclusion promise")
            if not log_entry._inner.inclusion_proof.checkpoint:
                _logger.debug(
                    "0.1 bundle contains inclusion proof without checkpoint; ignoring"
                )
        else:
            if not log_entry._inner.inclusion_proof.checkpoint:
                raise InvalidBundle("expected checkpoint in inclusion proof")

            if (
                not log_entry._inner.inclusion_promise
                and not self.verification_material.timestamp_verification_data
            ):
                raise InvalidBundle(
                    "bundle must contain an inclusion promise or signed timestamp(s)"
                )

        self._log_entry = log_entry

    @property
    def signing_certificate(self) -> Certificate:
        """Returns the bundle's contained signing (i.e. leaf) certificate."""
        return self._signing_certificate

    @property
    def log_entry(self) -> TransparencyLogEntry:
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
        if self._inner.dsse_envelope is not None:
            return dsse.Envelope(self._inner.dsse_envelope)
        return None

    @property
    def signature(self) -> bytes:
        """
        Returns the signature bytes of this bundle.
        Either from the DSSE Envelope or from the message itself.
        """
        return (
            self._dsse_envelope.signature
            if self._dsse_envelope
            else self._inner.message_signature.signature  # type: ignore[union-attr]
        )

    @property
    def verification_material(self) -> VerificationMaterial:
        """
        Returns the bundle's verification material.
        """
        return VerificationMaterial(self._inner.verification_material)

    @classmethod
    def from_json(cls, raw: bytes | str) -> Bundle:
        """
        Deserialize the given Sigstore bundle.
        """
        try:
            inner = _Bundle.from_json(raw)
        except ValueError as exc:
            raise InvalidBundle(f"failed to load bundle: {exc}")
        return cls(inner)

    def to_json(self) -> str:
        """
        Return a JSON encoding of this bundle.
        """
        return self._inner.to_json()

    def _to_parts(
        self,
    ) -> tuple[Certificate, MessageSignature | dsse.Envelope, TransparencyLogEntry]:
        """
        Decompose the `Bundle` into its core constituent parts.

        @private
        """

        content: MessageSignature | dsse.Envelope
        if self._dsse_envelope:
            content = self._dsse_envelope
        else:
            content = self._inner.message_signature  # type: ignore[assignment]

        return (self.signing_certificate, content, self.log_entry)

    @classmethod
    def from_parts(
        cls, cert: Certificate, sig: bytes, log_entry: TransparencyLogEntry
    ) -> Bundle:
        """
        Construct a Sigstore bundle (of `hashedrekord` type) from its
        constituent parts.
        """

        return cls._from_parts(
            cert, MessageSignature(signature=base64.b64encode(sig)), log_entry
        )

    @classmethod
    def _from_parts(
        cls,
        cert: Certificate,
        content: MessageSignature | dsse.Envelope,
        log_entry: TransparencyLogEntry,
        signed_timestamp: list[TimeStampResponse] | None = None,
    ) -> Bundle:
        """
        @private
        """

        timestamp_verifcation_data = bundle_v1.TimestampVerificationData(
            rfc3161_timestamps=[]
        )
        if signed_timestamp is not None:
            timestamp_verifcation_data.rfc3161_timestamps.extend(
                [
                    RFC3161SignedTimestamp(
                        signed_timestamp=base64.b64encode(response.as_bytes())
                    )
                    for response in signed_timestamp
                ]
            )

        # Fill in the appropriate variant.
        message_signature = None
        dsse_envelope = None
        if isinstance(content, MessageSignature):
            message_signature = content
        else:
            dsse_envelope = content._inner

        inner = _Bundle(
            media_type=Bundle.BundleType.BUNDLE_0_3.value,
            verification_material=bundle_v1.VerificationMaterial(
                certificate=common_v1.X509Certificate(
                    raw_bytes=base64.b64encode(cert.public_bytes(Encoding.DER))
                ),
                tlog_entries=[log_entry._inner],
                timestamp_verification_data=timestamp_verifcation_data,
            ),
            message_signature=message_signature,
            dsse_envelope=dsse_envelope,
        )

        return cls(inner)


class ClientTrustConfig:
    """
    Represents a Sigstore client's trust configuration, including a root of trust.
    """

    class ClientTrustConfigType(str, Enum):
        """
        Known Sigstore client trust config media types.
        """

        CONFIG_0_1 = "application/vnd.dev.sigstore.clienttrustconfig.v0.1+json"

        def __str__(self) -> str:
            """Returns the variant's string value."""
            return self.value

    @classmethod
    def from_json(cls, raw: str) -> ClientTrustConfig:
        """
        Deserialize the given client trust config.
        """
        inner = trustroot_v1.ClientTrustConfig.from_json(raw)
        return cls(inner)

    @classmethod
    def production(
        cls,
        offline: bool = False,
    ) -> ClientTrustConfig:
        """Create new trust config from Sigstore production TUF repository.

        If `offline`, will use data in local TUF cache. Otherwise will
        update the data from remote TUF repository.
        """
        return cls.from_tuf(DEFAULT_TUF_URL, offline)

    @classmethod
    def staging(
        cls,
        offline: bool = False,
    ) -> ClientTrustConfig:
        """Create new trust config from Sigstore staging TUF repository.

        If `offline`, will use data in local TUF cache. Otherwise will
        update the data from remote TUF repository.
        """
        return cls.from_tuf(STAGING_TUF_URL, offline)

    @classmethod
    def from_tuf(
        cls,
        url: str,
        offline: bool = False,
    ) -> ClientTrustConfig:
        """Create a new trust config from a TUF repository.

        If `offline`, will use data in local TUF cache. Otherwise will
        update the trust config from remote TUF repository.
        """
        updater = TrustUpdater(url, offline)

        tr_path = updater.get_trusted_root_path()
        inner_tr = trustroot_v1.TrustedRoot.from_json(Path(tr_path).read_bytes())

        try:
            sc_path = updater.get_signing_config_path()
            inner_sc = trustroot_v1.SigningConfig.from_json(Path(sc_path).read_bytes())
        except TUFError as e:
            raise e

        return cls(
            trustroot_v1.ClientTrustConfig(
                media_type=ClientTrustConfig.ClientTrustConfigType.CONFIG_0_1.value,
                trusted_root=inner_tr,
                signing_config=inner_sc,
            )
        )

    def __init__(self, inner: trustroot_v1.ClientTrustConfig) -> None:
        """
        @api private
        """
        self._inner = inner

    @property
    def trusted_root(self) -> TrustedRoot:
        """
        Return the interior root of trust, as a `TrustedRoot`.
        """
        return TrustedRoot(self._inner.trusted_root)

    @property
    def signing_config(self) -> SigningConfig:
        """
        Return the interior root of trust, as a `SigningConfig`.
        """
        return SigningConfig(self._inner.signing_config)
