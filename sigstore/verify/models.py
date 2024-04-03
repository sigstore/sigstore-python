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
Common (base) models for the verification APIs.
"""

from __future__ import annotations

import base64
import logging
from textwrap import dedent

from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509 import (
    Certificate,
    load_der_x509_certificate,
)
from pydantic import BaseModel
from sigstore_protobuf_specs.dev.sigstore.bundle import v1 as bundle_v1
from sigstore_protobuf_specs.dev.sigstore.bundle.v1 import (
    Bundle as _Bundle,
)
from sigstore_protobuf_specs.dev.sigstore.common import v1 as common_v1
from sigstore_protobuf_specs.dev.sigstore.rekor import v1 as rekor_v1
from sigstore_protobuf_specs.dev.sigstore.rekor.v1 import (
    InclusionPromise,
    InclusionProof,
)

from sigstore import dsse
from sigstore._utils import (
    B64Str,
    BundleType,
    cert_is_leaf,
    cert_is_root_ca,
)
from sigstore.errors import Error
from sigstore.transparency import LogEntry, LogInclusionProof

_logger = logging.getLogger(__name__)


class VerificationResult(BaseModel):
    """
    Represents the result of a verification operation.

    Results are boolish, and failures contain a reason (and potentially
    some additional context).
    """

    success: bool
    """
    Represents the status of this result.
    """

    def __bool__(self) -> bool:
        """
        Returns a boolean representation of this result.

        `VerificationSuccess` is always `True`, and `VerificationFailure`
        is always `False`.
        """
        return self.success


class VerificationSuccess(VerificationResult):
    """
    The verification completed successfully,
    """

    success: bool = True
    """
    See `VerificationResult.success`.
    """


class VerificationFailure(VerificationResult):
    """
    The verification failed, due to `reason`.
    """

    success: bool = False
    """
    See `VerificationResult.success`.
    """

    reason: str
    """
    A human-readable explanation or description of the verification failure.
    """


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


class RekorEntryMissing(Exception):
    """
    Raised if `VerificationMaterials.rekor_entry()` fails to find an entry
    in the Rekor log.

    This is an internal exception; users should not see it.
    """

    pass


class InvalidRekorEntry(InvalidBundle):
    """
    Raised if the effective Rekor entry in `VerificationMaterials.rekor_entry()`
    does not match the other materials in `VerificationMaterials`.

    This can only happen in two scenarios:

    * A user has supplied the wrong offline entry, potentially maliciously;
    * The Rekor log responded with the wrong entry, suggesting a server error.
    """

    pass


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
        # Beneath all of this, we require that the inclusion proof be present.
        inclusion_promise: InclusionPromise | None = tlog_entry.inclusion_promise
        inclusion_proof: InclusionProof | None = tlog_entry.inclusion_proof
        if media_type == BundleType.BUNDLE_0_1:
            if not inclusion_promise:
                raise InvalidBundle("bundle must contain an inclusion promise")
            if inclusion_proof and not inclusion_proof.checkpoint.envelope:
                _logger.debug(
                    "0.1 bundle contains inclusion proof without checkpoint; ignoring"
                )
        else:
            if not inclusion_proof:
                raise InvalidBundle("bundle must contain an inclusion proof")
            if not inclusion_proof.checkpoint.envelope:
                raise InvalidBundle("expected checkpoint in inclusion proof")

        parsed_inclusion_proof: InclusionProof | None = None
        if (
            inclusion_proof is not None
            and inclusion_proof.checkpoint.envelope is not None
        ):
            parsed_inclusion_proof = LogInclusionProof(
                checkpoint=inclusion_proof.checkpoint.envelope,
                hashes=[h.hex() for h in inclusion_proof.hashes],
                log_index=inclusion_proof.log_index,
                root_hash=inclusion_proof.root_hash.hex(),
                tree_size=inclusion_proof.tree_size,
            )

        # Sanity: the only way we can hit this is with a v1 bundle without
        # an inclusion proof. Putting this check here rather than above makes
        # it clear that this check is required by us as the client, not the
        # protobuf-specs themselves.
        if parsed_inclusion_proof is None:
            raise InvalidBundle("bundle must contain inclusion proof")

        self._log_entry = LogEntry(
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
        inclusion_promise: rekor_v1.InclusionPromise | None = None
        if log_entry.inclusion_promise:
            inclusion_promise = rekor_v1.InclusionPromise(
                signed_entry_timestamp=base64.b64decode(log_entry.inclusion_promise)
            )

        inclusion_proof = rekor_v1.InclusionProof(
            log_index=log_entry.inclusion_proof.log_index,
            root_hash=bytes.fromhex(log_entry.inclusion_proof.root_hash),
            tree_size=log_entry.inclusion_proof.tree_size,
            hashes=[bytes.fromhex(hash_) for hash_ in log_entry.inclusion_proof.hashes],
            checkpoint=rekor_v1.Checkpoint(
                envelope=log_entry.inclusion_proof.checkpoint
            ),
        )

        tlog_entry = rekor_v1.TransparencyLogEntry(
            log_index=log_entry.log_index,
            log_id=common_v1.LogId(key_id=bytes.fromhex(log_entry.log_id)),
            integrated_time=log_entry.integrated_time,
            inclusion_promise=inclusion_promise,
            inclusion_proof=inclusion_proof,
            canonicalized_body=base64.b64decode(log_entry.body),
        )

        inner = _Bundle(
            media_type=BundleType.BUNDLE_0_3.value,
            verification_material=bundle_v1.VerificationMaterial(
                certificate=common_v1.X509Certificate(cert.public_bytes(Encoding.DER)),
            ),
        )

        # Fill in the appropriate variants.
        if isinstance(content, common_v1.MessageSignature):
            inner.message_signature = content
            tlog_entry.kind_version = rekor_v1.KindVersion(
                kind="hashedrekord", version="0.0.1"
            )
        else:
            inner.dsse_envelope = content._inner
            tlog_entry.kind_version = rekor_v1.KindVersion(kind="dsse", version="0.0.1")

        inner.verification_material.tlog_entries = [tlog_entry]

        return cls(inner)
