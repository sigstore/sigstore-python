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
Verification API machinery.
"""

from __future__ import annotations

import base64
import logging
from datetime import datetime, timezone
from typing import List, cast

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509 import (
    ExtendedKeyUsage,
    KeyUsage,
)
from cryptography.x509.oid import ExtendedKeyUsageOID
from OpenSSL.crypto import (
    X509,
    X509Store,
    X509StoreContext,
    X509StoreContextError,
    X509StoreFlags,
)
from pydantic import ConfigDict

from sigstore._internal.merkle import (
    InvalidInclusionProofError,
    verify_merkle_inclusion,
)
from sigstore._internal.rekor.checkpoint import (
    CheckpointError,
    verify_checkpoint,
)
from sigstore._internal.rekor.client import RekorClient
from sigstore._internal.sct import (
    _get_precertificate_signed_certificate_timestamps,
    verify_sct,
)
from sigstore._internal.set import InvalidSETError, verify_set
from sigstore._internal.trustroot import KeyringPurpose, TrustedRoot
from sigstore._utils import B64Str, HexStr, sha256_digest
from sigstore.hashes import Hashed
from sigstore.verify.models import InvalidRekorEntry as InvalidRekorEntryError
from sigstore.verify.models import RekorEntryMissing as RekorEntryMissingError
from sigstore.verify.models import (
    VerificationFailure,
    VerificationMaterials,
    VerificationResult,
    VerificationSuccess,
)
from sigstore.verify.policy import VerificationPolicy

_logger = logging.getLogger(__name__)


class LogEntryMissing(VerificationFailure):
    """
    A specialization of `VerificationFailure` for transparency log lookup failures,
    with additional lookup context.
    """

    reason: str = (
        "The transparency log has no entry for the given verification materials"
    )

    signature: B64Str
    """
    The signature present during lookup failure, encoded with base64.
    """

    artifact_hash: HexStr
    """
    The artifact hash present during lookup failure, encoded as a hex string.
    """


class CertificateVerificationFailure(VerificationFailure):
    """
    A specialization of `VerificationFailure` for certificate signature
    verification failures, with additional exception context.
    """

    # Needed for the `exception` field above, since exceptions are
    # not trivially serializable.
    model_config = ConfigDict(arbitrary_types_allowed=True)

    reason: str = "Failed to verify signing certificate"
    exception: Exception


class Verifier:
    """
    The primary API for verification operations.
    """

    def __init__(self, *, rekor: RekorClient, trusted_root: TrustedRoot):
        """
        Create a new `Verifier`.

        `rekor` is a `RekorClient` capable of connecting to a Rekor instance
        containing logs for the file(s) being verified.

        `fulcio_certificate_chain` is a list of PEM-encoded X.509 certificates,
        establishing the trust chain for the signing certificate and signature.
        """
        self._rekor = rekor
        self._fulcio_certificate_chain: List[X509] = [
            X509.from_cryptography(parent_cert)
            for parent_cert in trusted_root.get_fulcio_certs()
        ]

    @classmethod
    def production(cls) -> Verifier:
        """
        Return a `Verifier` instance configured against Sigstore's production-level services.
        """
        trusted_root = TrustedRoot.production(purpose=KeyringPurpose.VERIFY)
        return cls(
            rekor=RekorClient.production(trusted_root),
            trusted_root=trusted_root,
        )

    @classmethod
    def staging(cls) -> Verifier:
        """
        Return a `Verifier` instance configured against Sigstore's staging-level services.
        """
        trusted_root = TrustedRoot.staging(purpose=KeyringPurpose.VERIFY)
        return cls(
            rekor=RekorClient.staging(trusted_root),
            trusted_root=trusted_root,
        )

    def verify(
        self,
        input_: bytes | Hashed,
        materials: VerificationMaterials,
        policy: VerificationPolicy,
    ) -> VerificationResult:
        """Public API for verifying.

        `input_` is the input to verify, either as a buffer of contents or as
        a prehashed `Hashed` object.

        `materials` are the `VerificationMaterials` to verify.

        `policy` is the `VerificationPolicy` to verify against.

        Returns a `VerificationResult` which will be truthy or falsey depending on
        success.
        """

        hashed_input = sha256_digest(input_)

        # NOTE: The `X509Store` object currently cannot have its time reset once the `set_time`
        # method been called on it. To get around this, we construct a new one for every `verify`
        # call.
        store = X509Store()
        # NOTE: By explicitly setting the flags here, we ensure that OpenSSL's
        # PARTIAL_CHAIN default does not change on us. Enabling PARTIAL_CHAIN
        # would be strictly more conformant of OpenSSL, but we currently
        # *want* the "long" chain behavior of performing path validation
        # down to a self-signed root.
        store.set_flags(X509StoreFlags.X509_STRICT)
        for parent_cert_ossl in self._fulcio_certificate_chain:
            store.add_cert(parent_cert_ossl)

        # In order to verify an artifact, we need to achieve the following:
        #
        # 1) Verify that the signing certificate is signed by the certificate
        #    chain and that the signing certificate was valid at the time
        #    of signing.
        # 2) Verify the certificate sct.
        # 3) Verify that the signing certificate belongs to the signer.
        # 4) Verify that the artifact signature was signed by the public key in the
        #    signing certificate.
        # 5) Verify that the Rekor entry is consistent with the other signing
        #    materials (preventing CVE-2022-36056)
        # 6) Verify the inclusion proof supplied by Rekor for this artifact,
        #    if we're doing online verification.
        # 7) Verify the Signed Entry Timestamp (SET) supplied by Rekor for this
        #    artifact.
        # 8) Verify that the signing certificate was valid at the time of
        #    signing by comparing the expiry against the integrated timestamp.

        # 1) Verify that the signing certificate is signed by the root certificate and that the
        #    signing certificate was valid at the time of signing.
        sign_date = materials.certificate.not_valid_before_utc
        cert_ossl = X509.from_cryptography(materials.certificate)

        store.set_time(sign_date)
        store_ctx = X509StoreContext(store, cert_ossl)
        try:
            # get_verified_chain returns the full chain including the end-entity certificate
            # and chain should contain only CA certificates
            chain = store_ctx.get_verified_chain()[1:]
        except X509StoreContextError as store_ctx_error:
            return CertificateVerificationFailure(
                exception=store_ctx_error,
            )

        # 2) Check that the signing certificate has a valid sct

        # The SignedCertificateTimestamp should be acessed by the index 0
        sct = _get_precertificate_signed_certificate_timestamps(materials.certificate)[
            0
        ]
        verify_sct(
            sct,
            materials.certificate,
            [parent_cert.to_cryptography() for parent_cert in chain],
            self._rekor._ct_keyring,
        )

        # 3) Check that the signing certificate contains the proof claim as the subject
        # Check usage is "digital signature"
        usage_ext = materials.certificate.extensions.get_extension_for_class(KeyUsage)
        if not usage_ext.value.digital_signature:
            return VerificationFailure(
                reason="Key usage is not of type `digital signature`"
            )

        # Check that extended usage contains "code signing"
        extended_usage_ext = materials.certificate.extensions.get_extension_for_class(
            ExtendedKeyUsage
        )
        if ExtendedKeyUsageOID.CODE_SIGNING not in extended_usage_ext.value:
            return VerificationFailure(
                reason="Extended usage does not contain `code signing`"
            )

        policy_check = policy.verify(materials.certificate)
        if not policy_check:
            return policy_check

        _logger.debug("Successfully verified signing certificate validity...")

        # 4) Verify that the signature was signed by the public key in the signing certificate
        try:
            signing_key = materials.certificate.public_key()
            signing_key = cast(ec.EllipticCurvePublicKey, signing_key)
            signing_key.verify(
                materials.signature,
                hashed_input.digest,
                ec.ECDSA(hashed_input._as_prehashed()),
            )
        except InvalidSignature:
            return VerificationFailure(reason="Signature is invalid for input")

        _logger.debug("Successfully verified signature...")

        # 5) Retrieve the Rekor entry for this artifact (potentially from
        # an offline entry), confirming its consistency with the other
        # artifacts in the process.
        try:
            entry = materials.rekor_entry(hashed_input, self._rekor)
        except RekorEntryMissingError:
            return LogEntryMissing(
                signature=B64Str(base64.b64encode(materials.signature).decode()),
                artifact_hash=HexStr(hashed_input.digest.hex()),
            )
        except InvalidRekorEntryError:
            return VerificationFailure(
                reason="Rekor entry contents do not match other signing materials"
            )

        # 6) Verify the inclusion proof supplied by Rekor for this artifact.
        #
        # The inclusion proof should always be present in the online case. In
        # the offline case, if it is present, we verify it.
        if entry.inclusion_proof and entry.inclusion_proof.checkpoint:
            try:
                verify_merkle_inclusion(entry)
            except InvalidInclusionProofError as exc:
                return VerificationFailure(
                    reason=f"invalid Rekor inclusion proof: {exc}"
                )

            try:
                verify_checkpoint(self._rekor, entry)
            except CheckpointError as exc:
                return VerificationFailure(reason=f"invalid Rekor root hash: {exc}")

            _logger.debug(
                f"successfully verified inclusion proof: index={entry.log_index}"
            )
        elif not materials._offline:
            # Paranoia: if we weren't given an inclusion proof, then
            # this *must* have been offline verification. If it was online
            # then we've somehow entered an invalid state, so fail.
            return VerificationFailure(reason="missing Rekor inclusion proof")
        else:
            _logger.warning(
                "inclusion proof not present in bundle: skipping due to offline verification"
            )

        # 7) Verify the Signed Entry Timestamp (SET) supplied by Rekor for this artifact
        if entry.inclusion_promise:
            try:
                verify_set(self._rekor, entry)
                _logger.debug(
                    f"successfully verified inclusion promise: index={entry.log_index}"
                )
            except InvalidSETError as inval_set:
                return VerificationFailure(
                    reason=f"invalid Rekor entry SET: {inval_set}"
                )

        # 8) Verify that the signing certificate was valid at the time of signing
        integrated_time = datetime.fromtimestamp(entry.integrated_time, tz=timezone.utc)
        if not (
            materials.certificate.not_valid_before_utc
            <= integrated_time
            <= materials.certificate.not_valid_after_utc
        ):
            return VerificationFailure(
                reason="invalid signing cert: expired at time of Rekor entry"
            )

        return VerificationSuccess()
