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
import datetime
import logging
from typing import List, cast

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.x509 import Certificate, ExtendedKeyUsage, KeyUsage
from cryptography.x509.oid import ExtendedKeyUsageOID
from OpenSSL.crypto import (  # type: ignore[import-untyped]
    X509,
    X509Store,
    X509StoreContext,
    X509StoreContextError,
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
from sigstore._internal.set import InvalidSETError, verify_set
from sigstore._internal.tuf import TrustUpdater
from sigstore._utils import B64Str, HexStr
from sigstore.verify.models import InvalidRekorEntry as InvalidRekorEntryError
from sigstore.verify.models import RekorEntryMissing as RekorEntryMissingError
from sigstore.verify.models import (
    VerificationFailure,
    VerificationMaterials,
    VerificationResult,
    VerificationSuccess,
)
from sigstore.verify.policy import VerificationPolicy

logger = logging.getLogger(__name__)


class LogEntryMissing(VerificationFailure):
    """
    A specialization of `VerificationFailure` for transparency log lookup failures,
    with additional lookup context.
    """

    reason: (
        str
    ) = "The transparency log has no entry for the given verification materials"

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

    def __init__(
        self, *, rekor: RekorClient, fulcio_certificate_chain: List[Certificate]
    ):
        """
        Create a new `Verifier`.

        `rekor` is a `RekorClient` capable of connecting to a Rekor instance
        containing logs for the file(s) being verified.

        `fulcio_certificate_chain` is a list of PEM-encoded X.509 certificates,
        establishing the trust chain for the signing certificate and signature.
        """
        self._rekor = rekor

        self._fulcio_certificate_chain: List[X509] = []
        for parent_cert in fulcio_certificate_chain:
            parent_cert_ossl = X509.from_cryptography(parent_cert)
            self._fulcio_certificate_chain.append(parent_cert_ossl)

    @classmethod
    def production(cls) -> Verifier:
        """
        Return a `Verifier` instance configured against Sigstore's production-level services.
        """
        updater = TrustUpdater.production()
        return cls(
            rekor=RekorClient.production(updater),
            fulcio_certificate_chain=updater.get_fulcio_certs(),
        )

    @classmethod
    def staging(cls) -> Verifier:
        """
        Return a `Verifier` instance configured against Sigstore's staging-level services.
        """
        updater = TrustUpdater.staging()
        return cls(
            rekor=RekorClient.staging(updater),
            fulcio_certificate_chain=updater.get_fulcio_certs(),
        )

    def verify(
        self,
        materials: VerificationMaterials,
        policy: VerificationPolicy,
    ) -> VerificationResult:
        """Public API for verifying.

        `materials` are the `VerificationMaterials` to verify.

        `policy` is the `VerificationPolicy` to verify against.

        Returns a `VerificationResult` which will be truthy or falsey depending on
        success.
        """

        # NOTE: The `X509Store` object currently cannot have its time reset once the `set_time`
        # method been called on it. To get around this, we construct a new one for every `verify`
        # call.
        store = X509Store()
        for parent_cert_ossl in self._fulcio_certificate_chain:
            store.add_cert(parent_cert_ossl)

        # In order to verify an artifact, we need to achieve the following:
        #
        # 1) Verify that the signing certificate is signed by the certificate
        #    chain and that the signing certificate was valid at the time
        #    of signing.
        # 2) Verify that the signing certificate belongs to the signer.
        # 3) Verify that the artifact signature was signed by the public key in the
        #    signing certificate.
        # 4) Verify that the Rekor entry is consistent with the other signing
        #    materials (preventing CVE-2022-36056)
        # 5) Verify the inclusion proof supplied by Rekor for this artifact,
        #    if we're doing online verification.
        # 6) Verify the Signed Entry Timestamp (SET) supplied by Rekor for this
        #    artifact.
        # 7) Verify that the signing certificate was valid at the time of
        #    signing by comparing the expiry against the integrated timestamp.

        # 1) Verify that the signing certificate is signed by the root certificate and that the
        #    signing certificate was valid at the time of signing.
        sign_date = materials.certificate.not_valid_before
        cert_ossl = X509.from_cryptography(materials.certificate)

        store.set_time(sign_date)
        store_ctx = X509StoreContext(store, cert_ossl)
        try:
            store_ctx.verify_certificate()
        except X509StoreContextError as store_ctx_error:
            return CertificateVerificationFailure(
                exception=store_ctx_error,
            )

        # 2) Check that the signing certificate contains the proof claim as the subject
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

        logger.debug("Successfully verified signing certificate validity...")

        # 3) Verify that the signature was signed by the public key in the signing certificate
        try:
            signing_key = materials.certificate.public_key()
            signing_key = cast(ec.EllipticCurvePublicKey, signing_key)
            signing_key.verify(
                materials.signature,
                materials.input_digest,
                ec.ECDSA(Prehashed(hashes.SHA256())),
            )
        except InvalidSignature:
            return VerificationFailure(reason="Signature is invalid for input")

        logger.debug("Successfully verified signature...")

        # 4) Retrieve the Rekor entry for this artifact (potentially from
        # an offline entry), confirming its consistency with the other
        # artifacts in the process.
        try:
            entry = materials.rekor_entry(self._rekor)
        except RekorEntryMissingError:
            return LogEntryMissing(
                signature=B64Str(base64.b64encode(materials.signature).decode()),
                artifact_hash=HexStr(materials.input_digest.hex()),
            )
        except InvalidRekorEntryError:
            return VerificationFailure(
                reason="Rekor entry contents do not match other signing materials"
            )

        # 5) Verify the inclusion proof supplied by Rekor for this artifact.
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

            logger.debug(
                f"successfully verified inclusion proof: index={entry.log_index}"
            )
        elif not materials._offline:
            # Paranoia: if we weren't given an inclusion proof, then
            # this *must* have been offline verification. If it was online
            # then we've somehow entered an invalid state, so fail.
            return VerificationFailure(reason="missing Rekor inclusion proof")
        else:
            logger.warning(
                "inclusion proof not present in bundle: skipping due to offline verification"
            )

        # 6) Verify the Signed Entry Timestamp (SET) supplied by Rekor for this artifact
        if entry.inclusion_promise:
            try:
                verify_set(self._rekor, entry)
                logger.debug(
                    f"successfully verified inclusion promise: index={entry.log_index}"
                )
            except InvalidSETError as inval_set:
                return VerificationFailure(
                    reason=f"invalid Rekor entry SET: {inval_set}"
                )

        # 7) Verify that the signing certificate was valid at the time of signing
        integrated_time = datetime.datetime.utcfromtimestamp(entry.integrated_time)
        if not (
            materials.certificate.not_valid_before
            <= integrated_time
            <= materials.certificate.not_valid_after
        ):
            return VerificationFailure(
                reason="invalid signing cert: expired at time of Rekor entry"
            )

        return VerificationSuccess()
