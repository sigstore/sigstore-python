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

import rekor_types
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509 import (
    Certificate,
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
)
from sigstore._internal.rekor import _hashedrekord_from_parts
from sigstore._internal.rekor.checkpoint import (
    CheckpointError,
)
from sigstore._internal.rekor.client import RekorClient
from sigstore._internal.sct import (
    _get_precertificate_signed_certificate_timestamps,
    verify_sct,
)
from sigstore._internal.trustroot import KeyringPurpose, TrustedRoot
from sigstore._utils import B64Str, HexStr, sha256_digest
from sigstore.errors import Error, VerificationError
from sigstore.hashes import Hashed
from sigstore.transparency import InvalidLogEntry
from sigstore.verify.models import (
    Bundle,
    VerificationFailure,
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
        self._trusted_root = trusted_root

    @classmethod
    def production(cls) -> Verifier:
        """
        Return a `Verifier` instance configured against Sigstore's production-level services.
        """
        trusted_root = TrustedRoot.production(purpose=KeyringPurpose.VERIFY)
        return cls(
            rekor=RekorClient.production(),
            trusted_root=trusted_root,
        )

    @classmethod
    def staging(cls) -> Verifier:
        """
        Return a `Verifier` instance configured against Sigstore's staging-level services.
        """
        trusted_root = TrustedRoot.staging(purpose=KeyringPurpose.VERIFY)
        return cls(
            rekor=RekorClient.staging(),
            trusted_root=trusted_root,
        )

    def _verify_common_signing_cert(
        self, cert: Certificate, policy: VerificationPolicy
    ) -> None:
        """
        Performs the signing certificate verification steps that are shared between
        `verify_intoto` and `verify_artifact`.

        Raises `VerificationError` on all failures.
        """

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

        # 1. Verify that the signing certificate is signed by the root certificate and that the
        #    signing certificate was valid at the time of signing.
        sign_date = cert.not_valid_before_utc
        cert_ossl = X509.from_cryptography(cert)

        store.set_time(sign_date)
        store_ctx = X509StoreContext(store, cert_ossl)
        try:
            # get_verified_chain returns the full chain including the end-entity certificate
            # and chain should contain only CA certificates
            chain = store_ctx.get_verified_chain()[1:]
        except X509StoreContextError as e:
            raise VerificationError(f"failed to build chain: {e}")

        # 2. Check that the signing certificate has a valid SCT
        sct = _get_precertificate_signed_certificate_timestamps(cert)[0]
        try:
            verify_sct(
                sct,
                cert,
                [parent_cert.to_cryptography() for parent_cert in chain],
                self._trusted_root.ct_keyring(),
            )
        except Error as e:
            raise VerificationError(f"failed to verify SCT on signing certificate: {e}")

        # 3. Check that the signing certificate has the expected KU/EKU and
        #    verifies against the given `VerificationPolicy`.

        usage_ext = cert.extensions.get_extension_for_class(KeyUsage)
        if not usage_ext.value.digital_signature:
            raise VerificationError("Key usage is not of type `digital signature`")

        extended_usage_ext = cert.extensions.get_extension_for_class(ExtendedKeyUsage)
        if ExtendedKeyUsageOID.CODE_SIGNING not in extended_usage_ext.value:
            raise VerificationError("Extended usage does not contain `code signing`")

        policy.verify(cert)

        _logger.debug("Successfully verified signing certificate validity...")

    def verify_intoto(self, bundle: Bundle, policy: VerificationPolicy) -> None:
        """
        Verifies an bundle's in-toto statement (encapsulated within the bundle
        as a DSSE envelope).

        This method is only for DSSE-enveloped in-toto statements. To verify
        an arbitrary input against a bundle, use the `verify_artifact`
        method.

        `bundle` is the Sigstore `Bundle` to both verify and verify against.

        `policy` is the `VerificationPolicy` to verify against.

        Returns the in-toto statement as a raw `bytes`, for subsequent
        JSON decoding and policy evaluation. Callers **must** perform this decoding
        and evaluation; mere signature verification by this API does not imply
        that the in-toto statement is valid or trustworthy.
        """

    def verify_artifact(
        self,
        input_: bytes | Hashed,
        bundle: Bundle,
        policy: VerificationPolicy,
    ) -> VerificationResult:
        """Public API for verifying.

        `input_` is the input to verify, either as a buffer of contents or as
        a prehashed `Hashed` object.

        `bundle` is the Sigstore `Bundle` to verify against.

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
        # 1. Verify that the signing certificate chains to the root of trust
        #    and is valid at the time of signing.
        # 2. Verify the signing certificate's SCT.
        # 3. Verify that the signing certificate conforms to the Sigstore
        #    X.509 profile as well as the passed-in `VerificationPolicy`.
        # 4. Verify the signature and input against the signing certificate's
        #    public key.
        # 5. Verify the transparency log entry's consistency against the other
        #    materials, to prevent variants of CVE-2022-36056.
        # 6. Verify the inclusion proof and signed checkpoint for the log
        #    entry.
        # 7. Verify the inclusion promise for the log entry, if present.
        # 8. Verify the timely insertion of the log entry against the validity
        #    period for the signing certificate.

        # (1) through (3) are performed by `_verify_common_signing_cert`.

        # 1. Verify that the signing certificate is signed by the root certificate and that the
        #    signing certificate was valid at the time of signing.
        sign_date = bundle.signing_certificate.not_valid_before_utc
        cert_ossl = X509.from_cryptography(bundle.signing_certificate)

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

        # 2. Check that the signing certificate has a valid SCT

        # The SignedCertificateTimestamp should be acessed by the index 0
        sct = _get_precertificate_signed_certificate_timestamps(
            bundle.signing_certificate
        )[0]
        verify_sct(
            sct,
            bundle.signing_certificate,
            [parent_cert.to_cryptography() for parent_cert in chain],
            self._trusted_root.ct_keyring(),
        )

        # 3. Check that the signing certificate contains the proof claim as the subject
        # Check usage is "digital signature"
        usage_ext = bundle.signing_certificate.extensions.get_extension_for_class(
            KeyUsage
        )
        if not usage_ext.value.digital_signature:
            return VerificationFailure(
                reason="Key usage is not of type `digital signature`"
            )

        # Check that extended usage contains "code signing"
        extended_usage_ext = (
            bundle.signing_certificate.extensions.get_extension_for_class(
                ExtendedKeyUsage
            )
        )
        if ExtendedKeyUsageOID.CODE_SIGNING not in extended_usage_ext.value:
            return VerificationFailure(
                reason="Extended usage does not contain `code signing`"
            )

        policy_check = policy.verify(bundle.signing_certificate)
        if not policy_check:
            return policy_check

        _logger.debug("Successfully verified signing certificate validity...")

        # 4. Verify that the signature was signed by the public key in the signing certificate
        try:
            signing_key = bundle.signing_certificate.public_key()
            signing_key = cast(ec.EllipticCurvePublicKey, signing_key)
            signing_key.verify(
                bundle._inner.message_signature.signature,
                hashed_input.digest,
                ec.ECDSA(hashed_input._as_prehashed()),
            )
        except InvalidSignature:
            return VerificationFailure(reason="Signature is invalid for input")

        _logger.debug("Successfully verified signature...")

        # 5. Verify the consistency of the log entry's body against
        #    the other bundle materials (and input being verified).
        entry = bundle.log_entry

        expected_body = _hashedrekord_from_parts(
            bundle.signing_certificate,
            bundle._inner.message_signature.signature,
            hashed_input,
        )
        actual_body = rekor_types.Hashedrekord.model_validate_json(
            base64.b64decode(entry.body)
        )
        if expected_body != actual_body:
            return VerificationFailure(
                reason="transparency log entry is inconsistent with other materials"
            )

        # 6. Verify the inclusion proof for this artifact, including its checkpoint.
        # 7. Verify the optional inclusion promise (SET) for this artifact
        try:
            entry._verify(self._trusted_root.rekor_keyring())
        except InvalidInclusionProofError as exc:
            return VerificationFailure(reason=f"invalid inclusion proof: {exc}")
        except CheckpointError as exc:
            return VerificationFailure(
                reason=f"invalid inclusion proof checkpoint: {exc}"
            )
        except InvalidLogEntry as exc:
            return VerificationFailure(reason=str(exc))

        # 8. Verify that log entry was integrated circa the signing certificate's
        #    validity period.
        integrated_time = datetime.fromtimestamp(entry.integrated_time, tz=timezone.utc)
        if not (
            bundle.signing_certificate.not_valid_before_utc
            <= integrated_time
            <= bundle.signing_certificate.not_valid_after_utc
        ):
            return VerificationFailure(
                reason="invalid signing cert: expired at time of Rekor entry"
            )

        return VerificationSuccess()
