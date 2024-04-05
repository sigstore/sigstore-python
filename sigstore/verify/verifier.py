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

from sigstore._internal.rekor import _hashedrekord_from_parts
from sigstore._internal.rekor.client import RekorClient
from sigstore._internal.sct import (
    _get_precertificate_signed_certificate_timestamps,
    verify_sct,
)
from sigstore._internal.trustroot import KeyringPurpose, TrustedRoot
from sigstore._utils import sha256_digest
from sigstore.errors import VerificationError
from sigstore.hashes import Hashed
from sigstore.verify.models import Bundle
from sigstore.verify.policy import VerificationPolicy

_logger = logging.getLogger(__name__)


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

    def verify(
        self,
        input_: bytes | Hashed,
        bundle: Bundle,
        policy: VerificationPolicy,
    ) -> None:
        """
        Public API for verifying.

        `input_` is the input to verify, either as a buffer of contents or as
        a prehashed `Hashed` object.

        `bundle` is the Sigstore `Bundle` to verify against.

        `policy` is the `VerificationPolicy` to verify against.

        On failure, this method raises `VerificationError`.
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
        # 5) Verify that the log entry is consistent with the other verification
        #    materials, to prevent variants of CVE-2022-36056.
        # 6) Verify the inclusion proof supplied by Rekor for this artifact,
        #    if we're doing online verification.
        # 7) Verify the Signed Entry Timestamp (SET) supplied by Rekor for this
        #    artifact.
        # 8) Verify that the signing certificate was valid at the time of
        #    signing by comparing the expiry against the integrated timestamp.

        # 1) Verify that the signing certificate is signed by the root certificate and that the
        #    signing certificate was valid at the time of signing.
        sign_date = bundle.signing_certificate.not_valid_before_utc
        cert_ossl = X509.from_cryptography(bundle.signing_certificate)

        store.set_time(sign_date)
        store_ctx = X509StoreContext(store, cert_ossl)
        try:
            # get_verified_chain returns the full chain including the end-entity certificate
            # and chain should contain only CA certificates
            chain = store_ctx.get_verified_chain()[1:]
        except X509StoreContextError as exc:
            raise VerificationError(
                f"failed to build chain to signing certificate: {exc}"
            )

        # 2) Check that the signing certificate has a valid sct

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

        # 3) Check that the signing certificate contains the proof claim as the subject
        # Check usage is "digital signature"
        usage_ext = bundle.signing_certificate.extensions.get_extension_for_class(
            KeyUsage
        )
        if not usage_ext.value.digital_signature:
            raise VerificationError("Key usage is not of type `digital signature`")

        # Check that extended usage contains "code signing"
        extended_usage_ext = (
            bundle.signing_certificate.extensions.get_extension_for_class(
                ExtendedKeyUsage
            )
        )
        if ExtendedKeyUsageOID.CODE_SIGNING not in extended_usage_ext.value:
            raise VerificationError("Extended usage does not contain `code signing`")

        policy.verify(bundle.signing_certificate)

        _logger.debug("Successfully verified signing certificate validity...")

        # 4) Verify that the signature was signed by the public key in the signing certificate
        try:
            signing_key = bundle.signing_certificate.public_key()
            signing_key = cast(ec.EllipticCurvePublicKey, signing_key)
            signing_key.verify(
                bundle._inner.message_signature.signature,
                hashed_input.digest,
                ec.ECDSA(hashed_input._as_prehashed()),
            )
        except InvalidSignature:
            raise VerificationError("Signature is invalid for input")

        _logger.debug("Successfully verified signature...")

        # 5) Verify the consistency of the log entry's body against
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
            raise VerificationError(
                "transparency log entry is inconsistent with other materials"
            )

        # 6) Verify the inclusion proof for this artifact, including its checkpoint.
        # 7) Verify the optional inclusion promise (SET) for this artifact
        try:
            entry._verify(self._trusted_root.rekor_keyring())
        except VerificationError as exc:
            # NOTE: Re-raise with a prefix here for additional context.
            raise VerificationError(f"invalid log entry: {exc}")

        # 7) Verify that the signing certificate was valid at the time of signing
        integrated_time = datetime.fromtimestamp(entry.integrated_time, tz=timezone.utc)
        if not (
            bundle.signing_certificate.not_valid_before_utc
            <= integrated_time
            <= bundle.signing_certificate.not_valid_after_utc
        ):
            raise VerificationError(
                "invalid signing cert: expired at time of Rekor entry"
            )
