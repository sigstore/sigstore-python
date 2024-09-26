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
from cryptography.x509 import ExtendedKeyUsage, KeyUsage
from cryptography.x509.oid import ExtendedKeyUsageOID
from OpenSSL.crypto import (
    X509,
    X509Store,
    X509StoreContext,
    X509StoreContextError,
    X509StoreFlags,
)
from pydantic import ValidationError

from sigstore import dsse
from sigstore._internal.rekor import _hashedrekord_from_parts
from sigstore._internal.rekor.client import RekorClient
from sigstore._internal.sct import (
    _get_precertificate_signed_certificate_timestamps,
    verify_sct,
)
from sigstore._internal.trust import ClientTrustConfig, KeyringPurpose, TrustedRoot
from sigstore._utils import base64_encode_pem_cert, sha256_digest
from sigstore.errors import VerificationError
from sigstore.hashes import Hashed
from sigstore.models import Bundle
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
    def production(cls, *, offline: bool = False) -> Verifier:
        """
        Return a `Verifier` instance configured against Sigstore's production-level services.
        """
        return cls(
            rekor=RekorClient.production(),
            trusted_root=TrustedRoot.production(offline=offline),
        )

    @classmethod
    def staging(cls, *, offline: bool = False) -> Verifier:
        """
        Return a `Verifier` instance configured against Sigstore's staging-level services.
        """
        return cls(
            rekor=RekorClient.staging(),
            trusted_root=TrustedRoot.staging(offline=offline),
        )

    @classmethod
    def _from_trust_config(cls, trust_config: ClientTrustConfig) -> Verifier:
        """
        Create a `Verifier` from the given `ClientTrustConfig`.

        @api private
        """
        return cls(
            rekor=RekorClient(trust_config._inner.signing_config.tlog_urls[0]),
            trusted_root=trust_config.trusted_root,
        )

    def _verify_common_signing_cert(
        self, bundle: Bundle, policy: VerificationPolicy
    ) -> None:
        """
        Performs the signing certificate verification steps that are shared between
        `verify_dsse` and `verify_artifact`.

        Raises `VerificationError` on all failures.
        """

        # In order to verify an artifact, we need to achieve the following:
        #
        # 1. Verify that the signing certificate chains to the root of trust
        #    and is valid at the time of signing.
        # 2. Verify the signing certificate's SCT.
        # 3. Verify that the signing certificate conforms to the Sigstore
        #    X.509 profile as well as the passed-in `VerificationPolicy`.
        # 4. Verify the inclusion proof and signed checkpoint for the log
        #    entry.
        # 5. Verify the inclusion promise for the log entry, if present.
        # 6. Verify the timely insertion of the log entry against the validity
        #    period for the signing certificate.
        # 7. Verify the signature and input against the signing certificate's
        #    public key.
        # 8. Verify the transparency log entry's consistency against the other
        #    materials, to prevent variants of CVE-2022-36056.
        #
        # This method performs steps (1) through (6) above. Its caller
        # MUST perform steps (7) and (8) separately, since they vary based on
        # the kind of verification being performed (i.e. hashedrekord, DSSE, etc.)

        cert = bundle.signing_certificate

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

        # (1): verify that the signing certificate is signed by the root
        #      certificate and that the signing certificate was valid at the
        #      time of signing.
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

        # (2): verify the signing certificate's SCT.
        sct = _get_precertificate_signed_certificate_timestamps(cert)[0]
        try:
            verify_sct(
                sct,
                cert,
                [parent_cert.to_cryptography() for parent_cert in chain],
                self._trusted_root.ct_keyring(KeyringPurpose.VERIFY),
            )
        except VerificationError as e:
            raise VerificationError(f"failed to verify SCT on signing certificate: {e}")

        # (3): verify the signing certificate against the Sigstore
        #      X.509 profile and verify against the given `VerificationPolicy`.
        usage_ext = cert.extensions.get_extension_for_class(KeyUsage)
        if not usage_ext.value.digital_signature:
            raise VerificationError("Key usage is not of type `digital signature`")

        extended_usage_ext = cert.extensions.get_extension_for_class(ExtendedKeyUsage)
        if ExtendedKeyUsageOID.CODE_SIGNING not in extended_usage_ext.value:
            raise VerificationError("Extended usage does not contain `code signing`")

        policy.verify(cert)

        _logger.debug("Successfully verified signing certificate validity...")

        # (4): verify the inclusion proof and signed checkpoint for the
        #      log entry.
        # (5): verify the inclusion promise for the log entry, if present.
        entry = bundle.log_entry
        try:
            entry._verify(self._trusted_root.rekor_keyring(KeyringPurpose.VERIFY))
        except VerificationError as exc:
            raise VerificationError(f"invalid log entry: {exc}")

        # (6): verify that log entry was integrated circa the signing certificate's
        #      validity period.
        integrated_time = datetime.fromtimestamp(entry.integrated_time, tz=timezone.utc)
        if not (
            bundle.signing_certificate.not_valid_before_utc
            <= integrated_time
            <= bundle.signing_certificate.not_valid_after_utc
        ):
            raise VerificationError(
                "invalid signing cert: expired at time of Rekor entry"
            )

    def verify_dsse(
        self, bundle: Bundle, policy: VerificationPolicy
    ) -> tuple[str, bytes]:
        """
        Verifies an bundle's DSSE envelope, returning the encapsulated payload
        and its content type.

        This method is only for DSSE-enveloped payloads. To verify
        an arbitrary input against a bundle, use the `verify_artifact`
        method.

        `bundle` is the Sigstore `Bundle` to both verify and verify against.

        `policy` is the `VerificationPolicy` to verify against.

        Returns a tuple of `(type, payload)`, where `type` is the payload's
        type as encoded in the DSSE envelope and `payload` is the raw `bytes`
        of the payload. No validation of either `type` or `payload` is
        performed; users of this API **must** assert that `type` is known
        to them before proceeding to handle `payload` in an application-dependent
        manner.
        """

        # (1) through (6) are performed by `_verify_common_signing_cert`.
        self._verify_common_signing_cert(bundle, policy)

        # (7): verify the bundle's signature and DSSE envelope against the
        #      signing certificate's public key.
        envelope = bundle._dsse_envelope
        if envelope is None:
            raise VerificationError(
                "cannot perform DSSE verification on a bundle without a DSSE envelope"
            )

        signing_key = bundle.signing_certificate.public_key()
        signing_key = cast(ec.EllipticCurvePublicKey, signing_key)
        dsse._verify(signing_key, envelope)

        # (8): verify the consistency of the log entry's body against
        #      the other bundle materials.
        # NOTE: This is very slightly weaker than the consistency check
        # for hashedrekord entries, due to how inclusion is recorded for DSSE:
        # the included entry for DSSE includes an envelope hash that we
        # *cannot* verify, since the envelope is uncanonicalized JSON.
        # Instead, we manually pick apart the entry body below and verify
        # the parts we can (namely the payload hash and signature list).
        entry = bundle.log_entry
        try:
            entry_body = rekor_types.Dsse.model_validate_json(
                base64.b64decode(entry.body)
            )
        except ValidationError as exc:
            raise VerificationError(f"invalid DSSE log entry: {exc}")

        payload_hash = sha256_digest(envelope._inner.payload).digest.hex()
        if (
            entry_body.spec.root.payload_hash.algorithm  # type: ignore[union-attr]
            != rekor_types.dsse.Algorithm.SHA256
        ):
            raise VerificationError("expected SHA256 payload hash in DSSE log entry")
        if payload_hash != entry_body.spec.root.payload_hash.value:  # type: ignore[union-attr]
            raise VerificationError("log entry payload hash does not match bundle")

        # NOTE: Like `dsse._verify`: multiple signatures would be frivolous here,
        # but we handle them just in case the signer has somehow produced multiple
        # signatures for their envelope with the same signing key.
        signatures = [
            rekor_types.dsse.Signature(
                signature=base64.b64encode(signature.sig).decode(),
                verifier=base64_encode_pem_cert(bundle.signing_certificate),
            )
            for signature in envelope._inner.signatures
        ]
        if signatures != entry_body.spec.root.signatures:
            raise VerificationError("log entry signatures do not match bundle")

        return (envelope._inner.payload_type, envelope._inner.payload)

    def verify_artifact(
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

        # (1) through (6) are performed by `_verify_common_signing_cert`.
        self._verify_common_signing_cert(bundle, policy)

        hashed_input = sha256_digest(input_)

        # (7): verify that the signature was signed by the public key in the signing certificate.
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

        # (8): verify the consistency of the log entry's body against
        #      the other bundle materials (and input being verified).
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
