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
from rfc3161_client import TimeStampResponse, VerifierBuilder
from rfc3161_client import VerificationError as Rfc3161VerificationError

from sigstore import dsse
from sigstore._internal.rekor import _hashedrekord_from_parts
from sigstore._internal.rekor.client import RekorClient
from sigstore._internal.sct import (
    _get_precertificate_signed_certificate_timestamps,
    verify_sct,
)
from sigstore._internal.timestamp import TimestampSource, TimestampVerificationResult
from sigstore._internal.trust import ClientTrustConfig, KeyringPurpose, TrustedRoot
from sigstore._utils import base64_encode_pem_cert, sha256_digest
from sigstore.errors import VerificationError
from sigstore.hashes import Hashed
from sigstore.models import Bundle
from sigstore.verify.policy import VerificationPolicy

_logger = logging.getLogger(__name__)

# Limit the number of timestamps to prevent DoS
# From https://github.com/sigstore/sigstore-go/blob/e92142f0734064ebf6001f188b7330a1212245fe/pkg/verify/tsa.go#L29
MAX_ALLOWED_TIMESTAMP: int = 32

# When verifying a timestamp, this threshold represents the minimum number of required
# timestamps to consider a signature valid.
VERIFY_TIMESTAMP_THRESHOLD: int = 1


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

    def _verify_signed_timestamp(
        self, timestamp_response: TimeStampResponse, signature: bytes
    ) -> TimestampVerificationResult | None:
        """
        Verify a Signed Timestamp using the TSA provided by the Trusted Root.
        """
        cert_authorities = self._trusted_root.get_timestamp_authorities()
        for certificate_authority in cert_authorities:
            certificates = certificate_authority.certificates(allow_expired=True)

            builder = VerifierBuilder()
            for certificate in certificates:
                builder.add_root_certificate(certificate)

            verifier = builder.build()
            try:
                verifier.verify(timestamp_response, signature)
            except Rfc3161VerificationError as e:
                _logger.debug("Unable to verify Timestamp with CA.")
                _logger.exception(e)
                continue

            if (
                certificate_authority.validity_period_start
                and certificate_authority.validity_period_end
            ):
                if (
                    certificate_authority.validity_period_start
                    <= timestamp_response.tst_info.gen_time
                    < certificate_authority.validity_period_end
                ):
                    return TimestampVerificationResult(
                        source=TimestampSource.TIMESTAMP_AUTHORITY,
                        time=timestamp_response.tst_info.gen_time,
                    )

                _logger.debug(
                    "Unable to verify Timestamp because not in CA time range."
                )
            else:
                _logger.debug(
                    "Unable to verify Timestamp because no validity provided."
                )

        return None

    def _verify_timestamp_authority(
        self, bundle: Bundle
    ) -> List[TimestampVerificationResult]:
        """
        Verify that the given bundle has been timestamped by a trusted timestamp authority
        and that the timestamp is valid.

        Returns the number of valid signed timestamp in the bundle.
        """
        timestamp_responses = (
            bundle.verification_material.timestamp_verification_data.rfc3161_timestamps
        )
        if len(timestamp_responses) > MAX_ALLOWED_TIMESTAMP:
            msg = f"too many signed timestamp: {len(timestamp_responses)} > {MAX_ALLOWED_TIMESTAMP}"
            raise VerificationError(msg)

        if len(set(timestamp_responses)) != len(timestamp_responses):
            msg = "duplicate timestamp found"
            raise VerificationError(msg)

        # The Signer sends a hash of the signature as the messageImprint in a TimeStampReq
        # to the Timestamping Service
        signature_hash = sha256_digest(bundle.signature).digest
        verified_timestamps = []
        for tsr in timestamp_responses:
            if verified_timestamp := self._verify_signed_timestamp(tsr, signature_hash):
                verified_timestamps.append(verified_timestamp)

        return verified_timestamps

    def _establish_time(self, bundle: Bundle) -> List[TimestampVerificationResult]:
        """
        Establish the time for bundle verification.

        This method uses timestamps from two possible sources:
        1. RFC3161 signed timestamps from a Timestamping Authority (TSA)
        2. Transparency Log timestamps
        """
        verified_timestamps = []

        # If a timestamp from the timestamping service is available, the Verifier MUST
        # perform path validation using the timestamp from the Timestamping Service.
        if bundle.verification_material.timestamp_verification_data.rfc3161_timestamps:
            if not self._trusted_root.get_timestamp_authorities():
                msg = (
                    "no Timestamp Authorities have been provided to validate this "
                    "bundle but it contains a signed timestamp"
                )
                raise VerificationError(msg)

            timestamp_from_tsa = self._verify_timestamp_authority(bundle)
            if len(timestamp_from_tsa) < VERIFY_TIMESTAMP_THRESHOLD:
                msg = (
                    f"not enough timestamps validated to meet the validation "
                    f"threshold ({len(timestamp_from_tsa)}/{VERIFY_TIMESTAMP_THRESHOLD})"
                )
                raise VerificationError(msg)

            verified_timestamps.extend(timestamp_from_tsa)

        # If a timestamp from the Transparency Service is available, the Verifier MUST
        # perform path validation using the timestamp from the Transparency Service.
        # NOTE: We only include this timestamp if it's accompanied by an inclusion
        # promise that cryptographically binds it. We verify the inclusion promise
        # itself later, as part of log entry verification.
        if (
            timestamp := bundle.log_entry.integrated_time
        ) and bundle.log_entry.inclusion_promise:
            verified_timestamps.append(
                TimestampVerificationResult(
                    source=TimestampSource.TRANSPARENCY_SERVICE,
                    time=datetime.fromtimestamp(timestamp, tz=timezone.utc),
                )
            )
        return verified_timestamps

    def _verify_chain_at_time(
        self, certificate: X509, timestamp_result: TimestampVerificationResult
    ) -> List[X509]:
        """
        Verify the validity of the certificate chain at the given time.

        Raises a VerificationError if the chain can't be built or be verified.
        """
        # NOTE: The `X509Store` object cannot have its time reset once the `set_time`
        # method been called on it. To get around this, we construct a new one in each
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

        store.set_time(timestamp_result.time)

        store_ctx = X509StoreContext(store, certificate)

        try:
            # get_verified_chain returns the full chain including the end-entity certificate
            # and chain should contain only CA certificates
            return store_ctx.get_verified_chain()[1:]
        except X509StoreContextError as e:
            raise VerificationError(f"failed to build chain: {e}")

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
        # 0. Establish a time for the signature.
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
        # This method performs steps (0) through (6) above. Its caller
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

        # (0): Establishing a Time for the Signature
        # First, establish a time for the signature. This timestamp is required to
        # validate the certificate chain, so this step comes first.
        # While this step is optional and only performed if timestamp data has been
        # provided within the bundle, providing a signed timestamp without a TSA to
        # verify it result in a VerificationError.
        verified_timestamps = self._establish_time(bundle)
        if not verified_timestamps:
            raise VerificationError("not enough sources of verified time")

        # (1): verify that the signing certificate is signed by the root
        #      certificate and that the signing certificate was valid at the
        #      time of signing.
        cert_ossl = X509.from_cryptography(cert)
        chain: list[X509] = []
        for vts in verified_timestamps:
            chain = self._verify_chain_at_time(cert_ossl, vts)

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
