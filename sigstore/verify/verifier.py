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
from typing import cast

import rekor_types
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509 import Certificate, ExtendedKeyUsage, KeyUsage
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
from sigstore_models.common import v1
from sigstore_models.rekor import v2

from sigstore import dsse
from sigstore._internal.rekor import _hashedrekord_from_parts
from sigstore._internal.rekor.client import RekorClient
from sigstore._internal.sct import (
    verify_sct,
)
from sigstore._internal.timestamp import TimestampSource, TimestampVerificationResult
from sigstore._internal.trust import KeyringPurpose, TrustedRoot
from sigstore._utils import base64_encode_pem_cert, sha256_digest
from sigstore.errors import CertValidationError, VerificationError
from sigstore.hashes import Hashed
from sigstore.models import Bundle, ClientTrustConfig
from sigstore.verify.policy import VerificationPolicy

_logger = logging.getLogger(__name__)

# Limit the number of timestamps to prevent DoS
# From https://github.com/sigstore/sigstore-go/blob/e92142f0734064ebf6001f188b7330a1212245fe/pkg/verify/tsa.go#L29
MAX_ALLOWED_TIMESTAMP: int = 32

# When verifying an entry, this threshold represents the minimum number of required
# verified times to consider a signature valid.
VERIFIED_TIME_THRESHOLD: int = 1


class Verifier:
    """
    The primary API for verification operations.
    """

    def __init__(self, *, trusted_root: TrustedRoot):
        """
        Create a new `Verifier`.

        `trusted_root` is the `TrustedRoot` object containing the root of trust
        for the verification process.
        """
        self._fulcio_certificate_chain: list[X509] = [
            X509.from_cryptography(parent_cert)
            for parent_cert in trusted_root.get_fulcio_certs()
        ]
        self._trusted_root = trusted_root

        # this is an ugly hack needed for verifying "detached" materials
        # In reality we should be choosing the rekor instance based on the logid
        url = trusted_root._inner.tlogs[0].base_url
        self._rekor = RekorClient(url)

    @classmethod
    def production(cls, *, offline: bool = False) -> Verifier:
        """
        Return a `Verifier` instance configured against Sigstore's production-level services.

        `offline` controls the Trusted Root refresh behavior: if `True`,
        the verifier uses the Trusted Root in the local TUF cache. If `False`,
        a TUF repository refresh is attempted.
        """
        config = ClientTrustConfig.production(offline=offline)
        return cls(
            trusted_root=config.trusted_root,
        )

    @classmethod
    def staging(cls, *, offline: bool = False) -> Verifier:
        """
        Return a `Verifier` instance configured against Sigstore's staging-level services.

        `offline` controls the Trusted Root refresh behavior: if `True`,
        the verifier uses the Trusted Root in the local TUF cache. If `False`,
        a TUF repository refresh is attempted.
        """
        config = ClientTrustConfig.staging(offline=offline)
        return cls(
            trusted_root=config.trusted_root,
        )

    def _verify_signed_timestamp(
        self, timestamp_response: TimeStampResponse, message: bytes
    ) -> TimestampVerificationResult | None:
        """
        Verify a Signed Timestamp using the TSA provided by the Trusted Root.
        """
        cert_authorities = self._trusted_root.get_timestamp_authorities()
        for certificate_authority in cert_authorities:
            certificates = certificate_authority.certificates(allow_expired=True)

            # We expect at least a signing cert and a root cert but there may be intermediates
            if len(certificates) < 2:
                _logger.debug("Unable to verify Timestamp: cert chain is incomplete")
                continue

            builder = (
                VerifierBuilder()
                .tsa_certificate(certificates[0])
                .add_root_certificate(certificates[-1])
            )
            for certificate in certificates[1:-1]:
                builder = builder.add_intermediate_certificate(certificate)

            verifier = builder.build()
            try:
                verifier.verify_message(timestamp_response, message)
            except Rfc3161VerificationError:
                _logger.debug("Unable to verify Timestamp with CA.", exc_info=True)
                continue

            if (
                certificate_authority.validity_period_start
                <= timestamp_response.tst_info.gen_time
            ) and (
                not certificate_authority.validity_period_end
                or timestamp_response.tst_info.gen_time
                < certificate_authority.validity_period_end
            ):
                return TimestampVerificationResult(
                    source=TimestampSource.TIMESTAMP_AUTHORITY,
                    time=timestamp_response.tst_info.gen_time,
                )

            _logger.debug("Unable to verify Timestamp because not in CA time range.")

        return None

    def _verify_timestamp_authority(
        self, bundle: Bundle
    ) -> list[TimestampVerificationResult]:
        """
        Verify that the given bundle has been timestamped by a trusted timestamp authority
        and that the timestamp is valid.

        Returns the number of valid signed timestamp in the bundle.
        """
        timestamp_responses = []
        if (
            timestamp_verification_data
            := bundle.verification_material.timestamp_verification_data
        ):
            timestamp_responses = timestamp_verification_data.rfc3161_timestamps

        if len(timestamp_responses) > MAX_ALLOWED_TIMESTAMP:
            msg = f"too many signed timestamp: {len(timestamp_responses)} > {MAX_ALLOWED_TIMESTAMP}"
            raise VerificationError(msg)

        if len(set(timestamp_responses)) != len(timestamp_responses):
            msg = "duplicate timestamp found"
            raise VerificationError(msg)

        verified_timestamps = [
            result
            for tsr in timestamp_responses
            if (result := self._verify_signed_timestamp(tsr, bundle.signature))
        ]

        return verified_timestamps

    def _establish_time(self, bundle: Bundle) -> list[TimestampVerificationResult]:
        """
        Establish the time for bundle verification.

        This method uses timestamps from two possible sources:
        1. RFC3161 signed timestamps from a Timestamping Authority (TSA)
        2. Transparency Log timestamps
        """
        verified_timestamps = []

        # If a timestamp from the timestamping service is available, the Verifier MUST
        # perform path validation using the timestamp from the Timestamping Service.
        if bundle.verification_material.timestamp_verification_data:
            if not self._trusted_root.get_timestamp_authorities():
                msg = (
                    "no Timestamp Authorities have been provided to validate this "
                    "bundle but it contains a signed timestamp"
                )
                raise VerificationError(msg)

            timestamp_from_tsa = self._verify_timestamp_authority(bundle)
            verified_timestamps.extend(timestamp_from_tsa)

        # If a timestamp from the Transparency Service is available, the Verifier MUST
        # perform path validation using the timestamp from the Transparency Service.
        # NOTE: We only include this timestamp if it's accompanied by an inclusion
        # promise that cryptographically binds it. We verify the inclusion promise
        # itself later, as part of log entry verification.
        if (
            timestamp := bundle.log_entry._inner.integrated_time
        ) and bundle.log_entry._inner.inclusion_promise:
            kv = bundle.log_entry._inner.kind_version
            if not (kv.kind in ["dsse", "hashedrekord"] and kv.version == "0.0.1"):
                raise VerificationError(
                    "Integrated time only supported for dsse/hashedrekord 0.0.1 types"
                )

            verified_timestamps.append(
                TimestampVerificationResult(
                    source=TimestampSource.TRANSPARENCY_SERVICE,
                    time=datetime.fromtimestamp(timestamp, tz=timezone.utc),
                )
            )
        return verified_timestamps

    def _verify_chain_at_time(
        self, certificate: X509, timestamp_result: TimestampVerificationResult
    ) -> list[X509]:
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
            raise CertValidationError(
                f"failed to build timestamp certificate chain: {e}"
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
        # First, establish verified times for the signature. This is required to
        # validate the certificate chain, so this step comes first.
        # These include TSA timestamps and (in the case of rekor v1 entries)
        # rekor log integrated time.
        verified_timestamps = self._establish_time(bundle)
        if len(verified_timestamps) < VERIFIED_TIME_THRESHOLD:
            raise VerificationError("not enough sources of verified time")

        # (1): verify that the signing certificate is signed by the root
        #      certificate and that the signing certificate was valid at the
        #      time of signing.
        cert_ossl = X509.from_cryptography(cert)
        chain: list[X509] = []
        for vts in verified_timestamps:
            chain = self._verify_chain_at_time(cert_ossl, vts)

        # (2): verify the signing certificate's SCT.
        try:
            verify_sct(
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

        # (6): verify our established times (timestamps or the log integration time) are
        # within signing certificate validity period.
        for vts in verified_timestamps:
            if not (
                bundle.signing_certificate.not_valid_before_utc
                <= vts.time
                <= bundle.signing_certificate.not_valid_after_utc
            ):
                raise VerificationError(
                    f"invalid signing cert: expired at time of signing, time via {vts}"
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
        if entry._inner.kind_version.kind != "dsse":
            raise VerificationError(
                f"Expected entry type dsse, got {entry._inner.kind_version.kind}"
            )
        if entry._inner.kind_version.version == "0.0.2":
            _validate_dsse_v002_entry_body(bundle)
        elif entry._inner.kind_version.version == "0.0.1":
            _validate_dsse_v001_entry_body(bundle)
        else:
            raise VerificationError(
                f"Unsupported dsse version {entry._inner.kind_version.version}"
            )

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
                bundle._inner.message_signature.signature,  # type: ignore[union-attr]
                hashed_input.digest,
                ec.ECDSA(hashed_input._as_prehashed()),
            )
        except InvalidSignature:
            raise VerificationError("Signature is invalid for input")

        _logger.debug("Successfully verified signature...")

        # (8): verify the consistency of the log entry's body against
        #      the other bundle materials (and input being verified).
        entry = bundle.log_entry
        if entry._inner.kind_version.kind != "hashedrekord":
            raise VerificationError(
                f"Expected entry type hashedrekord, got {entry._inner.kind_version.kind}"
            )

        if entry._inner.kind_version.version == "0.0.2":
            _validate_hashedrekord_v002_entry_body(bundle, hashed_input)
        elif entry._inner.kind_version.version == "0.0.1":
            _validate_hashedrekord_v001_entry_body(bundle, hashed_input)
        else:
            raise VerificationError(
                f"Unsupported hashedrekord version {entry._inner.kind_version.version}"
            )


def _validate_dsse_v001_entry_body(bundle: Bundle) -> None:
    """
    Validate the Entry body for dsse v001.
    """
    entry = bundle.log_entry
    envelope = bundle._dsse_envelope
    if envelope is None:
        raise VerificationError(
            "cannot perform DSSE verification on a bundle without a DSSE envelope"
        )
    try:
        entry_body = rekor_types.Dsse.model_validate_json(
            entry._inner.canonicalized_body
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


def _validate_dsse_v002_entry_body(bundle: Bundle) -> None:
    """
    Validate Entry body for dsse v002.
    """
    entry = bundle.log_entry
    envelope = bundle._dsse_envelope
    if envelope is None:
        raise VerificationError(
            "cannot perform DSSE verification on a bundle without a DSSE envelope"
        )
    try:
        v2_body = v2.entry.Entry.from_json(entry._inner.canonicalized_body)
    except ValidationError as exc:
        raise VerificationError(f"invalid DSSE log entry: {exc}")

    if v2_body.spec.dsse_v002 is None:
        raise VerificationError("invalid DSSE log entry: missing dsse_v002 field")

    if v2_body.spec.dsse_v002.payload_hash.algorithm != v1.HashAlgorithm.SHA2_256:
        raise VerificationError("expected SHA256 hash in DSSE entry")

    digest = sha256_digest(envelope._inner.payload).digest
    if v2_body.spec.dsse_v002.payload_hash.digest != digest:
        raise VerificationError("DSSE entry payload hash does not match bundle")

    v2_signatures = [
        v2.verifier.Signature(
            content=base64.b64encode(signature.sig),
            verifier=_v2_verifier_from_certificate(bundle.signing_certificate),
        )
        for signature in envelope._inner.signatures
    ]
    if v2_signatures != v2_body.spec.dsse_v002.signatures:
        raise VerificationError("log entry signatures do not match bundle")


def _validate_hashedrekord_v001_entry_body(
    bundle: Bundle, hashed_input: Hashed
) -> None:
    """
    Validate the Entry body for hashedrekord v001.
    """
    entry = bundle.log_entry
    expected_body = _hashedrekord_from_parts(
        bundle.signing_certificate,
        bundle._inner.message_signature.signature,  # type: ignore[union-attr]
        hashed_input,
    )
    actual_body = rekor_types.Hashedrekord.model_validate_json(
        entry._inner.canonicalized_body
    )
    if expected_body != actual_body:
        raise VerificationError(
            "transparency log entry is inconsistent with other materials"
        )


def _validate_hashedrekord_v002_entry_body(
    bundle: Bundle, hashed_input: Hashed
) -> None:
    """
    Validate Entry body for hashedrekord v002.
    """
    entry = bundle.log_entry
    if bundle._inner.message_signature is None:
        raise VerificationError(
            "invalid hashedrekord log entry: missing message signature"
        )
    v2_expected_body = v2.entry.Entry(
        kind=entry._inner.kind_version.kind,
        api_version=entry._inner.kind_version.version,
        spec=v2.entry.Spec(
            hashed_rekord_v002=v2.hashedrekord.HashedRekordLogEntryV002(
                data=v1.HashOutput(
                    algorithm=hashed_input.algorithm,
                    digest=base64.b64encode(hashed_input.digest),
                ),
                signature=v2.verifier.Signature(
                    content=base64.b64encode(bundle._inner.message_signature.signature),
                    verifier=_v2_verifier_from_certificate(bundle.signing_certificate),
                ),
            )
        ),
    )
    v2_actual_body = v2.entry.Entry.from_json(entry._inner.canonicalized_body)
    if v2_expected_body != v2_actual_body:
        raise VerificationError(
            "transparency log entry is inconsistent with other materials"
        )


def _v2_verifier_from_certificate(certificate: Certificate) -> v2.verifier.Verifier:
    """
    Return a Rekor v2 Verifier for the signing certificate.

    This method decides which signature algorithms are supported for verification
    (in a rekor v2 entry), see
    https://github.com/sigstore/architecture-docs/blob/main/algorithm-registry.md.
    Note that actual signature verification happens in verify_artifact() and
    verify_dsse(): New keytypes need to be added here and in those methods.
    """
    public_key = certificate.public_key()

    if isinstance(public_key, ec.EllipticCurvePublicKey):
        if isinstance(public_key.curve, ec.SECP256R1):
            key_details = v1.PublicKeyDetails.PKIX_ECDSA_P256_SHA_256
        elif isinstance(public_key.curve, ec.SECP384R1):
            key_details = v1.PublicKeyDetails.PKIX_ECDSA_P384_SHA_384
        elif isinstance(public_key.curve, ec.SECP521R1):
            key_details = v1.PublicKeyDetails.PKIX_ECDSA_P521_SHA_512
        else:
            raise ValueError(f"Unsupported EC curve: {public_key.curve.name}")
    else:
        raise ValueError(f"Unsupported public key type: {type(public_key)}")

    return v2.verifier.Verifier(
        x509_certificate=v1.X509Certificate(
            raw_bytes=base64.b64encode(
                certificate.public_bytes(encoding=serialization.Encoding.DER)
            )
        ),
        key_details=key_details,
    )
