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
from cryptography.x509 import (
    Certificate,
    ExtendedKeyUsage,
    KeyUsage,
    UnsupportedGeneralNameType,
)
from cryptography.x509.oid import ExtendedKeyUsageOID
from cryptography.x509.verification import (
    Criticality,
    ExtensionPolicy,
    PolicyBuilder,
    Store,
)
from cryptography.x509.verification import (
    VerificationError as X509VerificationError,
)
from pydantic import ValidationError
from rfc3161_client import TimeStampResponse, VerifierBuilder
from rfc3161_client import VerificationError as Rfc3161VerificationError
from sigstore_models.common import v1
from sigstore_models.rekor import v2

from sigstore import dsse
from sigstore._internal.key_details import _get_key_details, _get_prehash
from sigstore._internal.rekor import _hashedrekord_from_parts
from sigstore._internal.rekor.client import RekorClient
from sigstore._internal.sct import (
    verify_sct,
)
from sigstore._internal.timestamp import TimestampSource, TimestampVerificationResult
from sigstore._internal.trust import Keyring, KeyringPurpose, RekorKeyring
from sigstore._utils import base64_encode_pem_cert, sha256_digest
from sigstore.errors import CertValidationError, VerificationError
from sigstore.hashes import Hashed
from sigstore.models import (
    Bundle,
    ClientTrustConfig,
    TransparencyLogEntry,
    TrustedRoot,
)
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

    def __init__(self, *, trusted_root: TrustedRoot, tlog_threshold: int = 1):
        """
        Create a new `Verifier`.

        `trusted_root` is the `TrustedRoot` object containing the root of trust
        for the verification process.

        `tlog_threshold` is the minimum number of trusted transparency log
        operators required for verification. It defaults to 1.
        """
        if tlog_threshold < 1:
            raise ValueError("transparency log threshold must be at least 1")

        self._fulcio_certificate_chain = trusted_root.get_fulcio_certs()
        self._trusted_root = trusted_root
        self._tlog_threshold = tlog_threshold

        # this is an ugly hack needed for verifying "detached" materials
        # In reality we should be choosing the rekor instance based on the logid
        tlogs = trusted_root._inner.tlogs
        if not tlogs:
            raise VerificationError(
                "trusted root contains no transparency log instances"
            )
        url = tlogs[0].base_url
        self._rekor = RekorClient(url)

    @classmethod
    def production(cls, *, offline: bool = False, tlog_threshold: int = 1) -> Verifier:
        """
        Return a `Verifier` instance configured against Sigstore's production-level services.

        `offline` controls Trusted Root refresh behavior.
        `tlog_threshold` controls the minimum transparency log threshold.
        """
        config = ClientTrustConfig.production(offline=offline)
        return cls(
            trusted_root=config.trusted_root,
            tlog_threshold=tlog_threshold,
        )

    @classmethod
    def staging(cls, *, offline: bool = False, tlog_threshold: int = 1) -> Verifier:
        """
        Return a `Verifier` instance configured against Sigstore's staging-level services.

        `offline` controls Trusted Root refresh behavior.
        `tlog_threshold` controls the minimum transparency log threshold.
        """
        config = ClientTrustConfig.staging(offline=offline)
        return cls(
            trusted_root=config.trusted_root,
            tlog_threshold=tlog_threshold,
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

    def _verify_tlog_entry_body(
        self,
        bundle: Bundle,
        entry: TransparencyLogEntry,
        hashed_input: Hashed | None,
    ) -> None:
        """Verify that a transparency log entry matches the bundle contents."""
        if bundle._dsse_envelope is not None:
            kind = entry._inner.kind_version.kind
            version = entry._inner.kind_version.version

            if kind == "hashedrekord" and version == "0.0.2":
                _validate_hashedrekord_v002_dsse_entry_body(bundle, entry)
            elif kind == "dsse" and version == "0.0.1":
                _validate_dsse_v001_entry_body(bundle, entry)
            else:
                raise VerificationError(
                    f"Unsupported DSSE log entry type: {kind}/{version}"
                )
            return

        if hashed_input is None:
            raise VerificationError(
                "missing artifact digest for log entry verification"
            )

        if entry._inner.kind_version.kind != "hashedrekord":
            raise VerificationError(
                f"Expected entry type hashedrekord, got {entry._inner.kind_version.kind}"
            )

        version = entry._inner.kind_version.version
        if version == "0.0.2":
            _validate_hashedrekord_v002_entry_body(bundle, hashed_input, entry)
        elif version == "0.0.1":
            _validate_hashedrekord_v001_entry_body(bundle, hashed_input, entry)
        else:
            raise VerificationError(f"Unsupported hashedrekord version {version}")

    def _verify_tlog_entries(
        self,
        bundle: Bundle,
        hashed_input: Hashed | None = None,
    ) -> list[TimestampVerificationResult]:
        """
        Verify the bundle's transparency log entries and enforce the configured
        threshold.

        A log entry contributes to the threshold only after its transparency log
        proof and its consistency with the signed bundle contents have both been
        verified.
        """
        trusted_tlogs = self._trusted_root._rekor_tlogs(KeyringPurpose.VERIFY)

        seen_entries: set[tuple[bytes, int]] = set()
        verified_entries = 0
        verified_operators: set[str] = set()
        verified_timestamps: list[TimestampVerificationResult] = []

        for entry in bundle._log_entries:
            entry_identity = (
                bytes(entry._inner.log_id.key_id),
                entry._inner.log_index,
            )
            if entry_identity in seen_entries:
                raise VerificationError("duplicate transparency log entry")
            seen_entries.add(entry_identity)

            # Prefer a trusted log whose configured log ID matches the bundle
            # entry. Rekor v2 log IDs are not necessarily the same as the key ID
            # computed from the log's public key, so matching must use the
            # TransparencyLogInstance metadata rather than Keyring's key IDs.
            #
            # If no usable trusted log has a matching log ID, preserve the
            # existing Keyring behavior by treating the bundle log ID as only a
            # hint and trying all successfully loaded trusted Rekor keys.
            candidate_keyrings = []
            exact_candidate_keyrings = []

            for tlog in trusted_tlogs:
                keyring = RekorKeyring(Keyring([tlog.public_key]))
                if not keyring._keyring:
                    continue

                candidate = (tlog, keyring)
                candidate_keyrings.append(candidate)

                if tlog.log_id.key_id == entry._inner.log_id.key_id:
                    exact_candidate_keyrings.append(candidate)

            candidates = exact_candidate_keyrings or candidate_keyrings

            verified_tlogs = []
            for tlog, keyring in candidates:
                try:
                    entry._verify(keyring)
                except VerificationError:
                    continue
                verified_tlogs.append(tlog)

            if not verified_tlogs:
                continue

            # The log proof alone is insufficient: the entry must describe the
            # artifact or DSSE envelope that is actually being verified.
            self._verify_tlog_entry_body(bundle, entry, hashed_input)

            if self._tlog_threshold == 1:
                verified_entries += 1
            else:
                if any(not tlog.operator for tlog in verified_tlogs):
                    raise VerificationError(
                        "operator metadata is required for transparency log "
                        "thresholds greater than 1"
                    )

                operators = {tlog.operator for tlog in verified_tlogs if tlog.operator}
                if len(operators) != 1:
                    raise VerificationError(
                        "transparency log entry matches multiple operators"
                    )

                verified_operators.update(operators)

            timestamp = entry._inner.integrated_time
            if timestamp and entry._inner.inclusion_promise:
                kv = entry._inner.kind_version
                if not (kv.kind in ["dsse", "hashedrekord"] and kv.version == "0.0.1"):
                    raise VerificationError(
                        "Integrated time only supported for "
                        "dsse/hashedrekord 0.0.1 types"
                    )

                verified_timestamps.append(
                    TimestampVerificationResult(
                        source=TimestampSource.TRANSPARENCY_SERVICE,
                        time=datetime.fromtimestamp(timestamp, tz=timezone.utc),
                    )
                )

        verified_count = (
            verified_entries if self._tlog_threshold == 1 else len(verified_operators)
        )
        if verified_count < self._tlog_threshold:
            raise VerificationError(
                "transparency log threshold not met: "
                f"{verified_count} < {self._tlog_threshold}"
            )

        return verified_timestamps

    def _establish_time(
        self,
        bundle: Bundle,
        tlog_timestamps: list[TimestampVerificationResult],
    ) -> list[TimestampVerificationResult]:
        """Establish verified signing times for bundle verification."""
        verified_timestamps = list(tlog_timestamps)

        if bundle.verification_material.timestamp_verification_data:
            if not self._trusted_root.get_timestamp_authorities():
                msg = (
                    "no Timestamp Authorities have been provided to validate this "
                    "bundle but it contains a signed timestamp"
                )
                raise VerificationError(msg)

            timestamp_from_tsa = self._verify_timestamp_authority(bundle)
            verified_timestamps.extend(timestamp_from_tsa)

        return verified_timestamps

    def _verify_chain_at_time(
        self, certificate: Certificate, timestamp_result: TimestampVerificationResult
    ) -> list[Certificate]:
        """
        Verify the validity of the certificate chain at the given time.

        Raises a VerificationError if the chain can't be built or be verified.
        """
        # Client verifiers normally require the client-auth EKU. Fulcio certificates
        # instead use code-signing, which is checked separately below; overriding
        # only the EKU validators preserves the remaining default extension policies.
        ca_policy = ExtensionPolicy.webpki_defaults_ca().may_be_present(
            ExtendedKeyUsage, Criticality.NON_CRITICAL, None
        )
        ee_policy = ExtensionPolicy.webpki_defaults_ee().may_be_present(
            ExtendedKeyUsage, Criticality.NON_CRITICAL, None
        )
        verifier = (
            PolicyBuilder()
            .store(Store(self._fulcio_certificate_chain))
            .time(timestamp_result.time)
            .extension_policies(ca_policy=ca_policy, ee_policy=ee_policy)
            .build_client_verifier()
        )

        try:
            # The verified chain includes the end-entity certificate, which callers omit.
            return verifier.verify(certificate, []).chain[1:]
        except (X509VerificationError, UnsupportedGeneralNameType) as e:
            raise CertValidationError(
                f"failed to build timestamp certificate chain: {e}"
            )

    def _verify_common_signing_cert(
        self,
        bundle: Bundle,
        policy: VerificationPolicy,
        tlog_timestamps: list[TimestampVerificationResult],
    ) -> None:
        """
        Performs the signing certificate verification steps that are shared between
        `verify_dsse` and `verify_artifact`.

        Raises `VerificationError` on all failures.
        """

        # Transparency log evidence and bundle-entry consistency are verified
        # before this method. This ensures that Rekor integrated time is trusted
        # only after the supporting log evidence has been authenticated.
        #
        # This method validates the signing certificate against the established
        # verified times, checks its SCT and verification policy, and enforces
        # its validity period.

        cert = bundle.signing_certificate

        # Establish verified signing times.
        # First, establish verified times for the signature. This is required to
        # validate the certificate chain, so this step comes first.
        # These include TSA timestamps and (in the case of rekor v1 entries)
        # rekor log integrated time.
        verified_timestamps = self._establish_time(bundle, tlog_timestamps)
        if len(verified_timestamps) < VERIFIED_TIME_THRESHOLD:
            raise VerificationError("not enough sources of verified time")

        # Verify that the signing certificate is signed by the root
        #      certificate and that the signing certificate was valid at the
        #      time of signing.
        chain: list[Certificate] = []
        for vts in verified_timestamps:
            chain = self._verify_chain_at_time(cert, vts)

        # Verify the signing certificate's SCT.
        try:
            verify_sct(
                cert,
                chain,
                self._trusted_root.ct_keyring(KeyringPurpose.VERIFY),
            )
        except VerificationError as e:
            raise VerificationError(f"failed to verify SCT on signing certificate: {e}")

        # Verify the signing certificate against the Sigstore
        #      X.509 profile and verify against the given `VerificationPolicy`.
        usage_ext = cert.extensions.get_extension_for_class(KeyUsage)
        if not usage_ext.value.digital_signature:
            raise VerificationError("Key usage is not of type `digital signature`")

        extended_usage_ext = cert.extensions.get_extension_for_class(ExtendedKeyUsage)
        if ExtendedKeyUsageOID.CODE_SIGNING not in extended_usage_ext.value:
            raise VerificationError("Extended usage does not contain `code signing`")

        policy.verify(cert)

        _logger.debug("Successfully verified signing certificate validity...")

        # Verify our established times (timestamps or log integration time) are
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

        envelope = bundle._dsse_envelope
        if envelope is None:
            raise VerificationError(
                "cannot perform DSSE verification on a bundle without a DSSE envelope"
            )

        tlog_timestamps = self._verify_tlog_entries(bundle)
        self._verify_common_signing_cert(bundle, policy, tlog_timestamps)

        # Verify the bundle's signature and DSSE envelope against the signing
        # certificate's public key.

        signing_key = bundle.signing_certificate.public_key()
        signing_key = cast(ec.EllipticCurvePublicKey, signing_key)
        dsse._verify(signing_key, envelope)

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

        hashed_input = sha256_digest(input_)
        bundle_signature = bundle._inner.message_signature
        if bundle_signature is None:
            raise VerificationError("Missing bundle message signature")

        tlog_timestamps = self._verify_tlog_entries(bundle, hashed_input)
        self._verify_common_signing_cert(bundle, policy, tlog_timestamps)

        # signature is verified over input digest, but if the bundle documents the digest we still
        # want to ensure it matches the input digest:
        if (
            bundle_signature.message_digest is not None
            and hashed_input.digest != bundle_signature.message_digest.digest
        ):
            raise VerificationError("Bundle message digest mismatch")

        # (7): verify that the signature was signed by the public key in the signing certificate.
        try:
            signing_key = bundle.signing_certificate.public_key()
            signing_key = cast(ec.EllipticCurvePublicKey, signing_key)
            signing_key.verify(
                bundle_signature.signature,
                hashed_input.digest,
                ec.ECDSA(hashed_input._as_prehashed()),
            )
        except InvalidSignature:
            raise VerificationError("Signature is invalid for input")

        _logger.debug("Successfully verified signature...")


def _validate_dsse_v001_entry_body(bundle: Bundle, entry: TransparencyLogEntry) -> None:
    """
    Validate the Entry body for dsse v001.
    """
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


def _validate_hashedrekord_v001_entry_body(
    bundle: Bundle, hashed_input: Hashed, entry: TransparencyLogEntry
) -> None:
    """
    Validate the Entry body for hashedrekord v001.
    """
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


def _validate_hashedrekord_v002_dsse_entry_body(
    bundle: Bundle, entry: TransparencyLogEntry
) -> None:
    """
    Validate Entry body for a Rekor v2 DSSE envelope encoded as a
    hashedrekord/0.0.2 entry (rekor-v2-spec §6.1.4).

    The expected entry body has:
      - data.digest = Hash(PAE(payloadType, payload)), where Hash is the
        externalized hash function of the entry's signing algorithm.
      - data.algorithm = the matching HashAlgorithm.
      - signature.content = envelope.signatures[0].sig.
      - signature.verifier = the bundle's signing certificate.
    """
    envelope = bundle._dsse_envelope
    if envelope is None:
        raise VerificationError(
            "cannot perform DSSE verification on a bundle without a DSSE envelope"
        )
    if len(envelope._inner.signatures) != 1:
        raise VerificationError(
            "DSSE envelope must have exactly one signature for hashedrekord encoding"
        )

    expected_verifier = _v2_verifier_from_certificate(bundle.signing_certificate)
    algorithm, hash_func = _get_prehash(expected_verifier.key_details)
    pae_digest = hash_func(envelope.pae()).digest()

    expected_body = v2.entry.Entry(
        kind=entry._inner.kind_version.kind,
        api_version=entry._inner.kind_version.version,
        spec=v2.entry.Spec(
            hashed_rekord_v002=v2.hashedrekord.HashedRekordLogEntryV002(
                data=v1.HashOutput(
                    algorithm=algorithm,
                    digest=base64.b64encode(pae_digest),
                ),
                signature=v2.verifier.Signature(
                    content=base64.b64encode(envelope.signature),
                    verifier=expected_verifier,
                ),
            )
        ),
    )
    actual_body = v2.entry.Entry.from_json(entry._inner.canonicalized_body)
    if expected_body != actual_body:
        raise VerificationError(
            "transparency log entry is inconsistent with other materials"
        )


def _validate_hashedrekord_v002_entry_body(
    bundle: Bundle, hashed_input: Hashed, entry: TransparencyLogEntry
) -> None:
    """
    Validate Entry body for hashedrekord v002.
    """
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

    Key-to-algorithm mapping is handled by the algorithm registry via
    `_get_key_details`.
    """
    return v2.verifier.Verifier(
        x509_certificate=v1.X509Certificate(
            raw_bytes=base64.b64encode(
                certificate.public_bytes(encoding=serialization.Encoding.DER)
            )
        ),
        key_details=_get_key_details(certificate),
    )
