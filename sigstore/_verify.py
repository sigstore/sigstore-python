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
API for verifying artifact signatures.
"""

from __future__ import annotations

import base64
import datetime
import hashlib
import json
import logging
from dataclasses import dataclass
from importlib import resources
from typing import List, Optional, cast

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509 import (
    Certificate,
    ExtendedKeyUsage,
    ExtensionNotFound,
    KeyUsage,
    ObjectIdentifier,
    load_pem_x509_certificate,
)
from cryptography.x509.oid import ExtendedKeyUsageOID
from OpenSSL.crypto import (  # type: ignore[import]
    X509,
    X509Store,
    X509StoreContext,
    X509StoreContextError,
)
from pydantic import BaseModel

from sigstore._internal.merkle import (
    InvalidInclusionProofError,
    verify_merkle_inclusion,
)
from sigstore._internal.rekor import RekorClient, RekorEntry
from sigstore._internal.set import InvalidSetError, verify_set
from sigstore._utils import cert_contains_identity

logger = logging.getLogger(__name__)


DEFAULT_FULCIO_ROOT_CERT = resources.read_binary("sigstore._store", "fulcio.crt.pem")
DEFAULT_FULCIO_INTERMEDIATE_CERT = resources.read_binary(
    "sigstore._store", "fulcio_intermediate.crt.pem"
)

STAGING_FULCIO_ROOT_CERT = resources.read_binary(
    "sigstore._store", "fulcio.crt.staging.pem"
)
STAGING_FULCIO_INTERMEDIATE_CERT = resources.read_binary(
    "sigstore._store", "fulcio_intermediate.crt.staging.pem"
)

# From: https://github.com/sigstore/fulcio/blob/main/docs/oid-info.md
_OIDC_ISSUER_OID = ObjectIdentifier("1.3.6.1.4.1.57264.1.1")
_OIDC_GITHUB_WORKFLOW_TRIGGER_OID = ObjectIdentifier("1.3.6.1.4.1.57264.1.2")
_OIDC_GITHUB_WORKFLOW_SHA_OID = ObjectIdentifier("1.3.6.1.4.1.57264.1.3")
_OIDC_GITHUB_WORKFLOW_NAME_OID = ObjectIdentifier("1.3.6.1.4.1.57264.1.4")
_OIDC_GITHUB_WORKFLOW_REPOSITORY_OID = ObjectIdentifier("1.3.6.1.4.1.57264.1.5")
_OIDC_GITHUB_WORKFLOW_REF_OID = ObjectIdentifier("1.3.6.1.4.1.57264.1.6")


@dataclass(init=False)
class VerificationMaterials:
    """
    Represents the materials needed to perform a Sigstore verification.
    """

    input_: bytes
    """
    The input that was signed for.
    """

    artifact_hash: str
    """
    The hex-encoded SHA256 hash of `input_`.
    """

    certificate: Certificate
    """
    The certificate that attests to and contains the public signing key.
    """

    signature: bytes
    """
    The raw signature.
    """

    offline_rekor_entry: Optional[RekorEntry]
    """
    An optional offline Rekor entry.

    If supplied an offline Rekor entry is supplied, verification will be done
    against this entry rather than the against the online transparency log.

    Offline Rekor entries do not carry their Merkle inclusion
    proofs, and as such are verified only against their Signed Entry Timestamps.
    This is a slightly weaker verification verification mode, as it does not
    demonstrate inclusion in the log.
    """

    def __init__(
        self,
        *,
        input_: bytes,
        cert_pem: str,
        signature: bytes,
        offline_rekor_entry: Optional[RekorEntry],
    ):
        self.input_ = input_
        self.artifact_hash = hashlib.sha256(self.input_).hexdigest()
        self.certificate = load_pem_x509_certificate(cert_pem.encode())
        self.signature = signature
        self.offline_rekor_entry = offline_rekor_entry


class VerificationPolicy:
    pass


class Verifier:
    def __init__(self, *, rekor: RekorClient, fulcio_certificate_chain: List[bytes]):
        """
        Create a new `Verifier`.

        `rekor` is a `RekorClient` capable of connecting to a Rekor instance
        containing logs for the file(s) being verified.

        `fulcio_certificate_chain` is a list of PEM-encoded X.509 certificates,
        establishing the trust chain for the signing certificate and signature.
        """
        self._rekor = rekor

        self._fulcio_certificate_chain: List[X509] = []
        for parent_cert_pem in fulcio_certificate_chain:
            parent_cert = load_pem_x509_certificate(parent_cert_pem)
            parent_cert_ossl = X509.from_cryptography(parent_cert)
            self._fulcio_certificate_chain.append(parent_cert_ossl)

    @classmethod
    def production(cls) -> Verifier:
        return cls(
            rekor=RekorClient.production(),
            fulcio_certificate_chain=[
                DEFAULT_FULCIO_ROOT_CERT,
                DEFAULT_FULCIO_INTERMEDIATE_CERT,
            ],
        )

    @classmethod
    def staging(cls) -> Verifier:
        return cls(
            rekor=RekorClient.staging(),
            fulcio_certificate_chain=[
                STAGING_FULCIO_ROOT_CERT,
                STAGING_FULCIO_INTERMEDIATE_CERT,
            ],
        )

    def verify(
        self,
        materials: VerificationMaterials,
        expected_cert_identity: Optional[str] = None,
        expected_cert_oidc_issuer: Optional[str] = None,
    ) -> VerificationResult:
        """Public API for verifying.

        `materials` are the `VerificationMaterials` to verify.

        `expected_cert_identity` is the expected Subject Alternative Name (SAN)
        within `certificate`.

        `expected_cert_oidc_issuer` is the expected OIDC Issuer Extension within `certificate`.

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
        # 4) Verify the inclusion proof supplied by Rekor for this artifact,
        #    if we're doing online verification.
        # 5) Verify the Signed Entry Timestamp (SET) supplied by Rekor for this
        #    artifact.
        # 6) Verify that the signing certificate was valid at the time of
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
                reason="Failed to verify signing certificate",
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

        if expected_cert_identity is not None and not cert_contains_identity(
            materials.certificate, expected_cert_identity
        ):
            return VerificationFailure(
                reason=f"Subject name does not contain identity: {expected_cert_identity}"
            )

        if expected_cert_oidc_issuer is not None:
            # Check that the OIDC issuer extension is present, and contains the expected
            # issuer string (which is probably a URL).
            try:
                oidc_issuer = materials.certificate.extensions.get_extension_for_oid(
                    _OIDC_ISSUER_OID
                ).value
            except ExtensionNotFound:
                return VerificationFailure(
                    reason="Certificate does not contain OIDC issuer extension"
                )

            # NOTE(ww): mypy is confused by the `Extension[ExtensionType]` returned
            # by `get_extension_for_oid` above.
            issuer_value = oidc_issuer.value  # type: ignore[attr-defined]
            if issuer_value != expected_cert_oidc_issuer.encode():
                return VerificationFailure(
                    reason=f"Certificate's OIDC issuer does not match (got {issuer_value})"
                )

        logger.debug("Successfully verified signing certificate validity...")

        # 3) Verify that the signature was signed by the public key in the signing certificate
        try:
            signing_key = materials.certificate.public_key()
            signing_key = cast(ec.EllipticCurvePublicKey, signing_key)
            signing_key.verify(
                materials.signature, materials.input_, ec.ECDSA(hashes.SHA256())
            )
        except InvalidSignature:
            return VerificationFailure(reason="Signature is invalid for input")

        logger.debug("Successfully verified signature...")

        entry: Optional[RekorEntry]
        if materials.offline_rekor_entry is not None:
            # NOTE: CVE-2022-36056 in cosign happened because the offline Rekor
            # entry was not matched against the other signing materials: an
            # adversary could present a *valid but unrelated* Rekor entry
            # and cosign would perform verification "as if" the entry was a
            # legitimate entry for the certificate and signature.
            # The steps below avoid this by decomposing the Rekor entry's
            # body and confirming that it contains the same signature,
            # certificate, and artifact hash as the rest of the verification
            # process.

            # TODO(ww): This should all go in a separate API, probably under the
            # RekorEntry class.
            logger.debug(
                "offline Rekor entry: ensuring contents match signing materials"
            )

            try:
                entry_body = json.loads(
                    base64.b64decode(materials.offline_rekor_entry.body)
                )
            except Exception:
                return VerificationFailure(
                    reason="couldn't parse offline Rekor entry's body"
                )

            # The Rekor entry's body should be a hashedrekord object.
            # TODO: This should use a real data model, ideally generated from
            # Rekor's official JSON schema.
            kind, version = entry_body.get("kind"), entry_body.get("apiVersion")
            if kind != "hashedrekord" or version != "0.0.1":
                return VerificationFailure(
                    reason=(
                        f"Rekor entry is of unsupported kind ('{kind}') or API "
                        f"version ('{version}')"
                    )
                )

            spec = entry_body["spec"]
            expected_sig, expected_cert, expected_hash = (
                spec["signature"]["content"],
                load_pem_x509_certificate(
                    base64.b64decode(spec["signature"]["publicKey"]["content"])
                ),
                spec["data"]["hash"]["value"],
            )

            if base64.b64decode(expected_sig) != materials.signature:
                return VerificationFailure(
                    reason=(
                        f"Rekor entry's signature ('{expected_sig}') does not "
                        f"match supplied signature ('{materials.signature}')"
                    )
                )

            if expected_cert != materials.certificate:
                return VerificationFailure(
                    reason=(
                        f"Rekor entry's certificate ('{expected_cert}') does not "
                        f"match supplied certificate ('{materials.certificate}')"
                    )
                )

            if expected_hash != materials.artifact_hash:
                return VerificationFailure(
                    reason=(
                        f"Rekor entry's hash ('{expected_hash}') does not "
                        f"match supplied hash ('{materials.artifact_hash}')"
                    )
                )

            logger.debug("offline Rekor entry matches signing artifacts!")
            entry = materials.offline_rekor_entry
        else:
            # Retrieve the relevant Rekor entry to verify the inclusion proof and SET.
            entry = self._rekor.log.entries.retrieve.post(
                materials.signature,
                materials.artifact_hash,
                materials.certificate,
            )
            if entry is None:
                return RekorEntryMissing(
                    signature=materials.signature,
                    sha256_artifact_hash=materials.artifact_hash,
                )

        # 4) Verify the inclusion proof supplied by Rekor for this artifact.
        #
        # We skip the inclusion proof for offline Rekor bundles.
        if materials.offline_rekor_entry is None:
            try:
                verify_merkle_inclusion(entry)
            except InvalidInclusionProofError as inval_inclusion_proof:
                return VerificationFailure(
                    reason=f"invalid Rekor inclusion proof: {inval_inclusion_proof}"
                )
        else:
            logger.debug("offline Rekor entry: skipping Merkle inclusion proof")

        # 5) Verify the Signed Entry Timestamp (SET) supplied by Rekor for this artifact
        try:
            verify_set(self._rekor, entry)
        except InvalidSetError as inval_set:
            return VerificationFailure(reason=f"invalid Rekor entry SET: {inval_set}")

        # 6) Verify that the signing certificate was valid at the time of signing
        integrated_time = datetime.datetime.utcfromtimestamp(entry.integrated_time)
        if (
            integrated_time < materials.certificate.not_valid_before
            or integrated_time >= materials.certificate.not_valid_after
        ):
            return VerificationFailure(
                reason="invalid signing cert: expired at time of Rekor entry"
            )

        logger.debug(f"Successfully verified Rekor entry at index {entry.log_index}")
        return VerificationSuccess()


class VerificationResult(BaseModel):
    success: bool

    def __bool__(self) -> bool:
        return self.success


class VerificationSuccess(VerificationResult):
    success: bool = True


class VerificationFailure(VerificationResult):
    success: bool = False
    reason: str


class RekorEntryMissing(VerificationFailure):
    reason: str = "Rekor has no entry for the given verification materials"
    signature: str
    sha256_artifact_hash: str


class CertificateVerificationFailure(VerificationFailure):
    exception: Exception

    class Config:
        # Needed for the `exception` field above, since exceptions are
        # not trivially serializable.
        arbitrary_types_allowed = True
