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

import base64
import datetime
import hashlib
import logging
from importlib import resources
from typing import BinaryIO, Optional, cast

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509 import (
    ExtendedKeyUsage,
    ExtensionNotFound,
    KeyUsage,
    ObjectIdentifier,
    RFC822Name,
    SubjectAlternativeName,
    load_pem_x509_certificate,
)
from cryptography.x509.oid import ExtendedKeyUsageOID
from OpenSSL.crypto import (
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
from sigstore._internal.rekor import (
    RekorClient,
    RekorEntry,
    RekorInclusionProof,
)
from sigstore._internal.set import InvalidSetError, verify_set

logger = logging.getLogger(__name__)


FULCIO_ROOT_CERT = resources.read_binary("sigstore._store", "fulcio.crt.pem")
FULCIO_INTERMEDIATE_CERT = resources.read_binary(
    "sigstore._store", "fulcio_intermediate.crt.pem"
)

# From: https://github.com/sigstore/fulcio/blob/main/docs/oid-info.md
_OIDC_ISSUER_OID = ObjectIdentifier("1.3.6.1.4.1.57264.1.1")
_OIDC_GITHUB_WORKFLOW_TRIGGER_OID = ObjectIdentifier("1.3.6.1.4.1.57264.1.2")
_OIDC_GITHUB_WORKFLOW_SHA_OID = ObjectIdentifier("1.3.6.1.4.1.57264.1.3")
_OIDC_GITHUB_WORKFLOW_NAME_OID = ObjectIdentifier("1.3.6.1.4.1.57264.1.4")
_OIDC_GITHUB_WORKFLOW_REPOSITORY_OID = ObjectIdentifier("1.3.6.1.4.1.57264.1.5")
_OIDC_GITHUB_WORKFLOW_REF_OID = ObjectIdentifier("1.3.6.1.4.1.57264.1.6")


class VerificationResult(BaseModel):
    success: bool

    def __bool__(self) -> bool:
        return self.success


class VerificationSuccess(VerificationResult):
    success: bool = True


class VerificationFailure(VerificationResult):
    success: bool = False
    reason: str


class CertificateVerificationFailure(VerificationFailure):
    exception: Exception

    class Config:
        # Needed for the `exception` field above, since exceptions are
        # not trivially serializable.
        arbitrary_types_allowed = True


def verify(
    rekor_url: str,
    file: BinaryIO,
    certificate: bytes,
    signature: bytes,
    expected_cert_email: Optional[str] = None,
    expected_cert_oidc_issuer: Optional[str] = None,
) -> VerificationResult:
    """Public API for verifying files.

    `file` is the file to verify.

    `certificate` is the PEM-encoded signing certificate.

    `signature` is a base64-encoded signature for `file`.

    `expected_cert_email` is the expected Subject Alternative Name (SAN) within `certificate`.

    `expected_cert_oidc_issuer` is the expected OIDC Issuer Extension within `certificate`.

    Returns a `VerificationResult` which will be truthy or falsey depending on
    success.
    """

    # Read the contents of the package to be verified
    logger.debug(f"Using payload from: {file.name}")
    artifact_contents = file.read()
    sha256_artifact_hash = hashlib.sha256(artifact_contents).hexdigest()

    cert = load_pem_x509_certificate(certificate)
    artifact_signature = base64.b64decode(signature)

    # In order to verify an artifact, we need to achieve the following:
    #
    # 1) Verify that the signing certificate is signed by the root certificate and that the signing
    #    certificate was valid at the time of signing.
    # 2) Verify that the signing certiticate belongs to the signer
    # 3) Verify that the signature was signed by the public key in the signing certificate
    #
    # And optionally, if we're performing verification online:
    #
    # 4) Verify the inclusion proof supplied by Rekor for this artifact
    # 5) Verify the Signed Entry Timestamp (SET) supplied by Rekor for this artifact
    # 6) Verify that the signing certificate was valid at the time of signing by comparing the
    #    expiry against the integrated timestamp

    # 1) Verify that the signing certificate is signed by the root certificate and that the signing
    #    certificate was valid at the time of signing.
    root = load_pem_x509_certificate(FULCIO_ROOT_CERT)
    intermediate = load_pem_x509_certificate(FULCIO_INTERMEDIATE_CERT)

    sign_date = cert.not_valid_before
    openssl_cert = X509.from_cryptography(cert)
    openssl_root = X509.from_cryptography(root)
    openssl_intermediate = X509.from_cryptography(intermediate)

    store = X509Store()
    store.add_cert(openssl_root)
    store.add_cert(openssl_intermediate)
    store.set_time(sign_date)
    store_ctx = X509StoreContext(store, openssl_cert)
    try:
        store_ctx.verify_certificate()
    except X509StoreContextError as store_ctx_error:
        return CertificateVerificationFailure(
            reason="Failed to verify signing certificate",
            exception=store_ctx_error,
        )

    # 2) Check that the signing certificate contains the proof claim as the subject
    # Check usage is "digital signature"
    usage_ext = cert.extensions.get_extension_for_class(KeyUsage)
    if not usage_ext.value.digital_signature:
        return VerificationFailure(
            reason="Key usage is not of type `digital signature`"
        )

    # Check that extended usage contains "code signing"
    extended_usage_ext = cert.extensions.get_extension_for_class(ExtendedKeyUsage)
    if ExtendedKeyUsageOID.CODE_SIGNING not in extended_usage_ext.value:
        return VerificationFailure(
            reason="Extended usage does not contain `code signing`"
        )

    if expected_cert_email is not None:
        # Check that SubjectAlternativeName contains signer identity
        san_ext = cert.extensions.get_extension_for_class(SubjectAlternativeName)
        if expected_cert_email not in san_ext.value.get_values_for_type(RFC822Name):
            return VerificationFailure(
                reason=f"Subject name does not contain identity: {expected_cert_email}"
            )

    if expected_cert_oidc_issuer is not None:
        # Check that the OIDC issuer extension is present, and contains the expected
        # issuer string (which is probably a URL).
        try:
            oidc_issuer = cert.extensions.get_extension_for_oid(_OIDC_ISSUER_OID).value
        except ExtensionNotFound:
            return VerificationFailure(
                reason="Certificate does not contain OIDC issuer extension"
            )

        if oidc_issuer.value != expected_cert_oidc_issuer.encode():
            return VerificationFailure(
                reason=f"Certificate's OIDC issuer does not match (got {oidc_issuer.value})"
            )

    logger.debug("Successfully verified signing certificate validity...")

    # 3) Verify that the signature was signed by the public key in the signing certificate
    signing_key = cert.public_key()
    signing_key = cast(ec.EllipticCurvePublicKey, signing_key)
    signing_key.verify(artifact_signature, artifact_contents, ec.ECDSA(hashes.SHA256()))

    logger.debug("Successfully verified signature...")

    # Get a base64 encoding of the signing key. We're going to use this in our Rekor query.
    pub_b64 = base64.b64encode(
        signing_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )

    # Retrieve the relevant Rekor entry to verify the inclusion proof and SET
    rekor = RekorClient(rekor_url)
    uuids = rekor.index.retrieve.post(sha256_artifact_hash, pub_b64.decode())

    valid_sig_exists = False
    for uuid in uuids:
        entry: RekorEntry = rekor.log.entries.get(uuid)

        # 4) Verify the inclusion proof supplied by Rekor for this artifact
        inclusion_proof = RekorInclusionProof.parse_obj(
            entry.verification.get("inclusionProof")
        )
        try:
            verify_merkle_inclusion(inclusion_proof, entry)
        except InvalidInclusionProofError as inval_inclusion_proof:
            logger.warning(
                f"Failed to validate Rekor entry's inclusion proof: {inval_inclusion_proof}"
            )
            continue

        # 5) Verify the Signed Entry Timestamp (SET) supplied by Rekor for this artifact
        try:
            verify_set(entry)
        except InvalidSetError as inval_set:
            logger.warning(f"Failed to validate Rekor entry's SET: {inval_set}")
            continue

        # 6) Verify that the signing certificate was valid at the time of signing
        integrated_time = datetime.datetime.utcfromtimestamp(entry.integrated_time)
        if (
            integrated_time < cert.not_valid_before
            or integrated_time >= cert.not_valid_after
        ):
            # No need to log anything here.
            #
            # If an artifact has been signed multiple times, this will happen so it's not really an
            # error case.
            continue

        # TODO: Does it make sense to collect all valid Rekor entries?
        valid_sig_exists = True
        break

    if not valid_sig_exists:
        return VerificationFailure(reason="No valid Rekor entries were found")

    logger.debug("Successfully verified Rekor entry...")
    return VerificationSuccess()
