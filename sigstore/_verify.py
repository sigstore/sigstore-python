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
    KeyUsage,
    RFC822Name,
    SubjectAlternativeName,
    load_pem_x509_certificate,
)
from cryptography.x509.oid import ExtendedKeyUsageOID
from OpenSSL.crypto import X509, X509Store, X509StoreContext
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


class VerificationResult(BaseModel):
    pass


def verify(
    file: BinaryIO,
    certificate: bytes,
    signature: bytes,
    cert_email: Optional[str] = None,
) -> Optional[VerificationResult]:
    """Public API for verifying files.

    `file` is the file to verify.

    `certificate` is the PEM-encoded signing certificate.

    `signature` is a base64-encoded signature for `file`.

    `cert_email` is the expected Subject Alternative Name (SAN) within `certificate`.

    Returns a `VerificationResult` if verification succeeds, or `None` if it fails.
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

    sign_date = cert.not_valid_before
    openssl_cert = X509.from_cryptography(cert)
    openssl_root = X509.from_cryptography(root)

    store = X509Store()
    store.add_cert(openssl_root)
    store.set_time(sign_date)
    store_ctx = X509StoreContext(store, openssl_cert)
    store_ctx.verify_certificate()

    # 2) Check that the signing certificate contains the proof claim as the subject
    # Check usage is "digital signature"
    usage_ext = cert.extensions.get_extension_for_class(KeyUsage)
    if not usage_ext.value.digital_signature:
        # Error
        logger.error("Key usage is not of type `digital signature`")
        return None

    # Check that extended usage contains "code signing"
    extended_usage_ext = cert.extensions.get_extension_for_class(ExtendedKeyUsage)
    if ExtendedKeyUsageOID.CODE_SIGNING not in extended_usage_ext.value:
        # Error
        logger.error("Extended usage does not contain `code signing`")
        return None

    if cert_email is not None:
        # Check that SubjectAlternativeName contains signer identity
        san_ext = cert.extensions.get_extension_for_class(SubjectAlternativeName)
        if cert_email not in san_ext.value.get_values_for_type(RFC822Name):
            # Error
            logger.error(f"Subject name does not contain identity: {cert_email}")
            return None

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
    rekor = RekorClient()
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
            logger.error(
                f"Failed to validate Rekor entry's inclusion proof: {inval_inclusion_proof}"
            )
            continue

        # 5) Verify the Signed Entry Timestamp (SET) supplied by Rekor for this artifact
        try:
            verify_set(entry)
        except InvalidSetError as inval_set:
            logger.error(f"Failed to validate Rekor entry's SET: {inval_set}")
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
        logger.error("No valid Rekor entries were found")
        return None

    logger.debug("Successfully verified Rekor entry...")
    return VerificationResult()
