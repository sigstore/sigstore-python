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

import base64
import hashlib
import logging
from typing import BinaryIO

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from pydantic import BaseModel

from sigstore._internal.fulcio import (
    FulcioCertificateSigningRequest,
    FulcioClient,
)
from sigstore._internal.oidc import Identity
from sigstore._internal.rekor import RekorClient, RekorEntry
from sigstore._internal.sct import verify_sct

logger = logging.getLogger(__name__)


class SigningResult(BaseModel):
    """
    Represents the artifacts of a signing operation.
    """

    cert_pem: str
    """
    The PEM-encoded public half of the certificate used for signing.
    """

    b64_signature: str
    """
    The base64-encoded signature.
    """

    log_entry: RekorEntry
    """
    A record of the Rekor log entry for the signing operation.
    """


def sign(file: BinaryIO, identity_token: str, ctfe_pem: bytes) -> SigningResult:
    """Public API for signing blobs"""

    logger.debug(f"Using payload from: {file.name}")
    artifact_contents = file.read()
    sha256_artifact_hash = hashlib.sha256(artifact_contents).hexdigest()

    logger.debug("Generating ephemeral keys...")
    private_key = ec.generate_private_key(ec.SECP384R1())
    public_key = private_key.public_key()

    logger.debug("Retrieving signed certificate...")
    fulcio = FulcioClient()

    oidc_identity = Identity(identity_token)

    # Build an X.509 Certificiate Signing Request - not currently supported
    # builder = (
    #     x509.CertificateSigningRequestBuilder()
    #     .subject_name(
    #         x509.Name(
    #             [
    #                 x509.NameAttribute(NameOID.EMAIL_ADDRESS, email_address),
    #             ]
    #         )
    #     )
    #     .add_extension(
    #         x509.BasicConstraints(ca=False, path_length=None),
    #         critical=True,
    #     )
    # )
    # certificate_request = builder.sign(private_key, hashes.SHA256())

    signed_proof = private_key.sign(
        oidc_identity.proof.encode(), ec.ECDSA(hashes.SHA256())
    )
    certificate_request = FulcioCertificateSigningRequest(public_key, signed_proof)

    certificate_response = fulcio.signing_cert.post(certificate_request, identity_token)

    # TODO(alex): Retrieve the public key via TUF
    #
    # Verify the SCT
    sct = certificate_response.sct  # noqa
    cert = certificate_response.cert  # noqa
    ctfe_key = load_pem_public_key(ctfe_pem)

    verify_sct(sct, cert, ctfe_key)

    logger.debug("Successfully verified SCT...")

    # Sign artifact
    artifact_signature = private_key.sign(artifact_contents, ec.ECDSA(hashes.SHA256()))
    b64_artifact_signature = base64.b64encode(artifact_signature).decode()

    # Prepare inputs
    b64_cert = base64.b64encode(cert.public_bytes(encoding=serialization.Encoding.PEM))

    # Create the transparency log entry
    rekor = RekorClient()
    entry = rekor.log.entries.post(
        b64_artifact_signature=b64_artifact_signature,
        sha256_artifact_hash=sha256_artifact_hash,
        b64_cert=b64_cert.decode(),
    )

    logger.debug(f"Transparency log entry created with index: {entry.log_index}")

    return SigningResult(
        cert_pem=cert.public_bytes(encoding=serialization.Encoding.PEM).decode(),
        b64_signature=b64_artifact_signature,
        log_entry=entry,
    )
