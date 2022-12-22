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
Top-level signing APIs for sigstore-python.
"""

from __future__ import annotations

import base64
import logging
from typing import IO

import cryptography.x509 as x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.x509.oid import NameOID
from pydantic import BaseModel

from sigstore._internal.fulcio import FulcioClient
from sigstore._internal.oidc import Identity
from sigstore._internal.rekor.client import RekorClient, RekorEntry
from sigstore._internal.sct import verify_sct
from sigstore._internal.tuf import TrustUpdater
from sigstore._utils import sha256_streaming

logger = logging.getLogger(__name__)


class Signer:
    """
    The primary API for signing operations.
    """

    def __init__(self, *, fulcio: FulcioClient, rekor: RekorClient):
        """
        Create a new `Signer`.

        `fulcio` is a `FulcioClient` capable of connecting to a Fulcio instance
        and returning signing certificates.

        `rekor` is a `RekorClient` capable of connecting to a Rekor instance
        and creating transparency log entries.
        """
        self._fulcio = fulcio
        self._rekor = rekor

    @classmethod
    def production(cls) -> Signer:
        """
        Return a `Signer` instance configured against Sigstore's production-level services.
        """
        updater = TrustUpdater.production()
        rekor = RekorClient.production(updater)
        return cls(fulcio=FulcioClient.production(), rekor=rekor)

    @classmethod
    def staging(cls) -> Signer:
        """
        Return a `Signer` instance configured against Sigstore's staging-level services.
        """
        updater = TrustUpdater.staging()
        rekor = RekorClient.staging(updater)
        return cls(fulcio=FulcioClient.staging(), rekor=rekor)

    def sign(
        self,
        input_: IO[bytes],
        identity_token: str,
    ) -> SigningResult:
        """Public API for signing blobs"""
        input_digest = sha256_streaming(input_)

        logger.debug("Generating ephemeral keys...")
        private_key = ec.generate_private_key(ec.SECP384R1())

        logger.debug("Retrieving signed certificate...")

        oidc_identity = Identity(identity_token)

        # Build an X.509 Certificiate Signing Request
        builder = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(
                x509.Name(
                    [
                        x509.NameAttribute(NameOID.EMAIL_ADDRESS, oidc_identity.proof),
                    ]
                )
            )
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            )
        )
        certificate_request = builder.sign(private_key, hashes.SHA256())

        certificate_response = self._fulcio.signing_cert.post(
            certificate_request, identity_token
        )

        # TODO(alex): Retrieve the public key via TUF
        #
        # Verify the SCT
        sct = certificate_response.sct  # noqa
        cert = certificate_response.cert  # noqa
        chain = certificate_response.chain

        verify_sct(sct, cert, chain, self._rekor._ct_keyring)

        logger.debug("Successfully verified SCT...")

        # Sign artifact
        artifact_signature = private_key.sign(
            input_digest, ec.ECDSA(Prehashed(hashes.SHA256()))
        )
        b64_artifact_signature = base64.b64encode(artifact_signature).decode()

        # Prepare inputs
        b64_cert = base64.b64encode(
            cert.public_bytes(encoding=serialization.Encoding.PEM)
        )

        # Create the transparency log entry
        entry = self._rekor.log.entries.post(
            b64_artifact_signature=b64_artifact_signature,
            sha256_artifact_hash=input_digest.hex(),
            b64_cert=b64_cert.decode(),
        )

        logger.debug(f"Transparency log entry created with index: {entry.log_index}")

        return SigningResult(
            cert_pem=cert.public_bytes(encoding=serialization.Encoding.PEM).decode(),
            b64_signature=b64_artifact_signature,
            log_entry=entry,
        )


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
