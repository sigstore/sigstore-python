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
API for signing artifacts.

Example:
```python
from pathlib import Path

from sigstore.sign import Signer
from sigstore.oidc import Issuer

issuer = Issuer.production()
token = issuer.identity_token()

# The artifact to sign
artifact = Path("foo.txt")

with artifact.open("rb") as a:
    signer = Signer.production()
    result = signer.sign(input_=a, identity_token=token)
    print(result)
```
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
from sigstore_protobuf_specs.dev.sigstore.bundle.v1 import (
    Bundle,
    VerificationMaterial,
)
from sigstore_protobuf_specs.dev.sigstore.common.v1 import (
    HashAlgorithm,
    HashOutput,
    LogId,
    MessageSignature,
    X509Certificate,
    X509CertificateChain,
)
from sigstore_protobuf_specs.dev.sigstore.rekor.v1 import (
    InclusionPromise,
    InclusionProof,
    KindVersion,
    TransparencyLogEntry,
)

from sigstore._internal.fulcio import FulcioClient
from sigstore._internal.oidc import Identity
from sigstore._internal.rekor.client import RekorClient
from sigstore._internal.sct import verify_sct
from sigstore._internal.tuf import TrustUpdater
from sigstore._utils import B64Str, HexStr, PEMCert, sha256_streaming
from sigstore.transparency import LogEntry

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
        logger.debug(f"cert-identity: {oidc_identity.proof}")
        logger.debug(f"cert-oidc-issuer: {oidc_identity.issuer}")

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
        b64_artifact_signature = B64Str(base64.b64encode(artifact_signature).decode())

        # Prepare inputs
        b64_cert = base64.b64encode(
            cert.public_bytes(encoding=serialization.Encoding.PEM)
        )

        # Create the transparency log entry
        entry = self._rekor.log.entries.post(
            b64_artifact_signature=B64Str(b64_artifact_signature),
            sha256_artifact_hash=input_digest.hex(),
            b64_cert=B64Str(b64_cert.decode()),
        )

        logger.debug(f"Transparency log entry created with index: {entry.log_index}")

        return SigningResult(
            input_digest=HexStr(input_digest.hex()),
            cert_pem=PEMCert(
                cert.public_bytes(encoding=serialization.Encoding.PEM).decode()
            ),
            b64_signature=B64Str(b64_artifact_signature),
            log_entry=entry,
        )


class SigningResult(BaseModel):
    """
    Represents the artifacts of a signing operation.
    """

    input_digest: HexStr
    """
    The hex-encoded SHA256 digest of the input that was signed for.
    """

    cert_pem: PEMCert
    """
    The PEM-encoded public half of the certificate used for signing.
    """

    b64_signature: B64Str
    """
    The base64-encoded signature.
    """

    log_entry: LogEntry
    """
    A record of the Rekor log entry for the signing operation.
    """

    def _to_bundle(self) -> Bundle:
        """
        Creates a Sigstore bundle (as defined by Sigstore's protobuf specs)
        from this `SigningResult`.
        """

        # TODO: Include the current Fulcio intermediate and root in the
        # chain as well.
        cert = x509.load_pem_x509_certificate(self.cert_pem.encode())
        cert_der = cert.public_bytes(encoding=serialization.Encoding.DER)
        chain = X509CertificateChain(certificates=[X509Certificate(raw_bytes=cert_der)])

        inclusion_proof: InclusionProof | None = None
        if self.log_entry.inclusion_proof is not None:
            inclusion_proof = InclusionProof(
                log_index=self.log_entry.inclusion_proof.log_index,
                root_hash=bytes.fromhex(self.log_entry.inclusion_proof.root_hash),
                tree_size=self.log_entry.inclusion_proof.tree_size,
                hashes=[
                    bytes.fromhex(h) for h in self.log_entry.inclusion_proof.hashes
                ],
            )

        tlog_entry = TransparencyLogEntry(
            log_index=self.log_entry.log_index,
            log_id=LogId(key_id=bytes.fromhex(self.log_entry.log_id)),
            kind_version=KindVersion(kind="hashedrekord", version="0.0.1"),
            integrated_time=self.log_entry.integrated_time,
            inclusion_promise=InclusionPromise(
                signed_entry_timestamp=base64.b64decode(
                    self.log_entry.signed_entry_timestamp
                )
            ),
            inclusion_proof=inclusion_proof,
            canonicalized_body=base64.b64decode(self.log_entry.body),
        )

        material = VerificationMaterial(
            x509_certificate_chain=chain,
            tlog_entries=[tlog_entry],
        )

        bundle = Bundle(
            media_type="application/vnd.dev.sigstore.bundle+json;version=0.1",
            verification_material=material,
            message_signature=MessageSignature(
                message_digest=HashOutput(
                    algorithm=HashAlgorithm.SHA2_256,
                    digest=bytes.fromhex(self.input_digest),
                ),
                signature=base64.b64decode(self.b64_signature),
            ),
        )

        return bundle
