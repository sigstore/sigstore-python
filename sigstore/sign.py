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

from sigstore.sign import SigningContext
from sigstore.oidc import Issuer

issuer = Issuer.production()
identity = issuer.identity_token()

# The artifact to sign
artifact = Path("foo.txt")

with artifact.open("rb") as file:
    signing_ctx = SigningContext.production()
    with signing_ctx.signer(identity, cache=True) as signer:
        result = signer.sign(file)
        print(result)
```
"""

from __future__ import annotations

import base64
import logging
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import IO, Iterator, Optional

import cryptography.x509 as x509
import sigstore_rekor_types
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
    Checkpoint,
    InclusionPromise,
    InclusionProof,
    KindVersion,
    TransparencyLogEntry,
)

from sigstore._internal.fulcio import (
    ExpiredCertificate,
    FulcioCertificateSigningResponse,
    FulcioClient,
)
from sigstore._internal.rekor.client import RekorClient
from sigstore._internal.sct import verify_sct
from sigstore._internal.tuf import TrustUpdater
from sigstore._utils import B64Str, HexStr, PEMCert, sha256_streaming
from sigstore.oidc import ExpiredIdentity, IdentityToken
from sigstore.transparency import LogEntry

logger = logging.getLogger(__name__)


class Signer:
    """
    The primary API for signing operations.
    """

    def __init__(
        self,
        identity_token: IdentityToken,
        signing_ctx: SigningContext,
        cache: bool = True,
    ) -> None:
        """
        Create a new `Signer`.

        `identity_token` is the identity token used to request a signing certificate
        from Fulcio.

        `signing_ctx` is a `SigningContext` that keeps information about the signing
        configuration.

        `cache` determines whether the signing certificate and ephemeral private key
        should be reused (until the certificate expires) to sign different artifacts.
        Default is `True`.
        """
        self._identity_token = identity_token
        self._signing_ctx: SigningContext = signing_ctx
        self.__cached_private_key: Optional[ec.EllipticCurvePrivateKey] = None
        self.__cached_signing_certificate: Optional[
            FulcioCertificateSigningResponse
        ] = None
        if cache:
            logger.debug("Generating ephemeral keys...")
            self.__cached_private_key = ec.generate_private_key(ec.SECP256R1())
            logger.debug("Requesting ephemeral certificate...")
            self.__cached_signing_certificate = self._signing_cert(self._private_key)

    @property
    def _private_key(self) -> ec.EllipticCurvePrivateKey:
        """Get or generate a signing key."""
        if self.__cached_private_key is None:
            logger.debug("no cached key; generating ephemeral key")
            return ec.generate_private_key(ec.SECP256R1())
        return self.__cached_private_key

    def _signing_cert(
        self,
        private_key: ec.EllipticCurvePrivateKey,
    ) -> FulcioCertificateSigningResponse:
        """Get or request a signing certificate from Fulcio."""
        # If it exists, verify if the current certificate is expired
        if self.__cached_signing_certificate:
            not_valid_after = self.__cached_signing_certificate.cert.not_valid_after
            not_valid_after_tzutc = not_valid_after.replace(tzinfo=timezone.utc)
            if datetime.now(timezone.utc) > not_valid_after_tzutc:
                raise ExpiredCertificate
            return self.__cached_signing_certificate

        else:
            logger.debug("Retrieving signed certificate...")

            # Build an X.509 Certificiate Signing Request
            builder = (
                x509.CertificateSigningRequestBuilder()
                .subject_name(
                    x509.Name(
                        [
                            x509.NameAttribute(
                                NameOID.EMAIL_ADDRESS, self._identity_token._identity
                            ),
                        ]
                    )
                )
                .add_extension(
                    x509.BasicConstraints(ca=False, path_length=None),
                    critical=True,
                )
            )
            certificate_request = builder.sign(private_key, hashes.SHA256())

            certificate_response = self._signing_ctx._fulcio.signing_cert.post(
                certificate_request, self._identity_token
            )

            return certificate_response

    def sign(
        self,
        input_: IO[bytes],
    ) -> SigningResult:
        """Public API for signing blobs"""
        input_digest = sha256_streaming(input_)
        private_key = self._private_key

        if not self._identity_token.in_validity_period():
            raise ExpiredIdentity

        try:
            certificate_response = self._signing_cert(private_key)
        except ExpiredCertificate as e:
            raise e

        # TODO(alex): Retrieve the public key via TUF
        #
        # Verify the SCT
        sct = certificate_response.sct  # noqa
        cert = certificate_response.cert  # noqa
        chain = certificate_response.chain

        verify_sct(sct, cert, chain, self._signing_ctx._rekor._ct_keyring)

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
        proposed_entry = sigstore_rekor_types.Hashedrekord(
            kind="hashedrekord",
            api_version="0.0.1",
            spec=sigstore_rekor_types.HashedrekordV001Schema(
                signature=sigstore_rekor_types.Signature1(
                    content=b64_artifact_signature,
                    public_key=sigstore_rekor_types.PublicKey1(
                        content=b64_cert.decode()
                    ),
                ),
                data=sigstore_rekor_types.Data(
                    hash=sigstore_rekor_types.Hash(
                        algorithm=sigstore_rekor_types.Algorithm.SHA256,
                        value=input_digest.hex(),
                    )
                ),
            ),
        )
        entry = self._signing_ctx._rekor.log.entries.post(proposed_entry)

        logger.debug(f"Transparency log entry created with index: {entry.log_index}")

        return SigningResult(
            input_digest=HexStr(input_digest.hex()),
            cert_pem=PEMCert(
                cert.public_bytes(encoding=serialization.Encoding.PEM).decode()
            ),
            b64_signature=B64Str(b64_artifact_signature),
            log_entry=entry,
        )


class SigningContext:
    """
    Keep a context between signing operations.
    """

    def __init__(
        self,
        *,
        fulcio: FulcioClient,
        rekor: RekorClient,
    ):
        """
        Create a new `SigningContext`.

        `fulcio` is a `FulcioClient` capable of connecting to a Fulcio instance
        and returning signing certificates.

        `rekor` is a `RekorClient` capable of connecting to a Rekor instance
        and creating transparency log entries.
        """
        self._fulcio = fulcio
        self._rekor = rekor

    @classmethod
    def production(cls) -> SigningContext:
        """
        Return a `SigningContext` instance configured against Sigstore's production-level services.
        """
        updater = TrustUpdater.production()
        rekor = RekorClient.production(updater)
        return cls(
            fulcio=FulcioClient.production(),
            rekor=rekor,
        )

    @classmethod
    def staging(cls) -> SigningContext:
        """
        Return a `SignerContext` instance configured against Sigstore's staging-level services.
        """
        updater = TrustUpdater.staging()
        rekor = RekorClient.staging(updater)
        return cls(
            fulcio=FulcioClient.staging(),
            rekor=rekor,
        )

    @contextmanager
    def signer(
        self, identity_token: IdentityToken, *, cache: bool = True
    ) -> Iterator[Signer]:
        """
        A context manager for signing operations.

        `identity_token` is the identity token passed to the `Signer` instance
        and used to request a signing certificate from Fulcio.

        `cache` determines whether the signing certificate and ephemeral private key
        generated by the `Signer` instance should be reused (until the certificate expires)
        to sign different artifacts.
        Default is `True`.
        """
        yield Signer(identity_token, self, cache)


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

    def to_bundle(self) -> Bundle:
        """
        Creates a Sigstore bundle (as defined by Sigstore's protobuf specs)
        from this `SigningResult`.
        """

        # NOTE: We explicitly only include the leaf certificate in the bundle's "chain"
        # here: the specs explicitly forbid the inclusion of the root certificate,
        # and discourage inclusion of any intermediates (since they're in the root of
        # trust already).
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
                checkpoint=Checkpoint(
                    envelope=self.log_entry.inclusion_proof.checkpoint
                ),
            )

        tlog_entry = TransparencyLogEntry(
            log_index=self.log_entry.log_index,
            log_id=LogId(key_id=bytes.fromhex(self.log_entry.log_id)),
            kind_version=KindVersion(kind="hashedrekord", version="0.0.1"),
            integrated_time=self.log_entry.integrated_time,
            inclusion_promise=InclusionPromise(
                signed_entry_timestamp=base64.b64decode(
                    self.log_entry.inclusion_promise
                )
            )
            if self.log_entry.inclusion_promise
            else None,
            inclusion_proof=inclusion_proof,
            canonicalized_body=base64.b64decode(self.log_entry.body),
        )

        material = VerificationMaterial(
            x509_certificate_chain=chain,
            tlog_entries=[tlog_entry],
        )

        bundle = Bundle(
            media_type="application/vnd.dev.sigstore.bundle+json;version=0.2",
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
