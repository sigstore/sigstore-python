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
artifact = Path("foo.txt").read_bytes()

signing_ctx = SigningContext.production()
with signing_ctx.signer(identity, cache=True) as signer:
    result = signer.sign(artifact)
    print(result)
```
"""

from __future__ import annotations

import base64
import logging
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Iterator, Optional

import cryptography.x509 as x509
import rekor_types
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from sigstore_protobuf_specs.dev.sigstore.common.v1 import (
    HashOutput,
    MessageSignature,
)

from sigstore import dsse
from sigstore import hashes as sigstore_hashes
from sigstore._internal.fulcio import (
    ExpiredCertificate,
    FulcioCertificateSigningResponse,
    FulcioClient,
)
from sigstore._internal.rekor.client import RekorClient
from sigstore._internal.sct import verify_sct
from sigstore._internal.trustroot import KeyringPurpose, TrustedRoot
from sigstore._utils import sha256_digest
from sigstore.oidc import ExpiredIdentity, IdentityToken
from sigstore.verify.models import Bundle

_logger = logging.getLogger(__name__)


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
            _logger.debug("Generating ephemeral keys...")
            self.__cached_private_key = ec.generate_private_key(ec.SECP256R1())
            _logger.debug("Requesting ephemeral certificate...")
            self.__cached_signing_certificate = self._signing_cert(self._private_key)

    @property
    def _private_key(self) -> ec.EllipticCurvePrivateKey:
        """Get or generate a signing key."""
        if self.__cached_private_key is None:
            _logger.debug("no cached key; generating ephemeral key")
            return ec.generate_private_key(ec.SECP256R1())
        return self.__cached_private_key

    def _signing_cert(
        self,
        private_key: ec.EllipticCurvePrivateKey,
    ) -> FulcioCertificateSigningResponse:
        """Get or request a signing certificate from Fulcio."""
        # If it exists, verify if the current certificate is expired
        if self.__cached_signing_certificate:
            not_valid_after = self.__cached_signing_certificate.cert.not_valid_after_utc
            if datetime.now(timezone.utc) > not_valid_after:
                raise ExpiredCertificate
            return self.__cached_signing_certificate

        else:
            _logger.debug("Retrieving signed certificate...")

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
        input_: bytes | dsse.Statement | sigstore_hashes.Hashed,
    ) -> Bundle:
        """
        Sign an input, and return a `Bundle` corresponding to the signed result.

        The input can be one of three forms:

        1. A `bytes` buffer;
        2. A `Hashed` object, containing a pre-hashed input (e.g., for inputs
           that are too large to buffer into memory);
        3. An in-toto `Statement` object.

        In cases (1) and (2), the signing operation will produce a `hashedrekord`
        entry within the bundle. In case (3), the signing operation will produce
        a DSSE envelope and corresponding `dsse` entry within the bundle.
        """
        private_key = self._private_key

        if not self._identity_token.in_validity_period():
            raise ExpiredIdentity

        try:
            certificate_response = self._signing_cert(private_key)
        except ExpiredCertificate as e:
            raise e

        # Verify the SCT
        sct = certificate_response.sct
        cert = certificate_response.cert
        chain = certificate_response.chain

        verify_sct(sct, cert, chain, self._signing_ctx._trusted_root.ct_keyring())

        _logger.debug("Successfully verified SCT...")

        # Prepare inputs
        b64_cert = base64.b64encode(
            cert.public_bytes(encoding=serialization.Encoding.PEM)
        )

        # Sign artifact
        content: MessageSignature | dsse.Envelope
        proposed_entry: rekor_types.Hashedrekord | rekor_types.Dsse
        if isinstance(input_, dsse.Statement):
            content = dsse._sign(private_key, input_)

            # Create the proposed DSSE entry
            proposed_entry = rekor_types.Dsse(
                spec=rekor_types.dsse.DsseSchema(
                    proposed_content=rekor_types.dsse.ProposedContent(
                        envelope=content.to_json(),
                        verifiers=[b64_cert.decode()],
                    ),
                ),
            )
        else:
            hashed_input = sha256_digest(input_)

            artifact_signature = private_key.sign(
                hashed_input.digest, ec.ECDSA(hashed_input._as_prehashed())
            )

            content = MessageSignature(
                message_digest=HashOutput(
                    algorithm=hashed_input.algorithm,
                    digest=hashed_input.digest,
                ),
                signature=artifact_signature,
            )

            # Create the proposed hashedrekord entry
            proposed_entry = rekor_types.Hashedrekord(
                spec=rekor_types.hashedrekord.HashedrekordV001Schema(
                    signature=rekor_types.hashedrekord.Signature(
                        content=base64.b64encode(artifact_signature).decode(),
                        public_key=rekor_types.hashedrekord.PublicKey(
                            content=b64_cert.decode()
                        ),
                    ),
                    data=rekor_types.hashedrekord.Data(
                        hash=rekor_types.hashedrekord.Hash(
                            algorithm=hashed_input._as_hashedrekord_algorithm(),
                            value=hashed_input.digest.hex(),
                        )
                    ),
                ),
            )

        # Submit the proposed entry to the transparency log
        entry = self._signing_ctx._rekor.log.entries.post(proposed_entry)

        _logger.debug(f"Transparency log entry created with index: {entry.log_index}")

        return Bundle._from_parts(cert, content, entry)


class SigningContext:
    """
    Keep a context between signing operations.
    """

    def __init__(
        self, *, fulcio: FulcioClient, rekor: RekorClient, trusted_root: TrustedRoot
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
        self._trusted_root = trusted_root

    @classmethod
    def production(cls) -> SigningContext:
        """
        Return a `SigningContext` instance configured against Sigstore's production-level services.
        """
        trusted_root = TrustedRoot.production(purpose=KeyringPurpose.SIGN)
        rekor = RekorClient.production()
        return cls(
            fulcio=FulcioClient.production(), rekor=rekor, trusted_root=trusted_root
        )

    @classmethod
    def staging(cls) -> SigningContext:
        """
        Return a `SignerContext` instance configured against Sigstore's staging-level services.
        """
        trusted_root = TrustedRoot.staging(purpose=KeyringPurpose.SIGN)
        rekor = RekorClient.staging()
        return cls(
            fulcio=FulcioClient.staging(), rekor=rekor, trusted_root=trusted_root
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
