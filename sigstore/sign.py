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
    result = signer.sign_artifact(artifact)
    print(result)
```
"""

from __future__ import annotations

import base64
import logging
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime, timezone

import cryptography.x509 as x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from sigstore_models.common.v1 import HashOutput, MessageSignature

from sigstore import dsse
from sigstore import hashes as sigstore_hashes
from sigstore._internal.fulcio import (
    ExpiredCertificate,
    FulcioClient,
)
from sigstore._internal.rekor import EntryRequestBody, RekorLogSubmitter
from sigstore._internal.sct import verify_sct
from sigstore._internal.timestamp import TimestampAuthorityClient, TimestampError
from sigstore._internal.trust import KeyringPurpose, TrustedRoot
from sigstore._utils import sha256_digest
from sigstore.models import Bundle, ClientTrustConfig
from sigstore.oidc import ExpiredIdentity, IdentityToken

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
        self.__cached_private_key: ec.EllipticCurvePrivateKey | None = None
        self.__cached_signing_certificate: x509.Certificate | None = None
        if cache:
            _logger.debug("Generating ephemeral keys...")
            self.__cached_private_key = ec.generate_private_key(ec.SECP256R1())
            _logger.debug("Requesting ephemeral certificate...")
            self.__cached_signing_certificate = self._signing_cert()

    @property
    def _private_key(self) -> ec.EllipticCurvePrivateKey:
        """Get or generate a signing key."""
        if self.__cached_private_key is None:
            _logger.debug("no cached key; generating ephemeral key")
            return ec.generate_private_key(ec.SECP256R1())
        return self.__cached_private_key

    def _signing_cert(
        self,
    ) -> x509.Certificate:
        """
        Get or request a signing certificate from Fulcio.

        Internally, this performs a CSR against Fulcio and verifies that
        the returned certificate is present in Fulcio's CT log.
        """

        # Our CSR cannot possibly succeed if our underlying identity token
        # is expired.
        if not self._identity_token.in_validity_period():
            raise ExpiredIdentity

        # If it exists, verify if the current certificate is expired
        if self.__cached_signing_certificate:
            not_valid_after = self.__cached_signing_certificate.not_valid_after_utc
            if datetime.now(timezone.utc) > not_valid_after:
                raise ExpiredCertificate
            return self.__cached_signing_certificate

        else:
            _logger.debug("Retrieving signed certificate...")

            # Build an X.509 Certificate Signing Request
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
            certificate_request = builder.sign(self._private_key, hashes.SHA256())

            certificate_response = self._signing_ctx._fulcio.signing_cert.post(
                certificate_request, self._identity_token
            )

            verify_sct(
                certificate_response.cert,
                certificate_response.chain,
                self._signing_ctx._trusted_root.ct_keyring(KeyringPurpose.SIGN),
            )

            _logger.debug("Successfully verified SCT...")

            return certificate_response.cert

    def _finalize_sign(
        self,
        cert: x509.Certificate,
        content: MessageSignature | dsse.Envelope,
        proposed_entry: EntryRequestBody,
    ) -> Bundle:
        """
        Perform the common "finalizing" steps in a Sigstore signing flow.
        """
        # If the user provided TSA urls, timestamps the response
        signed_timestamp = []
        for tsa_client in self._signing_ctx._tsa_clients:
            try:
                signed_timestamp.append(tsa_client.request_timestamp(content.signature))
            except TimestampError as e:
                _logger.warning(
                    f"Unable to use {tsa_client.url} to timestamp the bundle. Failed with {e}"
                )

        # Submit the proposed entry to the transparency log
        entry = self._signing_ctx._rekor.create_entry(proposed_entry)
        _logger.debug(
            f"Transparency log entry created with index: {entry._inner.log_index}"
        )

        return Bundle._from_parts(cert, content, entry, signed_timestamp)

    def sign_dsse(
        self,
        input_: dsse.Statement,
    ) -> Bundle:
        """
        Sign the given in-toto statement as a DSSE envelope, and return a
        `Bundle` containing the signed result.

        This API is **only** for in-toto statements; to sign arbitrary artifacts,
        use `sign_artifact` instead.
        """
        cert = self._signing_cert()

        # Sign the statement, producing a DSSE envelope
        content = dsse._sign(self._private_key, input_)

        # Create the proposed DSSE log entry
        proposed_entry = self._signing_ctx._rekor._build_dsse_request(
            envelope=content, certificate=cert
        )

        return self._finalize_sign(cert, content, proposed_entry)

    def sign_artifact(
        self,
        input_: bytes | sigstore_hashes.Hashed,
    ) -> Bundle:
        """
        Sign an artifact, and return a `Bundle` corresponding to the signed result.

        The input can be one of two forms:

        1. A `bytes` buffer;
        2. A `Hashed` object, containing a pre-hashed input (e.g., for inputs
           that are too large to buffer into memory).

        Regardless of the input format, the signing operation will produce a
        `hashedrekord` entry within the bundle. No other entry types
        are supported by this API.
        """

        cert = self._signing_cert()

        # Sign artifact
        hashed_input = sha256_digest(input_)

        artifact_signature = self._private_key.sign(
            hashed_input.digest, ec.ECDSA(hashed_input._as_prehashed())
        )

        content = MessageSignature(
            message_digest=HashOutput(
                algorithm=hashed_input.algorithm,
                digest=base64.b64encode(hashed_input.digest),
            ),
            signature=base64.b64encode(artifact_signature),
        )

        # Create the proposed hashedrekord entry
        proposed_entry = self._signing_ctx._rekor._build_hashed_rekord_request(
            hashed_input=hashed_input, signature=artifact_signature, certificate=cert
        )

        return self._finalize_sign(cert, content, proposed_entry)


class SigningContext:
    """
    Keep a context between signing operations.
    """

    def __init__(
        self,
        *,
        fulcio: FulcioClient,
        rekor: RekorLogSubmitter,
        trusted_root: TrustedRoot,
        tsa_clients: list[TimestampAuthorityClient] | None = None,
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
        self._tsa_clients = tsa_clients or []

    @classmethod
    def from_trust_config(cls, trust_config: ClientTrustConfig) -> SigningContext:
        """
        Create a `SigningContext` from the given `ClientTrustConfig`.

        @api private
        """
        signing_config = trust_config.signing_config
        return cls(
            fulcio=signing_config.get_fulcio(),
            rekor=signing_config.get_tlogs()[0],
            trusted_root=trust_config.trusted_root,
            tsa_clients=signing_config.get_tsas(),
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
