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
Client implementation for interacting with Fulcio.
"""

import base64
import datetime
import json
import struct
from abc import ABC
from dataclasses import dataclass
from enum import IntEnum
from typing import List
from urllib.parse import urljoin

import pem
import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509 import (
    Certificate,
    ExtensionNotFound,
    PrecertificateSignedCertificateTimestamps,
    load_pem_x509_certificate,
)
from cryptography.x509.certificate_transparency import (
    LogEntryType,
    SignedCertificateTimestamp,
    Version,
)
from pydantic import BaseModel, Field, validator

DEFAULT_FULCIO_URL = "https://fulcio.sigstore.dev"
SIGNING_CERT_ENDPOINT = "/api/v1/signingCert"
ROOT_CERT_ENDPOINT = "/api/v1/rootCert"


class SCTHashAlgorithm(IntEnum):
    """
    Hash algorithms that are valid for SCTs.

    These are exactly the same as the HashAlgorithm enum in RFC 5246 (TLS 1.2).

    See: https://datatracker.ietf.org/doc/html/rfc5246#section-7.4.1.4.1
    """

    NONE = 0
    MD5 = 1
    SHA1 = 2
    SHA224 = 3
    SHA256 = 4
    SHA384 = 5
    SHA512 = 6


class SCTSignatureAlgorithm(IntEnum):
    """
    Signature algorithms that are valid for SCTs.

    These are exactly the same as the SignatureAlgorithm enum in RFC 5246 (TLS 1.2).

    See: https://datatracker.ietf.org/doc/html/rfc5246#section-7.4.1.4.1
    """

    ANONYMOUS = 0
    RSA = 1
    DSA = 2
    ECDSA = 3


class FulcioSCTError(Exception):
    """
    Raised on errors when constructing a `FulcioSignedCertificateTimestamp`.
    """

    pass


class DetachedFulcioSCT(BaseModel):
    """
    Represents a "detached" SignedCertificateTimestamp from Fulcio.
    """

    version: Version = Field(..., alias="sct_version")
    log_id: bytes = Field(..., alias="id")
    timestamp: datetime.datetime
    digitally_signed: bytes = Field(..., alias="signature")
    extensions: bytes

    class Config:
        allow_population_by_field_name = True
        arbitrary_types_allowed = True

    @validator("digitally_signed", pre=True)
    def _validate_digitally_signed(cls, v: bytes) -> bytes:
        digitally_signed = base64.b64decode(v)

        if len(digitally_signed) <= 4:
            raise ValueError("impossibly small digitally-signed struct")

        return digitally_signed

    @validator("log_id", pre=True)
    def _validate_log_id(cls, v: bytes) -> bytes:
        return base64.b64decode(v)

    @validator("extensions", pre=True)
    def _validate_extensions(cls, v: bytes) -> bytes:
        return base64.b64decode(v)

    @property
    def entry_type(self) -> LogEntryType:
        return LogEntryType.X509_CERTIFICATE

    @property
    def signature_hash_algorithm(self) -> int:
        # TODO(ww): This should become a cryptography `Hash` subclass
        # instance once cryptography adds this API.
        return self.digitally_signed[0]

    @property
    def signature_algorithm(self) -> int:
        # TODO(ww): This should become a SignatureAlgorithm variant
        # once cryptography adds this API.
        return self.digitally_signed[1]

    @property
    def signature(self) -> bytes:
        (sig_size,) = struct.unpack("!H", self.digitally_signed[2:4])
        if len(self.digitally_signed[4:]) != sig_size:
            raise FulcioSCTError(
                f"signature size mismatch: expected {sig_size} bytes, "
                f"got {len(self.digitally_signed[4:])}"
            )
        return self.digitally_signed[4:]


# SignedCertificateTimestamp is an ABC, so register our DetachedFulcioSCT as
# virtual subclass.
SignedCertificateTimestamp.register(DetachedFulcioSCT)


@dataclass(frozen=True)
class FulcioCertificateSigningRequest:
    """Certificate request"""

    public_key: ec.EllipticCurvePublicKey
    signed_proof: bytes

    @property
    def data(self) -> str:
        content = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        data = {
            "publicKey": {
                "content": base64.b64encode(content).decode(),
            },
            "signedEmailAddress": base64.b64encode(self.signed_proof).decode(),
        }
        return json.dumps(data)


@dataclass(frozen=True)
class FulcioCertificateSigningResponse:
    """Certificate response"""

    cert: Certificate
    chain: List[Certificate]
    sct: SignedCertificateTimestamp


@dataclass(frozen=True)
class FulcioRootResponse:
    """Root certificate response"""

    root_cert: Certificate


class FulcioClientError(Exception):
    pass


class Endpoint(ABC):
    def __init__(self, url: str, session: requests.Session) -> None:
        self.url = url
        self.session = session


class FulcioSigningCert(Endpoint):
    def post(
        self, req: FulcioCertificateSigningRequest, token: str
    ) -> FulcioCertificateSigningResponse:
        """
        Get the signing certificate.

        Ideally, in the future, this could take an X.509 Certificate Signing
        Request object instead [^1], but the Fulcio API doesn't currently
        support this [^2].

        [^1]: https://cryptography.io/en/latest/x509/reference/#x-509-csr-certificate-signing-request-object  # noqa
        [^2]: https://github.com/sigstore/fulcio/issues/503

        """
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": "application/pem-certificate-chain",
        }
        resp: requests.Response = self.session.post(
            url=self.url, data=req.data, headers=headers
        )
        try:
            resp.raise_for_status()
        except requests.HTTPError as http_error:
            try:
                text = json.loads(http_error.response.text)
                raise FulcioClientError(text["message"]) from http_error
            except (AttributeError, KeyError):
                raise FulcioClientError from http_error

        # Cryptography doesn't have chain verification/building built in
        # https://github.com/pyca/cryptography/issues/2381
        try:
            cert_pem, *chain_pems = pem.parse(resp.content)
            cert = load_pem_x509_certificate(cert_pem.as_bytes())
            chain = [load_pem_x509_certificate(c.as_bytes()) for c in chain_pems]
        except ValueError:
            raise FulcioClientError(f"Did not find a cert in Fulcio response: {resp}")

        try:
            # Try to retrieve the embedded SCTs within the cert.
            precert_scts_extension = cert.extensions.get_extension_for_class(
                PrecertificateSignedCertificateTimestamps
            ).value

            if len(precert_scts_extension) != 1:
                raise FulcioClientError(
                    f"Unexpected embedded SCT count in response: {len(precert_scts_extension)} != 1"
                )

            sct = precert_scts_extension[0]
        except ExtensionNotFound:
            # If we don't have any embedded SCTs, then we might be dealing
            # with a Fulcio instance that provides detached SCTs.

            # The SCT header is a base64-encoded payload, which in turn
            # is a JSON representation of the SignedCertificateTimestamp
            # in RFC 6962 (subsec. 3.2).
            sct_b64 = resp.headers.get("SCT")
            if sct_b64 is None:
                raise FulcioClientError("Fulcio response did not include a SCT header")

            try:
                sct_json = json.loads(base64.b64decode(sct_b64).decode())
            except ValueError as exc:
                raise FulcioClientError from exc

            try:
                sct = DetachedFulcioSCT.parse_obj(sct_json)
            except Exception as exc:
                # Ideally we'd catch something less generic here.
                raise FulcioClientError from exc

        return FulcioCertificateSigningResponse(cert, chain, sct)


class FulcioRootCert(Endpoint):
    def get(self) -> FulcioRootResponse:
        """Get the root certificate"""
        resp: requests.Response = self.session.get(self.url)
        try:
            resp.raise_for_status()
        except requests.HTTPError as http_error:
            raise FulcioClientError from http_error
        root_cert: Certificate = load_pem_x509_certificate(resp.content)
        return FulcioRootResponse(root_cert)


class FulcioClient:
    """The internal Fulcio client"""

    def __init__(self, url: str = DEFAULT_FULCIO_URL) -> None:
        """Initialize the client"""
        self.url = url
        self.session = requests.Session()

    @property
    def signing_cert(self) -> FulcioSigningCert:
        return FulcioSigningCert(
            urljoin(self.url, SIGNING_CERT_ENDPOINT), session=self.session
        )

    @property
    def root_cert(self) -> FulcioRootCert:
        return FulcioRootCert(
            urljoin(self.url, ROOT_CERT_ENDPOINT), session=self.session
        )
