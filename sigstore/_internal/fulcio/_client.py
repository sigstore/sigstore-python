"""
Client implementation for interacting with Fulcio.
"""

import base64
import json
from abc import ABC
from dataclasses import dataclass
from typing import List
from urllib.parse import urljoin

import pem
import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509 import Certificate, load_pem_x509_certificate

DEFAULT_FULCIO_URL = "https://fulcio.sigstore.dev"
SIGNING_CERT_ENDPOINT = "/api/v1/signingCert"
ROOT_CERT_ENDPOINT = "/api/v1/rootCert"


@dataclass(frozen=True)
class FulcioCertificateSigningRequest:
    """Certificate request"""

    public_key: ec.EllipticCurvePublicKey
    signed_email_address: bytes

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
            "signedEmailAddress": base64.b64encode(self.signed_email_address).decode(),
        }
        return json.dumps(data)


@dataclass(frozen=True)
class FulcioCertificateSigningResponse:
    """Certificate response"""

    cert_pem: Certificate
    chain_pems: List[Certificate]
    sct: str


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


class FulcioClient:
    """The internal Fulcio client"""

    def __init__(self, url: str = DEFAULT_FULCIO_URL) -> None:
        """Initialize the client"""
        self.url = url
        self.session = requests.Session()

    @property
    def signing_cert(self) -> Endpoint:
        return FulcioSigningCert(
            urljoin(self.url, SIGNING_CERT_ENDPOINT), session=self.session
        )

    @property
    def root_cert(self) -> Endpoint:
        return FulcioRootCert(
            urljoin(self.url, ROOT_CERT_ENDPOINT), session=self.session
        )


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

        sct: str
        try:
            sct = resp.headers["SCT"]
        except IndexError as index_error:
            raise FulcioClientError from index_error

        # Cryptography doesn't have chain verification/building built in
        # https://github.com/pyca/cryptography/issues/2381
        try:
            cert_pem, *chain_pems = pem.parse(resp.content)
            cert = load_pem_x509_certificate(cert_pem.as_bytes())
            chain = [load_pem_x509_certificate(c.as_bytes()) for c in chain_pems]
        except ValueError:
            raise FulcioClientError(f"Did not find a cert in Fulcio response: {resp}")

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
