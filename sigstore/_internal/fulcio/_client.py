"""
Client implementation for interacting with Fulcio.
"""

import json
from abc import ABC
from dataclasses import dataclass
from typing import List
from urllib.parse import urljoin

import requests
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509 import Certificate, load_pem_x509_certificate

DEFAULT_FULCIO_URL = "https://fulcio.sigstore.dev"
SIGNING_CERT_ENDPOINT = "/api/v1/signingCert"
ROOT_CERT_ENDPOINT = "/api/v1/rootCert"


@dataclass(frozen=True)
class FulcioCertificateSigningRequest:
    """Certificate request"""

    public_key: ec.EllipticCurvePublicKey
    signed_email_address: str

    def json(self) -> str:
        return json.dumps(
            {
                "publicKey": {
                    "content": self.public_key.public_bytes,
                    "algorithm": "EC",
                },
                "signedEmailAddress": self.signed_email_address,
            }
        )


@dataclass(frozen=True)
class FulcioCertificateSigningResponse:
    """Certificate response"""

    cert_list: List[Certificate]
    sct: str


@dataclass(frozen=True)
class RootResponse:
    root_cert: Certificate


class FulcioClientError(Exception):
    pass


class Endpoint(ABC):
    def __init__(self, url: str, session: requests.Session) -> None:
        self.url = url
        self.session = session


PEM_BLOCK_DELIM = b"-----BEGIN CERTIFICATE-----"


class FulcioClient:
    """The internal Fulcio client"""

    def __init__(self, url: str = DEFAULT_FULCIO_URL) -> None:
        """Initialize the client"""
        self.url = url
        self.session = requests.Session()

    @property
    def signing_cert(self) -> Endpoint:
        return FulcioSigningCert(urljoin(self.url, SIGNING_CERT_ENDPOINT), session=self.session)

    @property
    def root_cert(self) -> Endpoint:
        return FulcioRootCert(urljoin(self.url, ROOT_CERT_ENDPOINT), session=self.session)


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
        resp: requests.Response = self.session.post(
            url=self.url,
            data=req.json(),
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        )
        try:
            resp.raise_for_status()
        except requests.HTTPError as http_error:
            raise FulcioClientError from http_error
        sct: str
        try:
            sct = resp.headers["SCT"]
        except IndexError as index_error:
            raise FulcioClientError from index_error
        pem_blocks = resp.raw.split(PEM_BLOCK_DELIM)
        if len(pem_blocks) != 3 or not pem_blocks[0]:
            raise FulcioClientError(f"Unexpected number of PEM blocks in Fulcio response: {resp}")
        pem_blocks = pem_blocks[1:]
        cert_list: List[Certificate] = []
        for pem_block in pem_blocks:
            cert: Certificate = load_pem_x509_certificate(pem_block)
            cert_list.append(cert)
        return CertificateResponse(cert_list, sct)


class FulcioRootCert(Endpoint):
    def get(self) -> RootResponse:
        """Get the root certificate"""
        resp: requests.Response = self.session.get(self.url)
        try:
            resp.raise_for_status()
        except requests.HTTPError as http_error:
            raise FulcioClientError from http_error
        root_cert: Certificate = load_pem_x509_certificate(resp.raw)
        return RootResponse(root_cert)
