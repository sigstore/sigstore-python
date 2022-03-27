"""
Client implementation for interacting with Fulcio.
"""

import json
from dataclasses import dataclass
from typing import List

import requests
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509 import Certificate, load_pem_x509_certificate

DEFAULT_FULCIO_URL = "https://fulcio.sigstore.dev"
SIGNING_CERT_ENDPOINT = "/api/v1/signingCert"
ROOT_CERT_ENDPOINT = "/api/v1/rootCert"


@dataclass(frozen=True)
class CertificateRequest:
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
class CertificateResponse:
    """Certificate response"""

    cert_list: List[Certificate]
    sct: str


@dataclass(frozen=True)
class RootResponse:
    root_cert: Certificate


class FulcioClientError(Exception):
    pass


PEM_BLOCK_DELIM = b"-----BEGIN CERTIFICATE-----"


class FulcioClient:
    """The internal Fulcio client"""

    def __init__(self, base_url: str = DEFAULT_FULCIO_URL) -> None:
        """Initialize the client"""
        self.base_url = base_url

    def signing_cert(self, req: CertificateRequest, token: str) -> CertificateResponse:
        """Get the signing certificate"""
        cert_url = self.base_url + SIGNING_CERT_ENDPOINT
        response: requests.Response = requests.post(
            url=cert_url,
            data=req.json(),
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        )
        if response.status_code != 201:
            raise FulcioClientError(f"Unexpected status code on Fulcio response: {response}")
        sct: str
        try:
            sct = response.headers["SCT"]
        except IndexError as index_error:
            raise FulcioClientError from index_error
        cert_data = response.raw.split(PEM_BLOCK_DELIM)
        assert not cert_data[0]
        cert_list: List[Certificate] = []
        cert_data = cert_data[1:]
        for cd in cert_data:
            cert: Certificate = load_pem_x509_certificate(cd)
            cert_list.append(cert)
        return CertificateResponse(cert_list, sct)

    def root_cert(self) -> RootResponse:
        """Get the root certificate"""
        root_url = self.base_url + ROOT_CERT_ENDPOINT
        response: requests.Response = requests.get(root_url)
        if response.status_code != 201:
            raise FulcioClientError(f"Unexpected status code on Fulcio response: {response}")
        root_cert: Certificate = load_pem_x509_certificate(response.raw)
        return RootResponse(root_cert)
