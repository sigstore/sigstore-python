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

from __future__ import annotations

import base64
import json
import logging
from abc import ABC
from dataclasses import dataclass
from typing import List
from urllib.parse import urljoin

import requests
from cryptography.hazmat.primitives import serialization
from cryptography.x509 import (
    Certificate,
    CertificateSigningRequest,
    load_pem_x509_certificate,
)
from cryptography.x509.certificate_transparency import SignedCertificateTimestamp

from sigstore._internal import USER_AGENT
from sigstore._internal.sct import (
    UnexpectedSctCountException,
    _get_precertificate_signed_certificate_timestamps,
)
from sigstore._utils import B64Str
from sigstore.oidc import IdentityToken

_logger = logging.getLogger(__name__)

DEFAULT_FULCIO_URL = "https://fulcio.sigstore.dev"
STAGING_FULCIO_URL = "https://fulcio.sigstage.dev"
SIGNING_CERT_ENDPOINT = "/api/v2/signingCert"
TRUST_BUNDLE_ENDPOINT = "/api/v2/trustBundle"


class FulcioSCTError(Exception):
    """
    Raised on errors when constructing a `FulcioSignedCertificateTimestamp`.
    """

    pass


class ExpiredCertificate(Exception):
    """An error raised when the Certificate is expired."""


@dataclass(frozen=True)
class FulcioCertificateSigningResponse:
    """Certificate response"""

    cert: Certificate
    chain: List[Certificate]
    sct: SignedCertificateTimestamp


@dataclass(frozen=True)
class FulcioTrustBundleResponse:
    """Trust bundle response, containing a list of certificate chains"""

    trust_bundle: List[List[Certificate]]


class FulcioClientError(Exception):
    """
    Raised on any error in the Fulcio client.
    """

    pass


class _Endpoint(ABC):
    def __init__(self, url: str, session: requests.Session) -> None:
        self.url = url
        self.session = session


def _serialize_cert_request(req: CertificateSigningRequest) -> str:
    data = {
        "certificateSigningRequest": B64Str(
            base64.b64encode(req.public_bytes(serialization.Encoding.PEM)).decode()
        )
    }
    return json.dumps(data)


class FulcioSigningCert(_Endpoint):
    """
    Fulcio REST API signing certificate functionality.
    """

    def post(
        self, req: CertificateSigningRequest, identity: IdentityToken
    ) -> FulcioCertificateSigningResponse:
        """
        Get the signing certificate, using an X.509 Certificate
        Signing Request.
        """
        headers = {
            "Authorization": f"Bearer {identity}",
            "Content-Type": "application/json",
            "Accept": "application/pem-certificate-chain",
        }
        resp: requests.Response = self.session.post(
            url=self.url, data=_serialize_cert_request(req), headers=headers
        )
        try:
            resp.raise_for_status()
        except requests.HTTPError as http_error:
            # See if we can optionally add a message
            if http_error.response:
                text = json.loads(http_error.response.text)
                if "message" in http_error.response.text:
                    raise FulcioClientError(text["message"]) from http_error
            raise FulcioClientError from http_error

        try:
            certificates = resp.json()["signedCertificateEmbeddedSct"]["chain"][
                "certificates"
            ]
        except KeyError:
            raise FulcioClientError("Fulcio response missing certificate chain")

        # Cryptography doesn't have chain verification/building built in
        # https://github.com/pyca/cryptography/issues/2381
        if len(certificates) < 2:
            raise FulcioClientError(
                f"Certificate chain is too short: {len(certificates)} < 2"
            )
        cert = load_pem_x509_certificate(certificates[0].encode())
        chain = [load_pem_x509_certificate(c.encode()) for c in certificates[1:]]

        try:
            # The SignedCertificateTimestamp should be accessed by the index 0
            sct = _get_precertificate_signed_certificate_timestamps(cert)[0]

        except UnexpectedSctCountException as ex:
            raise FulcioClientError(ex)

        return FulcioCertificateSigningResponse(cert, chain, sct)


class FulcioTrustBundle(_Endpoint):
    """
    Fulcio REST API trust bundle functionality.
    """

    def get(self) -> FulcioTrustBundleResponse:
        """Get the certificate chains from Fulcio"""
        resp: requests.Response = self.session.get(self.url)
        try:
            resp.raise_for_status()
        except requests.HTTPError as http_error:
            raise FulcioClientError from http_error

        trust_bundle_json = resp.json()
        chains: List[List[Certificate]] = []
        for certificate_chain in trust_bundle_json["chains"]:
            chain: List[Certificate] = []
            for certificate in certificate_chain["certificates"]:
                cert: Certificate = load_pem_x509_certificate(certificate.encode())
                chain.append(cert)
            chains.append(chain)
        return FulcioTrustBundleResponse(chains)


class FulcioClient:
    """The internal Fulcio client"""

    def __init__(self, url: str = DEFAULT_FULCIO_URL) -> None:
        """Initialize the client"""
        _logger.debug(f"Fulcio client using URL: {url}")
        self.url = url
        self.session = requests.Session()
        self.session.headers.update(
            {
                "User-Agent": USER_AGENT,
            }
        )

    def __del__(self) -> None:
        """
        Destroys the underlying network session.
        """
        self.session.close()

    @classmethod
    def production(cls) -> FulcioClient:
        """
        Returns a `FulcioClient` for the Sigstore production instance of Fulcio.
        """
        return cls(DEFAULT_FULCIO_URL)

    @classmethod
    def staging(cls) -> FulcioClient:
        """
        Returns a `FulcioClient` for the Sigstore staging instance of Fulcio.
        """
        return cls(STAGING_FULCIO_URL)

    @property
    def signing_cert(self) -> FulcioSigningCert:
        """
        Returns a model capable of interacting with Fulcio's signing certificate endpoints.
        """
        return FulcioSigningCert(
            urljoin(self.url, SIGNING_CERT_ENDPOINT), session=self.session
        )

    @property
    def trust_bundle(self) -> FulcioTrustBundle:
        """
        Returns a model capable of interacting with Fulcio's trust bundle endpoints.
        """
        return FulcioTrustBundle(
            urljoin(self.url, TRUST_BUNDLE_ENDPOINT), session=self.session
        )
