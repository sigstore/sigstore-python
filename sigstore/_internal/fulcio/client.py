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
import logging
from abc import ABC
from dataclasses import dataclass
from urllib.parse import urljoin

import urllib3
from cryptography.hazmat.primitives import serialization
from cryptography.x509 import (
    Certificate,
    CertificateSigningRequest,
    load_pem_x509_certificate,
)

from sigstore._internal import DEFAULT_RETRIES, USER_AGENT
from sigstore._utils import B64Str
from sigstore.oidc import IdentityToken

_logger = logging.getLogger(__name__)

SIGNING_CERT_ENDPOINT = "/api/v2/signingCert"
TRUST_BUNDLE_ENDPOINT = "/api/v2/trustBundle"

# Use a short connect timeout and a finite read timeout for Fulcio requests.
# Certificate issuance and trust-bundle retrieval should not block the caller
# indefinitely when the configured endpoint accepts a connection but stalls.
DEFAULT_FULCIO_TIMEOUT = urllib3.Timeout(connect=5, read=30)


class ExpiredCertificate(Exception):
    """An error raised when the Certificate is expired."""


@dataclass(frozen=True)
class FulcioCertificateSigningResponse:
    """Certificate response"""

    cert: Certificate
    chain: list[Certificate]


@dataclass(frozen=True)
class FulcioTrustBundleResponse:
    """Trust bundle response, containing a list of certificate chains"""

    trust_bundle: list[list[Certificate]]


class FulcioClientError(Exception):
    """
    Raised on any error in the Fulcio client.
    """


class _Endpoint(ABC):
    def __init__(self, url: str, http: urllib3.PoolManager) -> None:
        self.url = url
        self._http = http


def _build_cert_request(req: CertificateSigningRequest) -> dict[str, B64Str]:
    return {
        "certificateSigningRequest": B64Str(
            base64.b64encode(req.public_bytes(serialization.Encoding.PEM)).decode()
        )
    }


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
            "User-Agent": USER_AGENT,
        }
        try:
            resp = self._http.request(
                "POST",
                self.url,
                json=_build_cert_request(req),
                headers=headers,
            )
        except urllib3.exceptions.HTTPError as http_error:
            raise FulcioClientError from http_error

        if resp.status >= 400:
            try:
                error_body = resp.json()
                if isinstance(error_body, dict) and "message" in error_body:
                    raise FulcioClientError(error_body["message"])
            except ValueError:
                pass
            raise FulcioClientError(f"Fulcio returned an error with HTTP {resp.status}")

        try:
            certificates = resp.json()["signedCertificateEmbeddedSct"]["chain"][
                "certificates"
            ]
        except (ValueError, KeyError, TypeError) as exc:
            raise FulcioClientError(
                "Fulcio response missing certificate chain"
            ) from exc

        # Cryptography doesn't have chain verification/building built in
        # https://github.com/pyca/cryptography/issues/2381
        if len(certificates) < 2:
            raise FulcioClientError(
                f"Certificate chain is too short: {len(certificates)} < 2"
            )
        cert = load_pem_x509_certificate(certificates[0].encode())
        chain = [load_pem_x509_certificate(c.encode()) for c in certificates[1:]]

        return FulcioCertificateSigningResponse(cert, chain)


class FulcioTrustBundle(_Endpoint):
    """
    Fulcio REST API trust bundle functionality.
    """

    def get(self) -> FulcioTrustBundleResponse:
        """Get the certificate chains from Fulcio"""
        try:
            resp = self._http.request("GET", self.url)
        except urllib3.exceptions.HTTPError as http_error:
            raise FulcioClientError from http_error

        if resp.status >= 400:
            raise FulcioClientError(f"Fulcio returned an error with HTTP {resp.status}")

        trust_bundle_json = resp.json()
        chains: list[list[Certificate]] = []
        for certificate_chain in trust_bundle_json["chains"]:
            chain: list[Certificate] = []
            for certificate in certificate_chain["certificates"]:
                cert: Certificate = load_pem_x509_certificate(certificate.encode())
                chain.append(cert)
            chains.append(chain)
        return FulcioTrustBundleResponse(chains)


class FulcioClient:
    """The internal Fulcio client"""

    def __init__(self, url: str) -> None:
        """Initialize the client"""
        _logger.debug(f"Fulcio client using URL: {url}")
        self.url = url
        self._http = urllib3.PoolManager(
            headers={"User-Agent": USER_AGENT},
            retries=DEFAULT_RETRIES,
            timeout=DEFAULT_FULCIO_TIMEOUT,
        )

    @property
    def signing_cert(self) -> FulcioSigningCert:
        """
        Returns a model capable of interacting with Fulcio's signing certificate endpoints.
        """
        return FulcioSigningCert(
            urljoin(self.url, SIGNING_CERT_ENDPOINT), http=self._http
        )

    @property
    def trust_bundle(self) -> FulcioTrustBundle:
        """
        Returns a model capable of interacting with Fulcio's trust bundle endpoints.
        """
        return FulcioTrustBundle(
            urljoin(self.url, TRUST_BUNDLE_ENDPOINT), http=self._http
        )
