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
import datetime
import json
import logging
import struct
from abc import ABC
from dataclasses import dataclass
from enum import IntEnum
from typing import List
from urllib.parse import urljoin

import requests
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509 import (
    Certificate,
    CertificateSigningRequest,
    PrecertificateSignedCertificateTimestamps,
    load_pem_x509_certificate,
)
from cryptography.x509.certificate_transparency import (
    LogEntryType,
    SignatureAlgorithm,
    SignedCertificateTimestamp,
    Version,
)
from pydantic import BaseModel, Field, validator

logger = logging.getLogger(__name__)

DEFAULT_FULCIO_URL = "https://fulcio.sigstore.dev"
STAGING_FULCIO_URL = "https://fulcio.sigstage.dev"
SIGNING_CERT_ENDPOINT = "/api/v2/signingCert"
TRUST_BUNDLE_ENDPOINT = "/api/v2/trustBundle"


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

    def to_cryptography(self) -> hashes.HashAlgorithm:
        if self != SCTHashAlgorithm.SHA256:
            raise FulcioSCTError(f"unexpected hash algorithm: {self!r}")

        return hashes.SHA256()


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
    extension_bytes: bytes = Field(..., alias="extensions")

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

    @validator("extension_bytes", pre=True)
    def _validate_extensions(cls, v: bytes) -> bytes:
        return base64.b64decode(v)

    @property
    def entry_type(self) -> LogEntryType:
        return LogEntryType.X509_CERTIFICATE

    @property
    def signature_hash_algorithm(self) -> hashes.HashAlgorithm:
        hash_ = SCTHashAlgorithm(self.digitally_signed[0])
        return hash_.to_cryptography()

    @property
    def signature_algorithm(self) -> SignatureAlgorithm:
        return SignatureAlgorithm(self.digitally_signed[1])

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
    pass


class Endpoint(ABC):
    def __init__(self, url: str, session: requests.Session) -> None:
        self.url = url
        self.session = session


def _serialize_cert_request(req: CertificateSigningRequest) -> str:
    data = {
        "certificateSigningRequest": base64.b64encode(
            req.public_bytes(serialization.Encoding.PEM)
        ).decode()
    }
    return json.dumps(data)


class FulcioSigningCert(Endpoint):
    def post(
        self, req: CertificateSigningRequest, token: str
    ) -> FulcioCertificateSigningResponse:
        """
        Get the signing certificate, using an X.509 Certificate
        Signing Request.
        """
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": "application/pem-certificate-chain",
        }
        resp: requests.Response = self.session.post(
            url=self.url, data=_serialize_cert_request(req), headers=headers
        )
        try:
            resp.raise_for_status()
        except requests.HTTPError as http_error:
            try:
                text = json.loads(http_error.response.text)
                raise FulcioClientError(text["message"]) from http_error
            except (AttributeError, KeyError):
                raise FulcioClientError from http_error

        if resp.json().get("signedCertificateEmbeddedSct"):
            sct_embedded = True
            try:
                certificates = resp.json()["signedCertificateEmbeddedSct"]["chain"][
                    "certificates"
                ]
            except KeyError:
                raise FulcioClientError("Fulcio response missing certificate chain")
        else:
            sct_embedded = False
            try:
                certificates = resp.json()["signedCertificateDetachedSct"]["chain"][
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

        if sct_embedded:
            # Try to retrieve the embedded SCTs within the cert.
            precert_scts_extension = cert.extensions.get_extension_for_class(
                PrecertificateSignedCertificateTimestamps
            ).value

            if len(precert_scts_extension) != 1:
                raise FulcioClientError(
                    f"Unexpected embedded SCT count in response: {len(precert_scts_extension)} != 1"
                )
            sct = precert_scts_extension[0]
        else:
            # If we don't have any embedded SCTs, then we might be dealing
            # with a Fulcio instance that provides detached SCTs.

            # The detached SCT is a base64-encoded payload, which in turn
            # is a JSON representation of the SignedCertificateTimestamp
            # in RFC 6962 (subsec. 3.2).
            try:
                sct_b64 = resp.json()["signedCertificateDetachedSct"][
                    "signedCertificateTimestamp"
                ]
            except KeyError:
                raise FulcioClientError(
                    "Fulcio response did not include a detached SCT"
                )

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


class FulcioTrustBundle(Endpoint):
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
        logger.debug(f"Fulcio client using URL: {url}")
        self.url = url
        self.session = requests.Session()

    def __del__(self) -> None:
        self.session.close()

    @classmethod
    def production(cls) -> FulcioClient:
        return cls(DEFAULT_FULCIO_URL)

    @classmethod
    def staging(cls) -> FulcioClient:
        return cls(STAGING_FULCIO_URL)

    @property
    def signing_cert(self) -> FulcioSigningCert:
        return FulcioSigningCert(
            urljoin(self.url, SIGNING_CERT_ENDPOINT), session=self.session
        )

    @property
    def trust_bundle(self) -> FulcioTrustBundle:
        return FulcioTrustBundle(
            urljoin(self.url, TRUST_BUNDLE_ENDPOINT), session=self.session
        )
