# Copyright 2025 The Sigstore Authors
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
Client implementation for interacting with RekorV2.
"""

from __future__ import annotations

import json
import logging
from typing import cast

import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.x509 import Certificate
from sigstore_protobuf_specs.dev.sigstore.common import v1 as common_v1
from sigstore_protobuf_specs.dev.sigstore.rekor import v2
from sigstore_protobuf_specs.io import intoto

from sigstore._internal import USER_AGENT
from sigstore._internal.rekor import (
    EntryRequestBody,
    RekorClientError,
    RekorLogSubmitter,
)
from sigstore.dsse import Envelope
from sigstore.hashes import Hashed
from sigstore.models import LogEntry

_logger = logging.getLogger(__name__)


class RekorV2Client(RekorLogSubmitter):
    """The internal Rekor client for the v2 API

    See https://github.com/sigstore/rekor-tiles/blob/main/CLIENTS.md
    """

    def __init__(self, base_url: str) -> None:
        """
        Create a new `RekorV2Client` from the given URL.
        """
        self.url = f"{base_url}/api/v2"
        self.session = requests.Session()
        self.session.headers.update(
            {
                "Content-Type": "application/json",
                "Accept": "application/json",
                "User-Agent": USER_AGENT,
            }
        )

    def __del__(self) -> None:
        """
        Terminates the underlying network session.
        """
        self.session.close()

    def create_entry(self, payload: EntryRequestBody) -> LogEntry:
        """
        Submit a new entry for inclusion in the Rekor log.

        Note that this call can take a fairly long time as the log
        only responds after the entry has been included in the log.
        https://github.com/sigstore/rekor-tiles/blob/main/CLIENTS.md#handling-longer-requests
        """
        _logger.debug(f"proposed: {json.dumps(payload)}")
        resp = self.session.post(
            f"{self.url}/log/entries",
            json=payload,
        )

        try:
            resp.raise_for_status()
        except requests.HTTPError as http_error:
            raise RekorClientError(http_error)

        integrated_entry = resp.json()
        _logger.debug(f"integrated: {integrated_entry}")
        return LogEntry._from_dict_rekor(integrated_entry)

    @staticmethod
    def _get_key_details(certificate: Certificate) -> common_v1.PublicKeyDetails:
        """Determine PublicKeyDetails from a certificate

        We know that sign.Signer only uses secp256r1 so do not support anything else"""
        public_key = certificate.public_key()
        if isinstance(public_key, EllipticCurvePublicKey):
            if public_key.curve.name == "secp256r1":
                return cast(
                    common_v1.PublicKeyDetails,
                    common_v1.PublicKeyDetails.PKIX_ECDSA_P256_SHA_256,
                )
            raise ValueError(f"Unsupported EC curve: {public_key.curve.name}")
        raise ValueError(f"Unsupported public key type: {type(public_key)}")

    @classmethod
    def _build_hashed_rekord_request(
        cls,
        hashed_input: Hashed,
        signature: bytes,
        certificate: Certificate,
    ) -> EntryRequestBody:
        """
        Construct a hashed rekord request to submit to Rekor.
        """
        req = v2.CreateEntryRequest(
            hashed_rekord_request_v002=v2.HashedRekordRequestV002(
                digest=hashed_input.digest,
                signature=v2.Signature(
                    content=signature,
                    verifier=v2.Verifier(
                        x509_certificate=common_v1.X509Certificate(
                            raw_bytes=certificate.public_bytes(
                                encoding=serialization.Encoding.DER
                            )
                        ),
                        key_details=cls._get_key_details(certificate),
                    ),
                ),
            )
        )
        return EntryRequestBody(req.to_dict())

    @classmethod
    def _build_dsse_request(
        cls, envelope: Envelope, certificate: Certificate
    ) -> EntryRequestBody:
        """
        Construct a dsse request to submit to Rekor.
        """
        req = v2.CreateEntryRequest(
            dsse_request_v002=v2.DsseRequestV002(
                envelope=intoto.Envelope(
                    payload=envelope._inner.payload,
                    payload_type=envelope._inner.payload_type,
                    signatures=[
                        intoto.Signature(
                            keyid=signature.keyid,
                            sig=signature.sig,
                        )
                        for signature in envelope._inner.signatures
                    ],
                ),
                verifiers=[
                    v2.Verifier(
                        x509_certificate=common_v1.X509Certificate(
                            raw_bytes=certificate.public_bytes(
                                encoding=serialization.Encoding.DER
                            )
                        ),
                        key_details=cls._get_key_details(certificate),
                    )
                ],
            )
        )
        return EntryRequestBody(req.to_dict())
