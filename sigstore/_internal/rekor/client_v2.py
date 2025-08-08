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
Client implementation for interacting with Rekor v2.
"""

from __future__ import annotations

import base64
import json
import logging

import requests
from cryptography.hazmat.primitives import serialization
from cryptography.x509 import Certificate
from sigstore_models.common import v1 as common_v1
from sigstore_models.rekor import v2 as rekor_v2
from sigstore_models.rekor.v1 import TransparencyLogEntry as _TransparencyLogEntry

from sigstore._internal import USER_AGENT
from sigstore._internal.key_details import _get_key_details
from sigstore._internal.rekor import (
    EntryRequestBody,
    RekorClientError,
    RekorLogSubmitter,
)
from sigstore.dsse import Envelope
from sigstore.hashes import Hashed
from sigstore.models import TransparencyLogEntry

_logger = logging.getLogger(__name__)


class RekorV2Client(RekorLogSubmitter):
    """
    The internal Rekor client for the v2 API.

    See https://github.com/sigstore/rekor-tiles/blob/main/CLIENTS.md
    """

    def __init__(self, base_url: str) -> None:
        """
        Create a new `RekorV2Client` from the given URL.
        """
        self.url = f"{base_url}/api/v2"

    def create_entry(self, payload: EntryRequestBody) -> TransparencyLogEntry:
        """
        Submit a new entry for inclusion in the Rekor log.

        Note that this call can take a fairly long time as the log
        only responds after the entry has been included in the log.
        https://github.com/sigstore/rekor-tiles/blob/main/CLIENTS.md#handling-longer-requests
        """
        _logger.debug(f"proposed: {json.dumps(payload)}")

        # Use a short lived session to avoid potential issues with multi-threading:
        # Session thread-safety is ambiguous
        session = requests.Session()
        session.headers.update(
            {
                "Content-Type": "application/json",
                "Accept": "application/json",
                "User-Agent": USER_AGENT,
            }
        )

        resp = session.post(
            f"{self.url}/log/entries",
            json=payload,
        )

        try:
            resp.raise_for_status()
        except requests.HTTPError as http_error:
            raise RekorClientError(http_error)

        integrated_entry = resp.json()
        _logger.debug(f"integrated: {integrated_entry}")
        inner = _TransparencyLogEntry.from_dict(integrated_entry)
        return TransparencyLogEntry(inner)

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
        req = rekor_v2.entry.CreateEntryRequest(
            hashed_rekord_request_v002=rekor_v2.hashedrekord.HashedRekordRequestV002(
                digest=base64.b64encode(hashed_input.digest),
                signature=rekor_v2.verifier.Signature(
                    content=base64.b64encode(signature),
                    verifier=rekor_v2.verifier.Verifier(
                        x509_certificate=common_v1.X509Certificate(
                            raw_bytes=base64.b64encode(
                                certificate.public_bytes(
                                    encoding=serialization.Encoding.DER
                                )
                            )
                        ),
                        key_details=_get_key_details(certificate),
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
        req = rekor_v2.entry.CreateEntryRequest(
            dsse_request_v002=rekor_v2.dsse.DSSERequestV002(
                envelope=envelope._inner,
                verifiers=[
                    rekor_v2.verifier.Verifier(
                        x509_certificate=common_v1.X509Certificate(
                            raw_bytes=base64.b64encode(
                                certificate.public_bytes(
                                    encoding=serialization.Encoding.DER
                                )
                            )
                        ),
                        key_details=_get_key_details(certificate),
                    )
                ],
            )
        )
        return EntryRequestBody(req.to_dict())
