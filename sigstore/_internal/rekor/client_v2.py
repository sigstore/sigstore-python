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

import rekor_types
import requests
from cryptography.hazmat.primitives import serialization
from cryptography.x509 import Certificate

from sigstore._internal import USER_AGENT
from sigstore._internal.rekor import EntryRequest, RekorLogSubmitter
from sigstore._internal.rekor.v2_types.dev.sigstore.common import v1 as common_v1
from sigstore._internal.rekor.v2_types.dev.sigstore.rekor import v2
from sigstore._internal.rekor.v2_types.io import intoto as v2_intoto
from sigstore.dsse import Envelope
from sigstore.hashes import Hashed
from sigstore.models import LogEntry

_logger = logging.getLogger(__name__)

DEFAULT_REKOR_URL = "https://rekor.sigstore.dev"
STAGING_REKOR_URL = "https://rekor.sigstage.dev"

# TODO: Link to merged documenation.
# See https://github.com/sigstore/rekor-tiles/pull/255/files#diff-eb568acf84d583e4d3734b07773e96912277776bad39c560392aa33ea2cf2210R196
CREATE_ENTRIES_TIMEOUT_SECONDS = 20

DEFAULT_KEY_DETAILS = common_v1.PublicKeyDetails.PKIX_ECDSA_P384_SHA_256


class RekorV2Client(RekorLogSubmitter):
    """The internal Rekor client for the v2 API"""

    # TODO: implement get_tile, get_entry_bundle, get_checkpoint.

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

    def create_entry(self, payload: EntryRequest) -> LogEntry:
        """
        Submit a new entry for inclusion in the Rekor log.
        """
        _logger.debug(f"proposed: {json.dumps(payload)}")
        resp = self.session.post(
            f"{self.url}/log/entries",
            json=payload,
            timeout=CREATE_ENTRIES_TIMEOUT_SECONDS,
        )

        try:
            resp.raise_for_status()
        except requests.HTTPError as http_error:
            raise RekorClientError(http_error)

        integrated_entry = resp.json()
        _logger.debug(f"integrated: {integrated_entry}")
        return LogEntry._from_dict_rekor(integrated_entry)

    @classmethod
    def _build_hashed_rekord_request(
        cls,
        hashed_input: Hashed,
        signature: bytes,
        certificate: Certificate,
    ) -> EntryRequest:
        """
        Construct a hashed rekord request to submit to Rekor.
        """
        req = v2.CreateEntryRequest(
            hashed_rekord_request_v0_0_2=v2.HashedRekordRequestV002(
                digest=hashed_input.digest,
                signature=v2.Signature(
                    content=signature,
                    verifier=v2.Verifier(
                        x509_certificate=common_v1.X509Certificate(
                            raw_bytes=certificate.public_bytes(
                                encoding=serialization.Encoding.DER
                            )
                        ),
                        key_details=DEFAULT_KEY_DETAILS,  # type: ignore[arg-type]
                    ),
                ),
            )
        )
        return EntryRequest(req.to_dict())

    @classmethod
    def _build_dsse_request(
        cls, envelope: Envelope, certificate: Certificate
    ) -> EntryRequest:
        """
        Construct a dsse request to submit to Rekor.
        """
        req = v2.CreateEntryRequest(
            dsse_request_v0_0_2=v2.DsseRequestV002(
                envelope=v2_intoto.Envelope(
                    payload=envelope._inner.payload,
                    payload_type=envelope._inner.payload_type,
                    signatures=[
                        v2_intoto.Signature(
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
                        key_details=DEFAULT_KEY_DETAILS,  # type: ignore[arg-type]
                    )
                ],
            )
        )
        return EntryRequest(req.to_dict())


class RekorClientError(Exception):
    """
    A generic error in the Rekor client.
    """

    def __init__(self, http_error: requests.HTTPError):
        """
        Create a new `RekorClientError` from the given `requests.HTTPError`.
        """
        if http_error.response is not None:
            try:
                error = rekor_types.Error.model_validate_json(http_error.response.text)
                super().__init__(f"{error.code}: {error.message}")
            except Exception:
                super().__init__(
                    f"Rekor returned an unknown error with HTTP {http_error.response.status_code}"
                )
        else:
            super().__init__(f"Unexpected Rekor error: {http_error}")
