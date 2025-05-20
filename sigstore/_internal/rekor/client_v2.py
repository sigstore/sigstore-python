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
from sigstore._internal.rekor.v2_types.dev.sigstore.common.v1 import PublicKeyDetails
from sigstore._internal.rekor.v2_types.dev.sigstore.rekor import v2
from sigstore._internal.rekor.v2_types.io import intoto as v2_intoto
from sigstore.dsse import Envelope
from sigstore.hashes import Hashed
from sigstore.models import LogEntry

_logger = logging.getLogger(__name__)

DEFAULT_REKOR_URL = "https://rekor.sigstore.dev"
STAGING_REKOR_URL = "https://rekor.sigstage.dev"

DEFAULT_KEY_DETAILS = PublicKeyDetails.PKIX_ECDSA_P384_SHA_256


class RekorV2Client:
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

    def create_entry(self, request: v2.CreateEntryRequest) -> LogEntry:
        """
        Submit a new entry for inclusion in the Rekor log.
        """
        # TODO: There may be a bug in betterproto, where the V_0_0_2 is changed to V002,
        # Or it is an issue with the proto `json_value`.
        # See https://github.com/sigstore/rekor-tiles/blob/bd5893730de581629a5f475923c663f776793496/api/proto/rekor_service.proto#L66.
        payload = request.to_dict()
        if "hashedRekordRequestV002" in payload:
            payload["hashedRekordRequestV0_0_2"] = payload.pop(
                "hashedRekordRequestV002"
            )
        if "dsseRequestV002" in payload:
            payload["dsseRequestV0_0_2"] = payload.pop("dsseRequestV002")
        _logger.debug(f"request: {json.dumps(payload)}")
        resp = self.session.post(f"{self.url}/log/entries", json=payload)

        try:
            resp.raise_for_status()
        except requests.HTTPError as http_error:
            raise RekorClientError(http_error)

        integrated_entry = resp.json()
        _logger.debug(f"integrated: {integrated_entry}")
        return LogEntry._from_dict_rekor(integrated_entry)

    @classmethod
    def _build_hashed_rekord_create_entry_request(
        cls,
        artifact_hashed_input: Hashed,
        artifact_signature: bytes,
        signining_certificate: Certificate,
    ) -> v2.CreateEntryRequest:
        return v2.CreateEntryRequest(
            hashed_rekord_request_v0_0_2=v2.HashedRekordRequestV002(
                digest=artifact_hashed_input.digest,
                signature=v2.Signature(
                    content=artifact_signature,
                    verifier=v2.Verifier(
                        public_key=v2.PublicKey(
                            raw_bytes=signining_certificate.public_key().public_bytes(
                                encoding=serialization.Encoding.DER,
                                format=serialization.PublicFormat.SubjectPublicKeyInfo,
                            )
                        ),
                        key_details=DEFAULT_KEY_DETAILS,
                    ),
                ),
            )
        )

    @classmethod
    def _build_dsse_create_entry_request(
        cls, envelope: Envelope, signing_certificate: Certificate
    ):
        return v2.CreateEntryRequest(
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
                        public_key=v2.PublicKey(
                            raw_bytes=signing_certificate.public_key().public_bytes(
                                encoding=serialization.Encoding.DER,
                                format=serialization.PublicFormat.SubjectPublicKeyInfo,
                            )
                        ),
                        key_details=DEFAULT_KEY_DETAILS,
                    )
                ],
            )
        )

    @classmethod
    def production(cls) -> RekorV2Client:
        """
        Returns a `RekorV2Client` populated with the default Rekor production instance.
        """
        return cls(
            DEFAULT_REKOR_URL,
        )

    @classmethod
    def staging(cls) -> RekorV2Client:
        """
        Returns a `RekorV2Client` populated with the default Rekor staging instance.
        """
        return cls(STAGING_REKOR_URL)


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
