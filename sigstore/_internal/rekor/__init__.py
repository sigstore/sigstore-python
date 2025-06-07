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
APIs for interacting with Rekor.
"""

from __future__ import annotations

import base64
from abc import ABC, abstractmethod
from typing import Any, NewType

import rekor_types
import requests
from cryptography.x509 import Certificate

from sigstore._utils import base64_encode_pem_cert
from sigstore.dsse import Envelope
from sigstore.hashes import Hashed
from sigstore.models import LogEntry

__all__ = [
    "_hashedrekord_from_parts",
]

EntryRequest = NewType("EntryRequest", dict[str, Any])


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


class RekorLogSubmitter(ABC):
    """Abstract class to represent a Rekor log entry submitter.

    Intended to be implemented by RekorClient and RekorV2Client
    """

    @abstractmethod
    def create_entry(
        self,
        request: EntryRequest,
    ) -> LogEntry:
        """
        Submit the request to Rekor.
        """
        pass

    @classmethod
    @abstractmethod
    def _build_hashed_rekord_request(
        self, hashed_input: Hashed, signature: bytes, certificate: Certificate
    ) -> EntryRequest:
        """
        Construct a hashed rekord request to submit to Rekor.
        """
        pass

    @classmethod
    @abstractmethod
    def _build_dsse_request(
        self, envelope: Envelope, certificate: Certificate
    ) -> EntryRequest:
        """
        Construct a dsse request to submit to Rekor.
        """
        pass


# TODO: This should probably live somewhere better.
def _hashedrekord_from_parts(
    cert: Certificate, sig: bytes, hashed: Hashed
) -> rekor_types.Hashedrekord:
    return rekor_types.Hashedrekord(
        spec=rekor_types.hashedrekord.HashedrekordV001Schema(
            signature=rekor_types.hashedrekord.Signature(
                content=base64.b64encode(sig).decode(),
                public_key=rekor_types.hashedrekord.PublicKey(
                    content=base64_encode_pem_cert(cert),
                ),
            ),
            data=rekor_types.hashedrekord.Data(
                hash=rekor_types.hashedrekord.Hash(
                    algorithm=hashed._as_hashedrekord_algorithm(),
                    value=hashed.digest.hex(),
                )
            ),
        )
    )
