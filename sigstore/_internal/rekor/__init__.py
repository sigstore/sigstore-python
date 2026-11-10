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
import typing
from abc import ABC, abstractmethod

import rekor_types
import urllib3
from cryptography.x509 import Certificate

from sigstore._utils import base64_encode_pem_cert
from sigstore.dsse import Envelope
from sigstore.hashes import Hashed

if typing.TYPE_CHECKING:
    from sigstore.models import TransparencyLogEntry

__all__ = [
    "DEFAULT_REKOR_TIMEOUT",
    "_hashedrekord_from_parts",
]

EntryRequestBody = typing.NewType("EntryRequestBody", dict[str, typing.Any])

# Overloaded Rekor typically errors after 30 secs so timeout is only a fallback.
DEFAULT_REKOR_TIMEOUT = urllib3.Timeout(connect=5, read=60)


class RekorClientError(Exception):
    """
    A generic error in the Rekor client.
    """

    @classmethod
    def from_response(cls, response: urllib3.BaseHTTPResponse) -> RekorClientError:
        """
        Create a new `RekorClientError` from the given `urllib3.BaseHTTPResponse`.
        """
        try:
            error = rekor_types.Error.model_validate_json(response.data)
            return cls(f"{error.code}: {error.message}")
        except Exception:  # noqa: BLE001
            return cls(f"Rekor returned an error with HTTP {response.status}")

    @classmethod
    def from_http_error(
        cls, http_error: urllib3.exceptions.HTTPError
    ) -> RekorClientError:
        """
        Create a new `RekorClientError` from the given `urllib3.exceptions.HTTPError`.
        """
        return cls(f"Unexpected Rekor error: {http_error}")


class RekorLogSubmitter(ABC):
    """
    Abstract class to represent a Rekor log entry submitter.

    Intended to be implemented by RekorClient and RekorV2Client.
    """

    @abstractmethod
    def create_entry(
        self,
        request: EntryRequestBody,
    ) -> TransparencyLogEntry:
        """
        Submit the request to Rekor.
        """

    @classmethod
    @abstractmethod
    def _build_hashed_rekord_request(
        self, hashed_input: Hashed, signature: bytes, certificate: Certificate
    ) -> EntryRequestBody:
        """
        Construct a hashed rekord request to submit to Rekor.
        """

    @classmethod
    @abstractmethod
    def _build_dsse_request(
        self, envelope: Envelope, certificate: Certificate
    ) -> EntryRequestBody:
        """
        Construct a dsse request to submit to Rekor.
        """


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
