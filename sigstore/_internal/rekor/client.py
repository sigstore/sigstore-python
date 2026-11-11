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
Client implementation for interacting with Rekor (v1).
"""

from __future__ import annotations

import base64
import json
import logging
import string
from abc import ABC
from dataclasses import dataclass
from typing import Any

import rekor_types
import urllib3
from cryptography.hazmat.primitives import serialization
from cryptography.x509 import Certificate

from sigstore._internal import DEFAULT_RETRIES, USER_AGENT
from sigstore._internal.rekor import (
    DEFAULT_REKOR_TIMEOUT,
    EntryRequestBody,
    RekorClientError,
    RekorLogSubmitter,
)
from sigstore.dsse import Envelope
from sigstore.hashes import Hashed
from sigstore.models import TransparencyLogEntry

_logger = logging.getLogger(__name__)

DEFAULT_REKOR_URL = "https://rekor.sigstore.dev"
STAGING_REKOR_URL = "https://rekor.sigstage.dev"


@dataclass(frozen=True)
class RekorLogInfo:
    """
    Represents information about the Rekor log.
    """

    root_hash: str
    tree_size: int
    signed_tree_head: str
    tree_id: str
    raw_data: dict[str, Any]

    @classmethod
    def from_response(cls, dict_: dict[str, Any]) -> RekorLogInfo:
        """
        Create a new `RekorLogInfo` from the given API response.
        """
        return cls(
            root_hash=dict_["rootHash"],
            tree_size=dict_["treeSize"],
            signed_tree_head=dict_["signedTreeHead"],
            tree_id=dict_["treeID"],
            raw_data=dict_,
        )


class _Endpoint(ABC):
    def __init__(self, url: str, http: urllib3.PoolManager) -> None:
        self.url = url
        self._http = http


class RekorLog(_Endpoint):
    """
    Represents a Rekor instance's log endpoint.
    """

    def get(self) -> RekorLogInfo:
        """
        Returns information about the Rekor instance's log.
        """
        try:
            resp = self._http.request("GET", self.url)
        except urllib3.exceptions.HTTPError as http_error:
            raise RekorClientError.from_http_error(http_error) from http_error

        if resp.status >= 400:
            raise RekorClientError.from_response(resp)
        return RekorLogInfo.from_response(resp.json())

    @property
    def entries(self) -> RekorEntries:
        """
        Returns a `RekorEntries` capable of accessing detailed information
        about individual log entries.
        """
        return RekorEntries(f"{self.url}/entries", http=self._http)


class RekorEntries(_Endpoint):
    """
    Represents the individual log entry endpoints on a Rekor instance.
    """

    def get(
        self, *, uuid: str | None = None, log_index: int | None = None
    ) -> TransparencyLogEntry:
        """
        Retrieve a specific log entry, either by UUID or by log index.

        Either `uuid` or `log_index` must be present, but not both.
        """
        if not (bool(uuid) ^ bool(log_index)):
            raise ValueError("uuid or log_index required, but not both")

        resp: urllib3.BaseHTTPResponse

        try:
            if uuid is not None:
                resp = self._http.request("GET", f"{self.url}/{uuid}")
            else:
                resp = self._http.request(
                    "GET", self.url, fields={"logIndex": str(log_index)}
                )
        except urllib3.exceptions.HTTPError as http_error:
            raise RekorClientError.from_http_error(http_error) from http_error

        if resp.status >= 400:
            raise RekorClientError.from_response(resp)
        return TransparencyLogEntry._from_v1_response(resp.json())

    def post(
        self,
        payload: EntryRequestBody,
    ) -> TransparencyLogEntry:
        """
        Submit a new entry for inclusion in the Rekor log.
        """

        _logger.debug(f"proposed: {json.dumps(payload)}")

        try:
            resp = self._http.request("POST", self.url, json=payload)
        except urllib3.exceptions.HTTPError as http_error:
            raise RekorClientError.from_http_error(http_error) from http_error

        if resp.status == 409 and (location := resp.headers.get("Location")):
            uuid = location.rstrip("/").split("/")[-1]
            if uuid and all(c in string.hexdigits for c in uuid):
                _logger.debug(
                    f"Entry already exists (409 Conflict); fetching existing entry {uuid}"
                )
                return self.get(uuid=uuid)

        if resp.status >= 400:
            raise RekorClientError.from_response(resp)

        integrated_entry = resp.json()
        _logger.debug(f"integrated: {integrated_entry}")
        return TransparencyLogEntry._from_v1_response(integrated_entry)

    @property
    def retrieve(self) -> RekorEntriesRetrieve:
        """
        Returns a `RekorEntriesRetrieve` capable of retrieving entries.
        """
        return RekorEntriesRetrieve(f"{self.url}/retrieve/", http=self._http)


class RekorEntriesRetrieve(_Endpoint):
    """
    Represents the entry retrieval endpoints on a Rekor instance.
    """

    def post(
        self,
        expected_entry: rekor_types.Hashedrekord | rekor_types.Dsse,
    ) -> TransparencyLogEntry | None:
        """
        Retrieves an extant Rekor entry, identified by its artifact signature,
        artifact hash, and signing certificate.

        Returns None if Rekor has no entry corresponding to the signing
        materials.
        """
        data = {"entries": [expected_entry.model_dump(mode="json", by_alias=True)]}

        try:
            resp = self._http.request("POST", self.url, json=data)
        except urllib3.exceptions.HTTPError as http_error:
            raise RekorClientError.from_http_error(http_error) from http_error

        if resp.status == 404:
            return None
        if resp.status >= 400:
            raise RekorClientError.from_response(resp)

        results = resp.json()

        # The response is a list of `{uuid: LogEntry}` objects.
        # We select the oldest entry for our actual return value,
        # since a malicious actor could conceivably spam the log with
        # newer duplicate entries.
        oldest_entry: TransparencyLogEntry | None = None
        for result in results:
            entry = TransparencyLogEntry._from_v1_response(result)

            # We expect every entry in Rekor v1 to have an integrated time.
            if entry._inner.integrated_time is None:
                raise ValueError(
                    f"Rekor v1 gave us an entry without an integrated time: {entry._inner.log_index}"
                )

            if (
                oldest_entry is None
                or entry._inner.integrated_time < oldest_entry._inner.integrated_time  # type: ignore[operator]
            ):
                oldest_entry = entry

        return oldest_entry


class RekorClient(RekorLogSubmitter):
    """The internal Rekor client"""

    def __init__(self, url: str) -> None:
        """
        Create a new `RekorClient` from the given URL.
        """
        self.url = f"{url}/api/v1"
        self._http = urllib3.PoolManager(
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
                "User-Agent": USER_AGENT,
            },
            retries=DEFAULT_RETRIES,
            timeout=DEFAULT_REKOR_TIMEOUT,
            maxsize=32,
        )

    @classmethod
    def production(cls) -> RekorClient:
        """
        Returns a `RekorClient` populated with the default Rekor production instance.
        """
        return cls(
            DEFAULT_REKOR_URL,
        )

    @classmethod
    def staging(cls) -> RekorClient:
        """
        Returns a `RekorClient` populated with the default Rekor staging instance.
        """
        return cls(STAGING_REKOR_URL)

    @property
    def log(self) -> RekorLog:
        """
        Returns a `RekorLog` adapter for making requests to a Rekor log.
        """

        return RekorLog(f"{self.url}/log", http=self._http)

    def create_entry(self, request: EntryRequestBody) -> TransparencyLogEntry:
        """
        Submit the request to Rekor.

        create_entry() can be called from multiple threads.
        """
        return self.log.entries.post(request)

    def _build_hashed_rekord_request(  # type: ignore[override]
        self, hashed_input: Hashed, signature: bytes, certificate: Certificate
    ) -> EntryRequestBody:
        """
        Construct a hashed rekord payload to submit to Rekor.
        """
        rekord = rekor_types.Hashedrekord(
            spec=rekor_types.hashedrekord.HashedrekordV001Schema(
                signature=rekor_types.hashedrekord.Signature(
                    content=base64.b64encode(signature).decode(),
                    public_key=rekor_types.hashedrekord.PublicKey(
                        content=base64.b64encode(
                            certificate.public_bytes(
                                encoding=serialization.Encoding.PEM
                            )
                        ).decode()
                    ),
                ),
                data=rekor_types.hashedrekord.Data(
                    hash=rekor_types.hashedrekord.Hash(
                        algorithm=hashed_input._as_hashedrekord_algorithm(),
                        value=hashed_input.digest.hex(),
                    )
                ),
            ),
        )
        return EntryRequestBody(rekord.model_dump(mode="json", by_alias=True))

    def _build_dsse_request(  # type: ignore[override]
        self, envelope: Envelope, certificate: Certificate
    ) -> EntryRequestBody:
        """
        Construct a dsse request to submit to Rekor.
        """
        dsse = rekor_types.Dsse(
            spec=rekor_types.dsse.DsseSchema(
                proposed_content=rekor_types.dsse.ProposedContent(
                    envelope=envelope.to_json(),
                    verifiers=[
                        base64.b64encode(
                            certificate.public_bytes(
                                encoding=serialization.Encoding.PEM
                            )
                        ).decode()
                    ],
                ),
            ),
        )
        return EntryRequestBody(dsse.model_dump(mode="json", by_alias=True))
