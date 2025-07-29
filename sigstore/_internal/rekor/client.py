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
Client implementation for interacting with Rekor.
"""

from __future__ import annotations

import base64
import json
import logging
from abc import ABC
from dataclasses import dataclass
from typing import Any

import rekor_types
import requests
from cryptography.hazmat.primitives import serialization
from cryptography.x509 import Certificate

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
    def __init__(self, url: str, session: requests.Session | None = None) -> None:
        # Note that _Endpoint may not be thread be safe if the same Session is provided
        # to an _Endpoint in multiple threads
        self.url = url
        if session is None:
            session = requests.Session()
            session.headers.update(
                {
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                    "User-Agent": USER_AGENT,
                }
            )

        self.session = session


class RekorLog(_Endpoint):
    """
    Represents a Rekor instance's log endpoint.
    """

    def get(self) -> RekorLogInfo:
        """
        Returns information about the Rekor instance's log.
        """
        resp: requests.Response = self.session.get(self.url)
        try:
            resp.raise_for_status()
        except requests.HTTPError as http_error:
            raise RekorClientError(http_error)
        return RekorLogInfo.from_response(resp.json())

    @property
    def entries(self) -> RekorEntries:
        """
        Returns a `RekorEntries` capable of accessing detailed information
        about individual log entries.
        """
        return RekorEntries(f"{self.url}/entries", session=self.session)


class RekorEntries(_Endpoint):
    """
    Represents the individual log entry endpoints on a Rekor instance.
    """

    def get(self, *, uuid: str | None = None, log_index: int | None = None) -> LogEntry:
        """
        Retrieve a specific log entry, either by UUID or by log index.

        Either `uuid` or `log_index` must be present, but not both.
        """
        if not (bool(uuid) ^ bool(log_index)):
            raise ValueError("uuid or log_index required, but not both")

        resp: requests.Response

        if uuid is not None:
            resp = self.session.get(f"{self.url}/{uuid}")
        else:
            resp = self.session.get(self.url, params={"logIndex": log_index})

        try:
            resp.raise_for_status()
        except requests.HTTPError as http_error:
            raise RekorClientError(http_error)
        return LogEntry._from_response(resp.json())

    def post(
        self,
        payload: EntryRequestBody,
    ) -> LogEntry:
        """
        Submit a new entry for inclusion in the Rekor log.
        """

        _logger.debug(f"proposed: {json.dumps(payload)}")

        resp: requests.Response = self.session.post(self.url, json=payload)
        try:
            resp.raise_for_status()
        except requests.HTTPError as http_error:
            raise RekorClientError(http_error)

        integrated_entry = resp.json()
        _logger.debug(f"integrated: {integrated_entry}")
        return LogEntry._from_response(integrated_entry)

    @property
    def retrieve(self) -> RekorEntriesRetrieve:
        """
        Returns a `RekorEntriesRetrieve` capable of retrieving entries.
        """
        return RekorEntriesRetrieve(f"{self.url}/retrieve/", session=self.session)


class RekorEntriesRetrieve(_Endpoint):
    """
    Represents the entry retrieval endpoints on a Rekor instance.
    """

    def post(
        self,
        expected_entry: rekor_types.Hashedrekord | rekor_types.Dsse,
    ) -> LogEntry | None:
        """
        Retrieves an extant Rekor entry, identified by its artifact signature,
        artifact hash, and signing certificate.

        Returns None if Rekor has no entry corresponding to the signing
        materials.
        """
        data = {"entries": [expected_entry.model_dump(mode="json", by_alias=True)]}

        resp: requests.Response = self.session.post(self.url, json=data)
        try:
            resp.raise_for_status()
        except requests.HTTPError as http_error:
            if http_error.response and http_error.response.status_code == 404:
                return None
            raise RekorClientError(http_error)

        results = resp.json()

        # The response is a list of `{uuid: LogEntry}` objects.
        # We select the oldest entry for our actual return value,
        # since a malicious actor could conceivably spam the log with
        # newer duplicate entries.
        oldest_entry: LogEntry | None = None
        for result in results:
            entry = LogEntry._from_response(result)
            if (
                oldest_entry is None
                or entry.integrated_time < oldest_entry.integrated_time
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

        return RekorLog(f"{self.url}/log")

    def create_entry(self, request: EntryRequestBody) -> LogEntry:
        """
        Submit the request to Rekor.
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
                # NOTE: mypy can't see that this kwarg is correct due to two interacting
                # behaviors/bugs (one pydantic, one datamodel-codegen):
                # See: <https://github.com/pydantic/pydantic/discussions/7418#discussioncomment-9024927>
                # See: <https://github.com/koxudaxi/datamodel-code-generator/issues/1903>
                proposed_content=rekor_types.dsse.ProposedContent(  # type: ignore[call-arg]
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
