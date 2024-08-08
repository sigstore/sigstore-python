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

import json
import logging
from abc import ABC
from dataclasses import dataclass
from typing import Any, Dict, Optional
from urllib.parse import urljoin

import rekor_types
import requests

from sigstore._internal import USER_AGENT
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
    raw_data: dict

    @classmethod
    def from_response(cls, dict_: Dict[str, Any]) -> RekorLogInfo:
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


class _Endpoint(ABC):
    def __init__(self, url: str, session: requests.Session) -> None:
        self.url = url
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
        return RekorEntries(urljoin(self.url, "entries/"), session=self.session)


class RekorEntries(_Endpoint):
    """
    Represents the individual log entry endpoints on a Rekor instance.
    """

    def get(
        self, *, uuid: Optional[str] = None, log_index: Optional[int] = None
    ) -> LogEntry:
        """
        Retrieve a specific log entry, either by UUID or by log index.

        Either `uuid` or `log_index` must be present, but not both.
        """
        if not (bool(uuid) ^ bool(log_index)):
            raise ValueError("uuid or log_index required, but not both")

        resp: requests.Response

        if uuid is not None:
            resp = self.session.get(urljoin(self.url, uuid))
        else:
            resp = self.session.get(self.url, params={"logIndex": log_index})

        try:
            resp.raise_for_status()
        except requests.HTTPError as http_error:
            raise RekorClientError(http_error)
        return LogEntry._from_response(resp.json())

    def post(
        self,
        proposed_entry: rekor_types.Hashedrekord | rekor_types.Dsse,
    ) -> LogEntry:
        """
        Submit a new entry for inclusion in the Rekor log.
        """

        payload = proposed_entry.model_dump(mode="json", by_alias=True)
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
        return RekorEntriesRetrieve(
            urljoin(self.url, "retrieve/"), session=self.session
        )


class RekorEntriesRetrieve(_Endpoint):
    """
    Represents the entry retrieval endpoints on a Rekor instance.
    """

    def post(
        self,
        expected_entry: rekor_types.Hashedrekord | rekor_types.Dsse,
    ) -> Optional[LogEntry]:
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
        oldest_entry: Optional[LogEntry] = None
        for result in results:
            entry = LogEntry._from_response(result)
            if (
                oldest_entry is None
                or entry.integrated_time < oldest_entry.integrated_time
            ):
                oldest_entry = entry

        return oldest_entry


class RekorClient:
    """The internal Rekor client"""

    def __init__(self, url: str) -> None:
        """
        Create a new `RekorClient` from the given URL.
        """
        self.url = urljoin(url, "api/v1/")
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
        return RekorLog(urljoin(self.url, "log/"), session=self.session)
