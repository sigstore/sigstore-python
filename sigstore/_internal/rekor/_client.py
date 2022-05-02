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
from abc import ABC
from dataclasses import dataclass
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin

import requests
from pydantic import BaseModel, Field, validator

DEFAULT_REKOR_URL = "https://rekor.sigstore.dev/api/v1/"


@dataclass(frozen=True)
class RekorEntry:
    uuid: str
    body: str
    integrated_time: int
    log_id: str
    log_index: int
    verification: dict
    raw_data: dict

    @classmethod
    def from_response(cls, dict_) -> RekorEntry:
        # Assumes we only get one entry back
        entries = list(dict_.items())
        if len(entries) != 1:
            raise RekorClientError("Recieved multiple entries in response")

        uuid, entry = entries[0]

        return cls(
            uuid=uuid,
            body=entry["body"],
            integrated_time=entry["integratedTime"],
            log_id=entry["logID"],
            log_index=entry["logIndex"],
            verification=entry["verification"],
            raw_data=entry,
        )


class RekorInclusionProof(BaseModel):
    log_index: int = Field(..., alias="logIndex")
    root_hash: str = Field(..., alias="rootHash")
    tree_size: int = Field(..., alias="treeSize")
    hashes: List[str] = Field(..., alias="hashes")

    @validator("log_index")
    def log_index_positive(cls, v):
        if v < 0:
            raise ValueError(f"Inclusion proof has invalid log index: {v} < 0")
        return v

    @validator("tree_size")
    def tree_size_positive(cls, v):
        if v < 0:
            raise ValueError(f"Inclusion proof has invalid tree size: {v} < 0")
        return v

    @validator("tree_size")
    def log_index_within_tree_size(cls, v, values, **kwargs):
        if v <= values["log_index"]:
            raise ValueError(
                "Inclusion proof has log index greater than or equal to tree size: "
                f"{v} <= {values['log_index']}"
            )
        return v


class RekorClientError(Exception):
    pass


class Endpoint(ABC):
    def __init__(self, url: str, session: requests.Session) -> None:
        self.url = url
        self.session = session


class RekorIndex(Endpoint):
    @property
    def retrieve(self) -> RekorRetrieve:
        return RekorRetrieve(urljoin(self.url, "retrieve/"), session=self.session)


class RekorRetrieve(Endpoint):
    def post(
        self,
        sha256_hash: Optional[str] = None,
        encoded_public_key: Optional[str] = None,
    ) -> List[str]:
        data: Dict[str, Any] = dict()
        if sha256_hash is not None:
            data["hash"] = f"sha256:{sha256_hash}"
        if encoded_public_key is not None:
            data["publicKey"] = {"format": "x509", "content": encoded_public_key}
        if not data:
            raise RekorClientError(
                "No parameters were provided to Rekor index retrieve query"
            )
        resp: requests.Response = self.session.post(self.url, data=json.dumps(data))
        try:
            resp.raise_for_status()
        except requests.HTTPError as http_error:
            raise RekorClientError from http_error
        return list(resp.json())


class RekorLog(Endpoint):
    @property
    def entries(self) -> RekorEntries:
        return RekorEntries(urljoin(self.url, "entries/"), session=self.session)


class RekorEntries(Endpoint):
    def get(self, uuid: str) -> RekorEntry:
        resp: requests.Response = self.session.get(urljoin(self.url, uuid))
        try:
            resp.raise_for_status()
        except requests.HTTPError as http_error:
            raise RekorClientError from http_error
        return RekorEntry.from_response(resp.json())

    def post(
        self,
        b64_artifact_signature: str,
        sha256_artifact_hash: str,
        b64_cert: str,
    ) -> RekorEntry:
        data = {
            "kind": "hashedrekord",
            "apiVersion": "0.0.1",
            "spec": {
                "signature": {
                    "content": b64_artifact_signature,
                    "publicKey": {"content": b64_cert},
                },
                "data": {
                    "hash": {"algorithm": "sha256", "value": sha256_artifact_hash}
                },
            },
        }

        resp: requests.Response = self.session.post(self.url, data=json.dumps(data))
        try:
            resp.raise_for_status()
        except requests.HTTPError as http_error:
            raise RekorClientError from http_error

        return RekorEntry.from_response(resp.json())


class RekorClient:
    """The internal Rekor client"""

    def __init__(self, url: str = DEFAULT_REKOR_URL) -> None:
        self.url = url
        self.session = requests.Session()
        self.session.headers.update(
            {"Content-Type": "application/json", "Accept": "application/json"}
        )

    @property
    def index(self) -> RekorIndex:
        return RekorIndex(urljoin(self.url, "index/"), session=self.session)

    @property
    def log(self) -> RekorLog:
        return RekorLog(urljoin(self.url, "log/"), session=self.session)
