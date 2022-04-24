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
from pydantic import BaseModel, Field

DEFAULT_REKOR_URL = "https://rekor.sigstore.dev/api/v1/"


@dataclass(frozen=True)
class RekorEntry:
    uuid: str
    body: str
    integrated_time: int
    log_id: str
    log_index: int
    verification: dict

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
        )


class RekorInclusionProof(BaseModel):
    log_index: int = Field(..., alias="logIndex")
    root_hash: str = Field(..., alias="rootHash")
    tree_size: int = Field(..., alias="treeSize")
    hashes: List[str] = Field(..., alias="hashes")


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
        encoded_public_key: str,
    ) -> RekorEntry:
        data = {
            "kind": "hashedrekord",
            "apiVersion": "0.0.1",
            "spec": {
                "signature": {
                    "content": b64_artifact_signature,
                    "publicKey": {"content": encoded_public_key},
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
