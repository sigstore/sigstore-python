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

import logging
from abc import ABC
from dataclasses import dataclass
from importlib import resources
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin

import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from pydantic import BaseModel, Field, StrictInt, StrictStr, validator
from securesystemslib.formats import encode_canonical

logger = logging.getLogger(__name__)

DEFAULT_REKOR_URL = "https://rekor.sigstore.dev"
STAGING_REKOR_URL = "https://rekor.sigstage.dev"

_DEFAULT_REKOR_ROOT_PUBKEY = resources.read_binary("sigstore._store", "rekor.pub")
_STAGING_REKOR_ROOT_PUBKEY = resources.read_binary(
    "sigstore._store", "rekor.staging.pub"
)

_DEFAULT_REKOR_CTFE_PUBKEY = resources.read_binary("sigstore._store", "ctfe.pub")
_STAGING_REKOR_CTFE_PUBKEY = resources.read_binary(
    "sigstore._store", "ctfe.staging.pub"
)


@dataclass(frozen=True)
class RekorEntry:
    uuid: Optional[str]
    """
    This entry's unique ID in the Rekor instance it was retrieved from.

    For sharded Rekor deployments, IDs are unique per-shard.

    Not present for `RekorEntry` instances loaded from offline bundles.
    """

    body: str
    """
    The base64-encoded body of the Rekor entry.
    """

    integrated_time: int
    """
    The UNIX time at which this entry was integrated into the Rekor log.
    """

    log_id: str
    """
    The log's ID (as the SHA256 hash of the DER-encoded public key for the log
    at the time of entry inclusion).
    """

    log_index: int
    """
    The index of this entry within the log.
    """

    inclusion_proof: Optional[RekorInclusionProof]
    """
    An optional inclusion proof for this log entry.

    Only present for entries retrieved from online logs.
    """

    signed_entry_timestamp: str
    """
    The base64-encoded Signed Entry Timestamp (SET) for this log entry.
    """

    @classmethod
    def from_response(cls, dict_: Dict[str, Any]) -> RekorEntry:
        # Assumes we only get one entry back
        entries = list(dict_.items())
        if len(entries) != 1:
            raise RekorClientError("Received multiple entries in response")

        uuid, entry = entries[0]

        return cls(
            uuid=uuid,
            body=entry["body"],
            integrated_time=entry["integratedTime"],
            log_id=entry["logID"],
            log_index=entry["logIndex"],
            inclusion_proof=RekorInclusionProof.parse_obj(
                entry["verification"]["inclusionProof"]
            ),
            signed_entry_timestamp=entry["verification"]["signedEntryTimestamp"],
        )

    @classmethod
    def from_bundle(cls, dict_: Dict[str, Any]) -> RekorEntry:
        """
        Creates a `RekorEntry` from an offline Rekor bundle.

        See: <https://github.com/sigstore/cosign/blob/main/specs/SIGNATURE_SPEC.md#properties>
        """

        payload = dict_["payload"]
        return cls(
            uuid=None,
            body=payload["body"],
            integrated_time=payload["body"],
            log_id=payload["body"],
            log_index=payload["body"],
            inclusion_proof=None,
            signed_entry_timestamp=dict_["SignedEntryTimestamp"],
        )

    def encode_canonical(self) -> bytes:
        """
        Returns a base64-encoded, canonicalized JSON (RFC 8785) representation
        of the Rekor log entry.

        This encoded representation is suitable for verification against
        the Signed Entry Timestamp.
        """
        payload = {
            "body": self.body,
            "integratedTime": self.integrated_time,
            "logID": self.log_id,
            "logIndex": self.log_index,
        }

        return encode_canonical(payload).encode()  # type: ignore


@dataclass(frozen=True)
class RekorLogInfo:
    root_hash: str
    tree_size: int
    signed_tree_head: str
    tree_id: str
    raw_data: dict

    @classmethod
    def from_response(cls, dict_: Dict[str, Any]) -> RekorLogInfo:
        return cls(
            root_hash=dict_["rootHash"],
            tree_size=dict_["treeSize"],
            signed_tree_head=dict_["signedTreeHead"],
            tree_id=dict_["treeID"],
            raw_data=dict_,
        )


class RekorInclusionProof(BaseModel):
    log_index: StrictInt = Field(..., alias="logIndex")
    root_hash: StrictStr = Field(..., alias="rootHash")
    tree_size: StrictInt = Field(..., alias="treeSize")
    hashes: List[StrictStr] = Field(..., alias="hashes")

    class Config:
        allow_population_by_field_name = True

    @validator("log_index")
    def log_index_positive(cls, v: int) -> int:
        if v < 0:
            raise ValueError(f"Inclusion proof has invalid log index: {v} < 0")
        return v

    @validator("tree_size")
    def tree_size_positive(cls, v: int) -> int:
        if v < 0:
            raise ValueError(f"Inclusion proof has invalid tree size: {v} < 0")
        return v

    @validator("tree_size")
    def log_index_within_tree_size(
        cls, v: int, values: Dict[str, Any], **kwargs: Any
    ) -> int:
        if "log_index" in values and v <= values["log_index"]:
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


class RekorLog(Endpoint):
    def get(self) -> RekorLogInfo:
        resp: requests.Response = self.session.get(self.url)
        try:
            resp.raise_for_status()
        except requests.HTTPError as http_error:
            raise RekorClientError from http_error
        return RekorLogInfo.from_response(resp.json())

    @property
    def entries(self) -> RekorEntries:
        return RekorEntries(urljoin(self.url, "entries/"), session=self.session)


class RekorEntries(Endpoint):
    def get(
        self, *, uuid: Optional[str] = None, log_index: Optional[int] = None
    ) -> RekorEntry:
        if not (bool(uuid) ^ bool(log_index)):
            raise RekorClientError("uuid or log_index required, but not both")

        resp: requests.Response

        if uuid is not None:
            resp = self.session.get(urljoin(self.url, uuid))
        else:
            resp = self.session.get(self.url, params={"logIndex": log_index})

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
        # TODO(ww): Dedupe this payload construction with the retrive endpoint below.
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

        resp: requests.Response = self.session.post(self.url, json=data)
        try:
            resp.raise_for_status()
        except requests.HTTPError as http_error:
            raise RekorClientError from http_error

        return RekorEntry.from_response(resp.json())

    @property
    def retrieve(self) -> RekorEntriesRetrieve:
        return RekorEntriesRetrieve(
            urljoin(self.url, "retrieve/"), session=self.session
        )


class RekorEntriesRetrieve(Endpoint):
    def post(
        self,
        b64_artifact_signature: str,
        sha256_artifact_hash: str,
        b64_cert: str,
    ) -> Optional[RekorEntry]:
        """
        Retrieves an extant Rekor entry, identified by its artifact signature,
        artifact hash, and signing certificate.

        Returns None if Rekor has no entry corresponding to the signing
        materials.
        """
        data = {
            "entries": [
                {
                    "kind": "hashedrekord",
                    "apiVersion": "0.0.1",
                    "spec": {
                        "signature": {
                            "content": b64_artifact_signature,
                            "publicKey": {"content": b64_cert},
                        },
                        "data": {
                            "hash": {
                                "algorithm": "sha256",
                                "value": sha256_artifact_hash,
                            }
                        },
                    },
                }
            ]
        }

        resp: requests.Response = self.session.post(self.url, json=data)
        try:
            resp.raise_for_status()
        except requests.HTTPError as http_error:
            if http_error.response.status_code == 404:
                return None
            raise RekorClientError(resp.json()) from http_error

        results = resp.json()

        # The response is a list of `{uuid: LogEntry}` objects.
        # We select the oldest entry for our actual return value,
        # since a malicious actor could conceivably spam the log with
        # newer duplicate entries.
        oldest_entry: Optional[RekorEntry] = None
        for result in results:
            entry = RekorEntry.from_response(result)
            if (
                oldest_entry is None
                or entry.integrated_time < oldest_entry.integrated_time
            ):
                oldest_entry = entry

        return oldest_entry


class RekorClient:
    """The internal Rekor client"""

    def __init__(self, url: str, pubkey: bytes, ctfe_pubkey: bytes) -> None:
        self.url = urljoin(url, "api/v1/")
        self.session = requests.Session()
        self.session.headers.update(
            {"Content-Type": "application/json", "Accept": "application/json"}
        )

        pubkey = serialization.load_pem_public_key(pubkey)
        if not isinstance(
            pubkey,
            ec.EllipticCurvePublicKey,
        ):
            raise RekorClientError(f"Invalid public key type: {pubkey}")
        self._pubkey = pubkey

        ctfe_pubkey = serialization.load_pem_public_key(ctfe_pubkey)
        if not isinstance(
            ctfe_pubkey,
            (
                rsa.RSAPublicKey,
                ec.EllipticCurvePublicKey,
            ),
        ):
            raise RekorClientError(f"Invalid CTFE public key type: {ctfe_pubkey}")
        self._ctfe_pubkey = ctfe_pubkey

    def __del__(self) -> None:
        self.session.close()

    @classmethod
    def production(cls) -> RekorClient:
        return cls(
            DEFAULT_REKOR_URL, _DEFAULT_REKOR_ROOT_PUBKEY, _DEFAULT_REKOR_CTFE_PUBKEY
        )

    @classmethod
    def staging(cls) -> RekorClient:
        return cls(
            STAGING_REKOR_URL, _STAGING_REKOR_ROOT_PUBKEY, _STAGING_REKOR_CTFE_PUBKEY
        )

    @property
    def log(self) -> RekorLog:
        return RekorLog(urljoin(self.url, "log/"), session=self.session)
