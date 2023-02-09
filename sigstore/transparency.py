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
Transparency log data structures.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, StrictInt, StrictStr, validator
from securesystemslib.formats import encode_canonical

from sigstore._utils import B64Str


@dataclass(frozen=True)
class LogEntry:
    """
    Represents a transparency log entry.

    Log entries are retrieved from the transparency log after signing or verification events,
    or loaded from "Sigstore" bundles provided by the user.
    """

    uuid: Optional[str]
    """
    This entry's unique ID in the log instance it was retrieved from.

    For sharded log deployments, IDs are unique per-shard.

    Not present for `LogEntry` instances loaded from Sigstore bundles.
    """

    body: B64Str
    """
    The base64-encoded body of the transparency log entry.
    """

    integrated_time: int
    """
    The UNIX time at which this entry was integrated into the transparency log.
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

    inclusion_proof: Optional["LogInclusionProof"]
    """
    An optional inclusion proof for this log entry.

    Only present for entries retrieved from online logs.
    """

    signed_entry_timestamp: B64Str
    """
    The base64-encoded Signed Entry Timestamp (SET) for this log entry.
    """

    @classmethod
    def _from_response(cls, dict_: dict[str, Any]) -> LogEntry:
        """
        Create a new `LogEntry` from the given API response.
        """

        # Assumes we only get one entry back
        entries = list(dict_.items())
        if len(entries) != 1:
            raise ValueError("Received multiple entries in response")

        uuid, entry = entries[0]

        return LogEntry(
            uuid=uuid,
            body=entry["body"],
            integrated_time=entry["integratedTime"],
            log_id=entry["logID"],
            log_index=entry["logIndex"],
            inclusion_proof=LogInclusionProof.parse_obj(
                entry["verification"]["inclusionProof"]
            ),
            signed_entry_timestamp=entry["verification"]["signedEntryTimestamp"],
        )

    def encode_canonical(self) -> bytes:
        """
        Returns a canonicalized JSON (RFC 8785) representation of the transparency log entry.

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


class LogInclusionProof(BaseModel):
    """
    Represents an inclusion proof for a transparency log entry.
    """

    log_index: StrictInt = Field(..., alias="logIndex")
    root_hash: StrictStr = Field(..., alias="rootHash")
    tree_size: StrictInt = Field(..., alias="treeSize")
    hashes: List[StrictStr] = Field(..., alias="hashes")

    class Config:
        allow_population_by_field_name = True

    @validator("log_index")
    def _log_index_positive(cls, v: int) -> int:
        if v < 0:
            raise ValueError(f"Inclusion proof has invalid log index: {v} < 0")
        return v

    @validator("tree_size")
    def _tree_size_positive(cls, v: int) -> int:
        if v < 0:
            raise ValueError(f"Inclusion proof has invalid tree size: {v} < 0")
        return v

    @validator("tree_size")
    def _log_index_within_tree_size(
        cls, v: int, values: Dict[str, Any], **kwargs: Any
    ) -> int:
        if "log_index" in values and v <= values["log_index"]:
            raise ValueError(
                "Inclusion proof has log index greater than or equal to tree size: "
                f"{v} <= {values['log_index']}"
            )
        return v
