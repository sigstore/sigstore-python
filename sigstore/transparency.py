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

from typing import Any, List, Optional

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictInt,
    StrictStr,
    ValidationInfo,
    field_validator,
)
from pydantic.dataclasses import dataclass
from securesystemslib.formats import encode_canonical

from sigstore._utils import B64Str


class LogInclusionProof(BaseModel):
    """
    Represents an inclusion proof for a transparency log entry.
    """

    model_config = ConfigDict(populate_by_name=True)

    checkpoint: StrictStr = Field(..., alias="checkpoint")
    hashes: List[StrictStr] = Field(..., alias="hashes")
    log_index: StrictInt = Field(..., alias="logIndex")
    root_hash: StrictStr = Field(..., alias="rootHash")
    tree_size: StrictInt = Field(..., alias="treeSize")

    @field_validator("log_index")
    def _log_index_positive(cls, v: int) -> int:
        if v < 0:
            raise ValueError(f"Inclusion proof has invalid log index: {v} < 0")
        return v

    @field_validator("tree_size")
    def _tree_size_positive(cls, v: int) -> int:
        if v < 0:
            raise ValueError(f"Inclusion proof has invalid tree size: {v} < 0")
        return v

    @field_validator("tree_size")
    def _log_index_within_tree_size(
        cls, v: int, info: ValidationInfo, **kwargs: Any
    ) -> int:
        if "log_index" in info.data and v <= info.data["log_index"]:
            raise ValueError(
                "Inclusion proof has log index greater than or equal to tree size: "
                f"{v} <= {info.data['log_index']}"
            )
        return v


@dataclass(frozen=True)
class LogEntry:
    """
    Represents a transparency log entry.

    Log entries are retrieved from the transparency log after signing or verification events,
    or loaded from "Sigstore" bundles provided by the user.

    This representation allows for either a missing inclusion promise or a missing
    inclusion proof, but not both: attempting to construct a `LogEntry` without
    at least one will fail.
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

    inclusion_proof: Optional[LogInclusionProof]
    """
    An inclusion proof for this log entry, if present.
    """

    inclusion_promise: Optional[B64Str]
    """
    An inclusion promise for this log entry, if present.

    Internally, this is a base64-encoded Signed Entry Timestamp (SET) for this
    log entry.
    """

    def __post_init__(self) -> None:
        """
        Invariant preservation.
        """

        # An inclusion proof isn't considered present unless its checkpoint
        # is also present.
        has_inclusion_proof = (
            self.inclusion_proof is not None and self.inclusion_proof.checkpoint
        )
        if not has_inclusion_proof and self.inclusion_promise is None:
            raise ValueError("Log entry must have either inclusion proof or promise")

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
            inclusion_proof=LogInclusionProof.model_validate(
                entry["verification"]["inclusionProof"]
            ),
            inclusion_promise=entry["verification"]["signedEntryTimestamp"],
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
