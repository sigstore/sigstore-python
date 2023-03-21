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

import base64
import re
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


# FIXME(jl): this does not feel like a de novo definition...
# does this exist already in sigstore-python (or its depenencices)?
@dataclass
class Signature:
    name: str
    sig_hash: bytes
    sig_base64: bytes


class Checkpoint(BaseModel):
    note: StrictStr = Field(..., alias="note")
    signatures: List[Signature] = Field(..., alias="signatures")

    @validator("signatures")
    def _signatures_nonempty(cls, v: List[bytes]) -> List[bytes]:
        if len(v) < 1:
            raise ValueError("Inclusion proof signatures list is empty!")
        return v

    @classmethod
    def from_note(cls, note: str) -> Checkpoint:
        """
        Serialize from a bundled text 'note'.

        A note contains:
        - a name, a string associated with the signer,
        - a separator blank line,
        - and signature(s), each signature takes the form
            `\u2014 NAME SIGNATURE\n`
          (where \u2014 == em dash).

        An adaptation of the Rekor's `UnmarshalText`:
        https://github.com/sigstore/rekor/blob/4b1fa6661cc6dfbc844b4c6ed9b1f44e7c5ae1c0/pkg/util/signed_note.go#L141
        """

        separator: str = "\n\n"
        if note.count(separator) != 1:
            raise ValueError(
                "Note must contain one blank line, deliniating the text from the signature block"
            )
        split = note.index(separator)

        text: str = note[: split + 1]
        data: str = note[split + len(separator) :]

        if len(data) == 0:
            raise ValueError("Malformed Note: must contain at least one signature!")
        if data[-1] != "\n":
            raise ValueError("Malformed Note: data section must end with newline!")

        signatures: list[Signature] = []

        sig_parser = re.compile(r"\u2014 (\S+) (\S+)\n")
        for (name, signature) in re.findall(sig_parser, data):
            signature_bytes: bytes = base64.b64decode(signature)
            if len(signature_bytes) < 5:
                raise ValueError("Malformed Note: signature contains too few bytes")

            signature = Signature(
                name=name,
                # FIXME(jl): In Go, construct an big-endian UInt32 from 4 bytes. Is this equivalent?
                sig_hash=signature_bytes[0:4],
                sig_base64=base64.b64encode(signature_bytes[4:]),
            )
            signatures.append(signature)

        return cls(note=text, signatures=signatures)


class LogInclusionProof(BaseModel):
    """
    Represents an inclusion proof for a transparency log entry.
    """

    checkpoint: StrictStr = Field(..., alias="checkpoint")
    hashes: List[StrictStr] = Field(..., alias="hashes")
    log_index: StrictInt = Field(..., alias="logIndex")
    root_hash: StrictStr = Field(..., alias="rootHash")
    tree_size: StrictInt = Field(..., alias="treeSize")

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
