# Copyright 2026 The Sigstore Authors
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
The `TransparencyLogEntry` model.

This lives in its own leaf module (rather than in `sigstore.models`, where it
used to live) so that it can be imported by both `sigstore.models` and the
Rekor client modules (`sigstore._internal.rekor.client`,
`sigstore._internal.rekor.client_v2`) without a circular import: `models.py`
needs `RekorClient`/`RekorV2Client` to implement `SigningConfig.get_tlogs()`,
and the Rekor clients need `TransparencyLogEntry` to type their responses.
`sigstore.models` re-exports `TransparencyLogEntry` for backwards
compatibility.
"""

from __future__ import annotations

import base64
import logging
from typing import TYPE_CHECKING, Any

import rfc8785
from pydantic import TypeAdapter
from rekor_types import Dsse, Hashedrekord, ProposedEntry
from sigstore_models.common import v1 as common_v1
from sigstore_models.rekor import v1 as rekor_v1
from sigstore_models.rekor.v1 import TransparencyLogEntry as _TransparencyLogEntry

from sigstore._internal.merkle import verify_merkle_inclusion
from sigstore._internal.rekor.checkpoint import verify_checkpoint
from sigstore._utils import KeyID
from sigstore.errors import InvalidBundle, VerificationError

if TYPE_CHECKING:
    from sigstore._internal.trust import RekorKeyring

_logger = logging.getLogger(__name__)


class TransparencyLogEntry:
    """
    Represents a transparency log entry.
    """

    def __init__(self, inner: _TransparencyLogEntry) -> None:
        """
        Creates a new `TransparencyLogEntry` from the given inner object.

        @private
        """
        self._inner = inner
        self._validate()

    def _validate(self) -> None:
        """
        Ensure this transparency log entry is well-formed and upholds our
        client invariants.
        """

        inclusion_proof: rekor_v1.InclusionProof | None = self._inner.inclusion_proof
        # This check is required by us as the client, not the
        # protobuf-specs themselves.
        if not inclusion_proof or not inclusion_proof.checkpoint:
            raise InvalidBundle("entry must contain inclusion proof, with checkpoint")

    def __eq__(self, value: object) -> bool:
        """
        Compares this `TransparencyLogEntry` with another object for equality.

        Two `TransparencyLogEntry` instances are considered equal if their
        inner contents are equal.
        """
        if not isinstance(value, TransparencyLogEntry):
            return NotImplemented
        return self._inner == value._inner

    @classmethod
    def _from_v1_response(cls, dict_: dict[str, Any]) -> TransparencyLogEntry:
        """
        Create a new `TransparencyLogEntry` from the given API response.
        """

        # Assumes we only get one entry back
        entries = list(dict_.items())
        if len(entries) != 1:
            raise ValueError("Received multiple entries in response")
        _, entry = entries[0]

        # Fill in the appropriate kind
        body_entry: ProposedEntry = TypeAdapter(ProposedEntry).validate_json(
            base64.b64decode(entry["body"])
        )
        if not isinstance(body_entry, Hashedrekord | Dsse):
            raise InvalidBundle("log entry is not of expected type")

        raw_inclusion_proof = entry["verification"]["inclusionProof"]

        # NOTE: The type ignores below are a consequence of our Pydantic
        # modeling: mypy and other typecheckers see `ProtoU64` as `int`,
        # but it gets coerced from a string due to Protobuf's JSON serialization.
        inner = _TransparencyLogEntry(
            log_index=str(entry["logIndex"]),  # type: ignore[arg-type]
            log_id=common_v1.LogId(
                key_id=base64.b64encode(bytes.fromhex(entry["logID"]))
            ),
            kind_version=rekor_v1.KindVersion(
                kind=body_entry.kind, version=body_entry.api_version
            ),
            integrated_time=str(entry["integratedTime"]),  # type: ignore[arg-type]
            inclusion_promise=rekor_v1.InclusionPromise(
                signed_entry_timestamp=entry["verification"]["signedEntryTimestamp"]
            ),
            inclusion_proof=rekor_v1.InclusionProof(
                log_index=str(raw_inclusion_proof["logIndex"]),  # type: ignore[arg-type]
                root_hash=base64.b64encode(
                    bytes.fromhex(raw_inclusion_proof["rootHash"])
                ),
                tree_size=str(raw_inclusion_proof["treeSize"]),  # type: ignore[arg-type]
                hashes=[
                    base64.b64encode(bytes.fromhex(h))
                    for h in raw_inclusion_proof["hashes"]
                ],
                checkpoint=rekor_v1.Checkpoint(
                    envelope=raw_inclusion_proof["checkpoint"]
                ),
            ),
            canonicalized_body=entry["body"],
        )

        return cls(inner)

    def _encode_canonical(self) -> bytes:
        """
        Returns a canonicalized JSON (RFC 8785) representation of the transparency log entry.

        This encoded representation is suitable for verification against
        the Signed Entry Timestamp.
        """
        # We might not have an integrated time if our log entry is from rekor
        # v2, i.e. was integrated synchronously instead of via an
        # inclusion promise.
        if self._inner.integrated_time is None:
            raise ValueError(
                "can't encode canonical form for SET without integrated time"
            )

        payload: dict[str, int | str] = {
            "body": base64.b64encode(self._inner.canonicalized_body).decode(),
            "integratedTime": self._inner.integrated_time,
            "logID": self._inner.log_id.key_id.hex(),
            "logIndex": self._inner.log_index,
        }

        return rfc8785.dumps(payload)

    def _verify_set(self, keyring: RekorKeyring) -> None:
        """
        Verify the inclusion promise (Signed Entry Timestamp) for a given transparency log
        `entry` using the given `keyring`.

        Fails if the given log entry does not contain an inclusion promise.
        """

        if self._inner.inclusion_promise is None:
            raise VerificationError("SET: invalid inclusion promise: missing")

        signed_entry_ts = self._inner.inclusion_promise.signed_entry_timestamp

        try:
            keyring.verify(
                key_id=KeyID(self._inner.log_id.key_id),
                signature=signed_entry_ts,
                data=self._encode_canonical(),
            )
        except VerificationError as exc:
            raise VerificationError(f"SET: invalid inclusion promise: {exc}")

    def _verify(self, keyring: RekorKeyring) -> None:
        """
        Verifies this log entry.

        This method performs steps (5), (6), and optionally (7) in
        the top-level verify API:

        * Verifies the consistency of the entry with the given bundle;
        * Verifies the Merkle inclusion proof and its signed checkpoint;
        * Verifies the inclusion promise, if present.
        """

        verify_merkle_inclusion(self)
        verify_checkpoint(keyring, self)

        _logger.debug(
            f"successfully verified inclusion proof: index={self._inner.log_index}"
        )

        if self._inner.inclusion_promise and self._inner.integrated_time:
            self._verify_set(keyring)
            _logger.debug(
                f"successfully verified inclusion promise: index={self._inner.log_index}"
            )
