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
Functionality for building and manipulating in-toto Statements and DSSE envelopes.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Literal, Union

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from pydantic import BaseModel, ConfigDict, Field, RootModel, StrictStr, ValidationError
from sigstore_protobuf_specs.io.intoto import Envelope, Signature

logger = logging.getLogger(__name__)

_Digest = Union[
    Literal["sha256"],
    Literal["sha384"],
    Literal["sha512"],
    Literal["sha3_256"],
    Literal["sha3_384"],
    Literal["sha3_512"],
]
"""
NOTE: in-toto's DigestSet contains all kinds of hash algorithms that
we intentionally do not support. This model is limited to common members of the
SHA-2 and SHA-3 family that are at least as strong as SHA-256.

See: <https://github.com/in-toto/attestation/blob/main/spec/v1/digest_set.md>
"""

_DigestSet = RootModel[Dict[_Digest, str]]
"""
An internal validation model for in-toto subject digest sets.
"""


class _Subject(BaseModel):
    """
    A single in-toto statement subject.
    """

    name: StrictStr | None
    digest: _DigestSet = Field(...)


class _Statement(BaseModel):
    """
    An internal validation model for in-toto statements.
    """

    model_config = ConfigDict(populate_by_name=True)

    type_: Literal["https://in-toto.io/Statement/v1"] = Field(..., alias="_type")
    subjects: list[_Subject] = Field(..., min_length=1, alias="subject")
    predicate_type: StrictStr = Field(..., alias="predicateType")
    predicate: dict[str, Any] | None = Field(None, alias="predicate")


class Statement:
    """
    Represents an in-toto statement.

    This type deals with opaque bytes to ensure that the encoding does not
    change, but Statements are internally checked for conformance against
    the JSON object layout defined in the in-toto attesation spec.

    See: <https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md>
    """

    _ENVELOPE_TYPE = "application/vnd.in-toto+json"

    def __init__(self, contents: bytes) -> None:
        """
        Construct a new Statement.

        This takes an opaque `bytes` containing the statement; use
        `StatementBuilder` to manually construct an in-toto statement
        from constituent pieces.
        """
        self._contents = contents
        try:
            self._statement = _Statement.model_validate_json(contents)
        except ValidationError:
            raise ValueError("malformed in-toto statement")

    def _pae(self) -> bytes:
        """
        Construct the PAE encoding for this statement.
        """

        # See:
        # https://github.com/secure-systems-lab/dsse/blob/v1.0.0/envelope.md
        # https://github.com/in-toto/attestation/blob/v1.0/spec/v1.0/envelope.md
        pae = f"DSSEv1 {len(Statement._ENVELOPE_TYPE)} {Statement._ENVELOPE_TYPE} ".encode()
        pae += b" ".join([str(len(self._contents)).encode(), self._contents])
        return pae

    def sign(self, key: ec.EllipticCurvePrivateKey) -> Envelope:
        """
        Sign the statement, returning a DSSE envelope containing the statement's
        signature.
        """

        pae = self._pae()
        logger.debug(f"DSSE PAE: {pae!r}")

        signature = key.sign(pae, ec.ECDSA(hashes.SHA256()))
        return Envelope(
            payload=self._contents,
            payload_type=Statement._ENVELOPE_TYPE,
            signatures=[Signature(sig=signature, keyid=None)],
        )


class _StatementBuilder:
    """
    A builder-style API for constructing in-toto Statements.
    """

    def __init__(
        self,
        subjects: list[_Subject] | None = None,
        predicate_type: str | None = None,
        predicate: dict[str, Any] | None = None,
    ):
        """
        Create a new `_StatementBuilder`.
        """
        self._subjects = subjects or []
        self._predicate_type = predicate_type
        self._predicate = predicate

    def subjects(self, subjects: list[_Subject]) -> _StatementBuilder:
        """
        Configure the subjects for this builder.
        """
        self._subjects = subjects
        return self

    def predicate_type(self, predicate_type: str) -> _StatementBuilder:
        """
        Configure the predicate type for this builder.
        """
        self._predicate_type = predicate_type
        return self

    def predicate(self, predicate: dict[str, Any]) -> _StatementBuilder:
        """
        Configure the predicate for this builder.
        """
        self._predicate = predicate
        return self

    def build(self) -> Statement:
        """
        Build a `Statement` from the builder's state.
        """
        try:
            stmt = _Statement(
                type_="https://in-toto.io/Statement/v1",
                subjects=self._subjects,
                predicate_type=self._predicate_type,
                predicate=self._predicate,
            )
        except ValidationError as e:
            raise ValueError(f"invalid statement: {e}")

        return Statement(stmt.model_dump_json(by_alias=True).encode())
