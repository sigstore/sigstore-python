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
from typing import Any, Dict, List, Literal, Optional, Union

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from pydantic import BaseModel, ConfigDict, Field, RootModel, StrictStr, ValidationError
from sigstore_protobuf_specs.dev.sigstore.common.v1 import HashAlgorithm
from sigstore_protobuf_specs.io.intoto import Envelope as _Envelope
from sigstore_protobuf_specs.io.intoto import Signature

from sigstore.errors import Error, VerificationError
from sigstore.hashes import Hashed

_logger = logging.getLogger(__name__)

Digest = Union[
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

DigestSet = RootModel[Dict[Digest, str]]
"""
An internal validation model for in-toto subject digest sets.
"""


class Subject(BaseModel):
    """
    A single in-toto statement subject.
    """

    name: Optional[StrictStr]
    digest: DigestSet = Field(...)


class _Statement(BaseModel):
    """
    An internal validation model for in-toto statements.
    """

    model_config = ConfigDict(populate_by_name=True)

    type_: Literal["https://in-toto.io/Statement/v1"] = Field(..., alias="_type")
    subjects: List[Subject] = Field(..., min_length=1, alias="subject")
    predicate_type: StrictStr = Field(..., alias="predicateType")
    predicate: Optional[Dict[str, Any]] = Field(None, alias="predicate")


class Statement:
    """
    Represents an in-toto statement.

    This type deals with opaque bytes to ensure that the encoding does not
    change, but Statements are internally checked for conformance against
    the JSON object layout defined in the in-toto attestation spec.

    See: <https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md>
    """

    def __init__(self, contents: bytes | _Statement) -> None:
        """
        Construct a new Statement.

        This takes an opaque `bytes` containing the statement; use
        `StatementBuilder` to manually construct an in-toto statement
        from constituent pieces.
        """
        if isinstance(contents, bytes):
            self._contents = contents
            try:
                self._inner = _Statement.model_validate_json(contents)
            except ValidationError:
                raise Error("malformed in-toto statement")
        else:
            self._contents = contents.model_dump_json(by_alias=True).encode()
            self._inner = contents

    def _matches_digest(self, digest: Hashed) -> bool:
        """
        Returns a boolean indicating whether this in-toto Statement contains a subject
        matching the given digest. The subject's name is **not** checked.

        No digests other than SHA256 are currently supported.
        """
        if digest.algorithm != HashAlgorithm.SHA2_256:
            raise VerificationError(f"unexpected digest algorithm: {digest.algorithm}")

        for sub in self._inner.subjects:
            sub_digest = sub.digest.root.get("sha256")
            if sub_digest is None:
                continue
            if sub_digest == digest.digest.hex():
                return True

        return False

    def _pae(self) -> bytes:
        """
        Construct the PAE encoding for this statement.
        """

        return _pae(Envelope._TYPE, self._contents)


class StatementBuilder:
    """
    A builder-style API for constructing in-toto Statements.
    """

    def __init__(
        self,
        subjects: Optional[List[Subject]] = None,
        predicate_type: Optional[str] = None,
        predicate: Optional[Dict[str, Any]] = None,
    ):
        """
        Create a new `StatementBuilder`.
        """
        self._subjects = subjects or []
        self._predicate_type = predicate_type
        self._predicate = predicate

    def subjects(self, subjects: list[Subject]) -> StatementBuilder:
        """
        Configure the subjects for this builder.
        """
        self._subjects = subjects
        return self

    def predicate_type(self, predicate_type: str) -> StatementBuilder:
        """
        Configure the predicate type for this builder.
        """
        self._predicate_type = predicate_type
        return self

    def predicate(self, predicate: dict[str, Any]) -> StatementBuilder:
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
            raise Error(f"invalid statement: {e}")

        return Statement(stmt)


class InvalidEnvelope(Error):
    """
    Raised when the associated `Envelope` is invalid in some way.
    """


class Envelope:
    """
    Represents a DSSE envelope.

    This class cannot be constructed directly; you must use `sign` or `from_json`.

    See: <https://github.com/secure-systems-lab/dsse/blob/v1.0.0/envelope.md>
    """

    _TYPE = "application/vnd.in-toto+json"

    def __init__(self, inner: _Envelope) -> None:
        """
        @private
        """

        self._inner = inner
        self._verify()

    def _verify(self) -> None:
        """
        Verify and load the Envelope.
        """
        if len(self._inner.signatures) != 1:
            raise InvalidEnvelope("envelope must contain exactly one signature")

        if not self._inner.signatures[0].sig:
            raise InvalidEnvelope("envelope signature must be non-empty")

        self._signature_bytes = self._inner.signatures[0].sig

    @classmethod
    def _from_json(cls, contents: bytes | str) -> Envelope:
        """Return a DSSE envelope from the given JSON representation."""
        inner = _Envelope().from_json(contents)
        return cls(inner)

    def to_json(self) -> str:
        """
        Return a JSON string with this DSSE envelope's contents.
        """
        return self._inner.to_json()

    def __eq__(self, other: object) -> bool:
        """Equality for DSSE envelopes."""

        if not isinstance(other, Envelope):
            return NotImplemented

        return self._inner == other._inner

    @property
    def signature(self) -> bytes:
        """Return the decoded bytes of the Envelope signature."""
        return self._signature_bytes


def _pae(type_: str, body: bytes) -> bytes:
    """
    Compute the PAE encoding for the given `type_` and `body`.
    """

    # See:
    # https://github.com/secure-systems-lab/dsse/blob/v1.0.0/envelope.md
    # https://github.com/in-toto/attestation/blob/v1.0/spec/v1.0/envelope.md
    pae = f"DSSEv1 {len(type_)} {type_} ".encode()
    pae += b" ".join([str(len(body)).encode(), body])
    return pae


def _sign(key: ec.EllipticCurvePrivateKey, stmt: Statement) -> Envelope:
    """
    Sign for the given in-toto `Statement`, and encapsulate the resulting
    signature in a DSSE `Envelope`.
    """
    pae = stmt._pae()
    _logger.debug(f"DSSE PAE: {pae!r}")

    signature = key.sign(pae, ec.ECDSA(hashes.SHA256()))
    return Envelope(
        _Envelope(
            payload=stmt._contents,
            payload_type=Envelope._TYPE,
            signatures=[Signature(sig=signature)],
        )
    )


def _verify(key: ec.EllipticCurvePublicKey, evp: Envelope) -> bytes:
    """
    Verify the given in-toto `Envelope`, returning the verified inner payload.

    This function does **not** check the envelope's payload type. The caller
    is responsible for performing this check.
    """

    pae = _pae(evp._inner.payload_type, evp._inner.payload)

    nsigs = len(evp._inner.signatures)
    if nsigs != 1:
        raise VerificationError(f"DSSE: exactly 1 signature allowed, got {nsigs}")

    signature = evp._inner.signatures[0].sig

    try:
        key.verify(signature, pae, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        raise VerificationError("DSSE: invalid signature")

    return evp._inner.payload
