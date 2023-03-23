from __future__ import annotations

import base64
import hashlib
import re
from dataclasses import dataclass
from typing import List

from cryptography.exceptions import InvalidSignature
from pydantic import BaseModel, Field, StrictStr, validator

from sigstore._internal.rekor import RekorClient
from sigstore._utils import KeyID


@dataclass(frozen=True)
class Signature:
    """
    Represents a `Signature` containing:
    - the name of the signature, e.g. "rekor.sigstage.dev"
    - the signature hash
    - the base64 signature
    """

    # FIXME(jl): this does not feel like a de novo definition...
    # does this exist already in sigstore-python (or its depenencices)?
    _name: StrictStr
    _hash: bytes
    _signature: bytes


class Checkpoint(BaseModel):
    """
    Represents a `Checkpoint` containing:
    - an origin, e.g. "rekor.sigstage.dev - 8050909264565447525"
    - the size of the log,
    - the hash of the log,
    - and any ancillary contants, e.g. "Timestamp: 1679349379012118479"
    """

    origin: StrictStr
    log_size: int
    log_hash: StrictStr
    other_content: list[str]

    @classmethod
    def from_text(cls, text: str) -> Checkpoint:
        """
        Serialize from the text header ("note") of a SignedNote.

        A checkpoint contains:
        -
        """

        lines = text.strip().split("\n")
        if len(lines) < 4:
            raise ValueError("Malformed Checkpoint: too few items in header!")

        origin = lines[0]
        if len(origin) == 0:
            raise ValueError("Malformed Checkpoint: empty origin!")

        log_size = int(lines[1])
        root_hash = base64.b64decode(lines[2]).hex()

        return Checkpoint(
            origin=origin,
            log_size=log_size,
            log_hash=root_hash,
            other_content=lines[3:],
        )


class InvalidSignedNote(Exception):
    """
    Raised during SignedNote verification if invalid in some way.
    """

    pass


class SignedNote(BaseModel):
    """
    Represents a signed `Note` containing a note and its corresponding list of signatures.
    """

    note: StrictStr = Field(..., alias="note")
    signatures: list[Signature] = Field(..., alias="signatures")

    @validator("signatures")
    def _signatures_nonempty(cls, v: List[bytes]) -> List[bytes]:
        if len(v) == 0:
            raise ValueError("Inclusion proof signatures list is empty!")
        return v

    @classmethod
    def from_text(cls, text: str) -> SignedNote:
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
        if text.count(separator) != 1:
            raise ValueError(
                "Note must contain one blank line, deliniating the text from the signature block"
            )
        split = text.index(separator)

        header: str = text[: split + 1]
        data: str = text[split + len(separator) :]

        if len(data) == 0:
            raise ValueError("Malformed Note: must contain at least one signature!")
        if data[-1] != "\n":
            raise ValueError("Malformed Note: data section must end with newline!")

        sig_parser = re.compile(r"\u2014 (\S+) (\S+)\n")
        signatures: list[Signature] = []
        for (name, signature) in re.findall(sig_parser, data):
            signature_bytes: bytes = base64.b64decode(signature)
            if len(signature_bytes) < 5:
                raise ValueError("Malformed Note: signature contains too few bytes")

            signature = Signature(
                _name=name,
                # FIXME(jl): In Go, construct a big-endian UInt32 from 4 bytes. Is this equivalent?
                _hash=signature_bytes[0:4],
                _signature=base64.b64encode(signature_bytes[4:]),
            )
            signatures.append(signature)

        return cls(note=header, signatures=signatures)

    def verify(self, client: RekorClient) -> None:
        """
        Verify the SignedNote with using the given RekorClient by verifying each contained signature.
        """

        note = hashlib.sha256(self.note.encode("utf-8")).digest()

        # Grab the singular Rekor root public key as the signing key.
        key_id = list(client._rekor_keyring._keyring.keys())[0]

        for signature in self.signatures:
            try:
                client._rekor_keyring.verify(
                    key_id=KeyID(key_id),
                    signature=base64.b64decode(signature._signature),
                    data=note,
                )
            except InvalidSignature as inval_sig:
                raise InvalidSignedNote("invalid signature") from inval_sig


class SignedCheckpoint(BaseModel):
    """
    Represents a *signed* `Checkpoint`: a `Checkpoint` and its corresponding *signed* `Note`.
    """

    signed_note: SignedNote
    checkpoint: Checkpoint

    @classmethod
    def from_text(cls, text: str) -> SignedCheckpoint:
        """
        Create a new `SignedCheckpoint` from the text representation.
        """

        signed_note = SignedNote.from_text(text)
        checkpoint = Checkpoint.from_text(signed_note.note)
        return cls(signed_note=signed_note, checkpoint=checkpoint)
