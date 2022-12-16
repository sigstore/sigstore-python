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
Common (base) models for the verification APIs.
"""

from __future__ import annotations

import base64
import json
import logging
from dataclasses import dataclass
from typing import IO

from cryptography.x509 import Certificate, load_pem_x509_certificate
from pydantic import BaseModel

from sigstore._internal.rekor import RekorClient, RekorEntry
from sigstore._utils import base64_encode_pem_cert, sha256_streaming

logger = logging.getLogger(__name__)


class VerificationResult(BaseModel):
    """
    Represents the result of a verification operation.

    Results are boolish, and failures contain a reason (and potentially
    some additional context).
    """

    success: bool
    """
    Represents the status of this result.
    """

    def __bool__(self) -> bool:
        """
        Returns a boolean representation of this result.

        `VerificationSuccess` is always `True`, and `VerificationFailure`
        is always `False`.
        """
        return self.success


class VerificationSuccess(VerificationResult):
    """
    The verification completed successfully,
    """

    success: bool = True
    """
    See `VerificationResult.success`.
    """


class VerificationFailure(VerificationResult):
    """
    The verification failed, due to `reason`.
    """

    success: bool = False
    """
    See `VerificationResult.success`.
    """

    reason: str
    """
    A human-readable explanation or description of the verification failure.
    """


class RekorEntryMissing(Exception):
    """
    Raised if `VerificationMaterials.rekor_entry()` fails to find an entry
    in the Rekor log.

    This is an internal exception; users should not see it.
    """

    pass


class InvalidRekorEntry(Exception):
    """
    Raised if the effective Rekor entry in `VerificationMaterials.rekor_entry()`
    does not match the other materials in `VerificationMaterials`.

    This can only happen in two scenarios:

    * A user has supplied the wrong offline entry, potentially maliciously;
    * The Rekor log responded with the wrong entry, suggesting a server error.
    """

    pass


@dataclass(init=False)
class VerificationMaterials:
    """
    Represents the materials needed to perform a Sigstore verification.
    """

    input_digest: bytes
    """
    The SHA256 hash of the verification input, as raw bytes.
    """

    certificate: Certificate
    """
    The certificate that attests to and contains the public signing key.
    """

    signature: bytes
    """
    The raw signature.
    """

    _offline_rekor_entry: RekorEntry | None
    """
    An optional offline Rekor entry.

    If supplied an offline Rekor entry is supplied, verification will be done
    against this entry rather than the against the online transparency log.

    Offline Rekor entries do not carry their Merkle inclusion
    proofs, and as such are verified only against their Signed Entry Timestamps.
    This is a slightly weaker verification verification mode, as it does not
    demonstrate inclusion in the log.

    NOTE: This is **intentionally not a public field**. The `rekor_entry()`
    method should be used to access a Rekor log entry for these materials,
    as it performs the online lookup if an offline entry is not provided
    and, **critically**, validates that the entry's contents match the other
    signing materials. Without this check an adversary could present a
    **valid but unrelated** Rekor entry during verification, similar
    to CVE-2022-36056 in cosign.
    """

    def __init__(
        self,
        *,
        input_: IO[bytes],
        cert_pem: str,
        signature: bytes,
        offline_rekor_entry: RekorEntry | None,
    ):
        """
        Create a new `VerificationMaterials` from the given materials.

        Effect: `input_` is consumed as part of construction.
        """

        self.input_digest = sha256_streaming(input_)
        self.certificate = load_pem_x509_certificate(cert_pem.encode())
        self.signature = signature
        self._offline_rekor_entry = offline_rekor_entry

    @property
    def has_offline_rekor_entry(self) -> bool:
        """
        Returns whether or not these `VerificationMaterials` contain an offline Rekor
        entry.

        If false, `VerificationMaterials.rekor_entry()` performs an online lookup.
        """
        return self._offline_rekor_entry is not None

    def rekor_entry(self, client: RekorClient) -> RekorEntry:
        """
        Returns a `RekorEntry` for the current signing materials.
        """
        entry: RekorEntry | None
        if self._offline_rekor_entry is not None:
            logger.debug("using offline rekor entry")
            entry = self._offline_rekor_entry
        else:
            logger.debug("retrieving rekor entry")
            entry = client.log.entries.retrieve.post(
                self.signature,
                self.input_digest.hex(),
                self.certificate,
            )

        if entry is None:
            raise RekorEntryMissing

        # To verify that an entry matches our other signing materials,
        # we transform our signature, artifact hash, and certificate
        # into a "hashedrekord" style payload and compare it against the
        # entry's own body.
        #
        # This is done by:
        #
        # * Serializing the certificate as PEM, and then base64-encoding it;
        # * base64-encoding the signature;
        # * Packing the resulting cert, signature, and hash into the
        #   hashedrekord body format;
        # * Comparing that body against the entry's own body, which
        #   is extracted from its base64(json(...)) encoding.

        logger.debug("Rekor entry: ensuring contents match signing materials")

        expected_body = {
            "kind": "hashedrekord",
            "apiVersion": "0.0.1",
            "spec": {
                "signature": {
                    "content": base64.b64encode(self.signature).decode(),
                    "publicKey": {"content": base64_encode_pem_cert(self.certificate)},
                },
                "data": {
                    "hash": {"algorithm": "sha256", "value": self.input_digest.hex()}
                },
            },
        }

        actual_body = json.loads(base64.b64decode(entry.body))

        if expected_body != actual_body:
            raise InvalidRekorEntry

        return entry
