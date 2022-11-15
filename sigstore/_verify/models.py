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

import hashlib
from dataclasses import dataclass

from cryptography.x509 import Certificate, load_pem_x509_certificate
from pydantic import BaseModel

from sigstore._internal.rekor import RekorEntry


class VerificationResult(BaseModel):
    """
    Represents the result of a verification operation.

    Results are boolish, and failures contain a reason (and potentially
    some additional context).
    """

    success: bool

    def __bool__(self) -> bool:
        return self.success


class VerificationSuccess(VerificationResult):
    """
    The verification completed successfully,
    """

    success: bool = True


class VerificationFailure(VerificationResult):
    """
    The verification failed, due to `reason`.
    """

    success: bool = False
    reason: str


@dataclass(init=False)
class VerificationMaterials:
    """
    Represents the materials needed to perform a Sigstore verification.
    """

    input_: bytes
    """
    The input that was signed for.
    """

    artifact_hash: str
    """
    The hex-encoded SHA256 hash of `input_`.
    """

    certificate: Certificate
    """
    The certificate that attests to and contains the public signing key.
    """

    signature: bytes
    """
    The raw signature.
    """

    offline_rekor_entry: RekorEntry | None
    """
    An optional offline Rekor entry.

    If supplied an offline Rekor entry is supplied, verification will be done
    against this entry rather than the against the online transparency log.

    Offline Rekor entries do not carry their Merkle inclusion
    proofs, and as such are verified only against their Signed Entry Timestamps.
    This is a slightly weaker verification verification mode, as it does not
    demonstrate inclusion in the log.
    """

    def __init__(
        self,
        *,
        input_: bytes,
        cert_pem: str,
        signature: bytes,
        offline_rekor_entry: RekorEntry | None,
    ):
        self.input_ = input_
        self.artifact_hash = hashlib.sha256(self.input_).hexdigest()
        self.certificate = load_pem_x509_certificate(cert_pem.encode())
        self.signature = signature
        self.offline_rekor_entry = offline_rekor_entry
