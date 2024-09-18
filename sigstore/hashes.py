# Copyright 2023 The Sigstore Authors
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
Hashing APIs.
"""

import rekor_types
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from pydantic import BaseModel
from sigstore_protobuf_specs.dev.sigstore.common.v1 import HashAlgorithm

from sigstore.errors import Error


class Hashed(BaseModel, frozen=True):
    """
    Represents a hashed value.
    """

    algorithm: HashAlgorithm
    """
    The digest algorithm uses to compute the digest.
    """

    digest: bytes
    """
    The digest representing the hash value.
    """

    def _as_hashedrekord_algorithm(self) -> rekor_types.hashedrekord.Algorithm:
        """
        Returns an appropriate `hashedrekord.Algorithm` for this `Hashed`.
        """
        if self.algorithm == HashAlgorithm.SHA2_256:
            return rekor_types.hashedrekord.Algorithm.SHA256
        raise Error(f"unknown hash algorithm: {self.algorithm}")

    def _as_prehashed(self) -> Prehashed:
        """
        Returns an appropriate Cryptography `Prehashed` for this `Hashed`.
        """
        if self.algorithm == HashAlgorithm.SHA2_256:
            return Prehashed(hashes.SHA256())
        raise Error(f"unknown hash algorithm: {self.algorithm}")

    def __str__(self) -> str:
        """
        Returns a str representation of this `Hashed`.
        """
        return f"{self.algorithm.name}:{self.digest.hex()}"
