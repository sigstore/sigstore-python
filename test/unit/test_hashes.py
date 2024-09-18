# Copyright 2024 The Sigstore Authors
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
import hashlib

import pytest
from sigstore_protobuf_specs.dev.sigstore.common.v1 import HashAlgorithm

from sigstore.hashes import Hashed


class TestHashes:
    @pytest.mark.parametrize(
        ("algorithm", "digest"),
        [
            (HashAlgorithm.SHA2_256, hashlib.sha256(b"").hexdigest()),
            (HashAlgorithm.SHA2_384, hashlib.sha384(b"").hexdigest()),
            (HashAlgorithm.SHA2_512, hashlib.sha512(b"").hexdigest()),
            (HashAlgorithm.SHA3_256, hashlib.sha3_256(b"").hexdigest()),
            (HashAlgorithm.SHA3_384, hashlib.sha3_384(b"").hexdigest()),
        ],
    )
    def test_hashed_repr(self, algorithm, digest):
        hashed = Hashed(algorithm=algorithm, digest=bytes.fromhex(digest))
        assert str(hashed) == f"{algorithm.name}:{digest}"
