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

import pytest
from pydantic import ValidationError

from sigstore._internal.rekor import client


class TestRekorInclusionProof:
    def test_valid(self):
        proof = client.RekorInclusionProof(
            log_index=1, root_hash="abcd", tree_size=2, hashes=[]
        )
        assert proof is not None

    def test_negative_log_index(self):
        with pytest.raises(
            ValidationError, match="Inclusion proof has invalid log index"
        ):
            client.RekorInclusionProof(
                log_index=-1, root_hash="abcd", tree_size=2, hashes=[]
            )

    def test_negative_tree_size(self):
        with pytest.raises(
            ValidationError, match="Inclusion proof has invalid tree size"
        ):
            client.RekorInclusionProof(
                log_index=1, root_hash="abcd", tree_size=-1, hashes=[]
            )

    def test_log_index_outside_tree_size(self):
        with pytest.raises(
            ValidationError,
            match="Inclusion proof has log index greater than or equal to tree size",
        ):
            client.RekorInclusionProof(
                log_index=2, root_hash="abcd", tree_size=1, hashes=[]
            )
