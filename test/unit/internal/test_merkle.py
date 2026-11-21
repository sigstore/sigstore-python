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

import pretend
import pytest

from sigstore._internal.merkle import (
    _hash_children,
    _hash_leaf,
    verify_merkle_inclusion,
)
from sigstore.errors import VerificationError


def _entry(body, log_index, tree_size, hashes, root_hash):
    return pretend.stub(
        _inner=pretend.stub(
            canonicalized_body=body,
            inclusion_proof=pretend.stub(
                log_index=log_index,
                tree_size=tree_size,
                hashes=hashes,
                root_hash=root_hash,
            ),
        )
    )


def test_verify_merkle_inclusion_rejects_index_outside_tree():
    leaf0 = _hash_leaf(b"entry-0")
    root = _hash_children(leaf0, _hash_leaf(b"entry-1"))

    # Leaf 1 of a two-leaf tree.
    verify_merkle_inclusion(_entry(b"entry-1", 1, 2, [leaf0], root))

    # The same hashes also chain to the root when the proof claims index 1
    # in a tree of size 1, which is not a valid position.
    with pytest.raises(VerificationError, match="invalid log index"):
        verify_merkle_inclusion(_entry(b"entry-1", 1, 1, [leaf0], root))
