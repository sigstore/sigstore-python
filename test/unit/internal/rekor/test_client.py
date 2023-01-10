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

import json

import pytest
from pydantic import ValidationError

from sigstore._internal.rekor import client
from sigstore.transparency import LogInclusionProof


class TestRekorBundle:
    def test_parses_and_converts_to_log_entry(self, asset):
        path = asset("example.bundle")
        bundle = client.RekorBundle.parse_file(path)

        assert bundle.payload.integrated_time == 1624396085
        assert bundle.payload.log_index == 5179
        assert (
            bundle.payload.log_id
            == "c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d"
        )

        raw = json.loads(path.read_text())
        assert raw["SignedEntryTimestamp"] == bundle.signed_entry_timestamp
        assert raw["Payload"]["body"] == bundle.payload.body

        entry = bundle.to_entry()
        assert isinstance(entry, client.LogEntry)
        assert entry.uuid is None
        assert entry.body == bundle.payload.body
        assert entry.integrated_time == bundle.payload.integrated_time
        assert entry.log_id == bundle.payload.log_id
        assert entry.log_index == bundle.payload.log_index
        assert entry.inclusion_proof is None
        assert entry.signed_entry_timestamp == bundle.signed_entry_timestamp

        # Round-tripping from RekorBundle -> RekorEntry -> RekorBundle is lossless.
        assert client.RekorBundle.from_entry(entry) == bundle


class TestRekorInclusionProof:
    def test_valid(self):
        proof = LogInclusionProof(log_index=1, root_hash="abcd", tree_size=2, hashes=[])
        assert proof is not None

    def test_negative_log_index(self):
        with pytest.raises(
            ValidationError, match="Inclusion proof has invalid log index"
        ):
            LogInclusionProof(log_index=-1, root_hash="abcd", tree_size=2, hashes=[])

    def test_negative_tree_size(self):
        with pytest.raises(
            ValidationError, match="Inclusion proof has invalid tree size"
        ):
            LogInclusionProof(log_index=1, root_hash="abcd", tree_size=-1, hashes=[])

    def test_log_index_outside_tree_size(self):
        with pytest.raises(
            ValidationError,
            match="Inclusion proof has log index greater than or equal to tree size",
        ):
            LogInclusionProof(log_index=2, root_hash="abcd", tree_size=1, hashes=[])
