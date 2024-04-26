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
from base64 import b64encode

import pytest
from pydantic import ValidationError

from sigstore.models import Bundle, InvalidBundle, LogEntry, LogInclusionProof


class TestLogEntry:
    def test_missing_inclusion_proof(self):
        with pytest.raises(ValueError, match=r"inclusion_proof"):
            LogEntry(
                uuid="fake",
                body=b64encode("fake".encode()),
                integrated_time=0,
                log_id="1234",
                log_index=1,
                inclusion_proof=None,
                inclusion_promise=None,
            )


class TestLogInclusionProof:
    def test_valid(self):
        proof = LogInclusionProof(
            log_index=1, root_hash="abcd", tree_size=2, hashes=[], checkpoint=""
        )
        assert proof is not None

    def test_negative_log_index(self):
        with pytest.raises(
            ValidationError, match="Inclusion proof has invalid log index"
        ):
            LogInclusionProof(
                log_index=-1, root_hash="abcd", tree_size=2, hashes=[], checkpoint=""
            )

    def test_negative_tree_size(self):
        with pytest.raises(
            ValidationError, match="Inclusion proof has invalid tree size"
        ):
            LogInclusionProof(
                log_index=1, root_hash="abcd", tree_size=-1, hashes=[], checkpoint=""
            )

    def test_log_index_outside_tree_size(self):
        with pytest.raises(
            ValidationError,
            match="Inclusion proof has log index greater than or equal to tree size",
        ):
            LogInclusionProof(
                log_index=2, root_hash="abcd", tree_size=1, hashes=[], checkpoint=""
            )

    def test_checkpoint_missing(self):
        with pytest.raises(ValidationError, match=r"should be a valid string"):
            (
                LogInclusionProof(
                    checkpoint=None,
                    hashes=["fake"],
                    log_index=0,
                    root_hash="fake",
                    tree_size=100,
                ),
            )


class TestBundle:
    """
    Tests for the `Bundle` wrapper model.
    """

    def test_invalid_bundle_version(self, signing_bundle):
        with pytest.raises(InvalidBundle, match="unsupported bundle format"):
            signing_bundle("bundle_invalid_version.txt")

    def test_invalid_empty_cert_chain(self, signing_bundle):
        with pytest.raises(
            InvalidBundle, match="expected non-empty certificate chain in bundle"
        ):
            signing_bundle("bundle_no_cert_v1.txt")

    def test_invalid_no_log_entry(self, signing_bundle):
        with pytest.raises(
            InvalidBundle, match="expected exactly one log entry in bundle"
        ):
            signing_bundle("bundle_no_log_entry.txt")

    def test_verification_materials_offline_no_checkpoint(self, signing_bundle):
        with pytest.raises(
            InvalidBundle, match="expected checkpoint in inclusion proof"
        ):
            signing_bundle("bundle_no_checkpoint.txt")

    def test_bundle_roundtrip(self, signing_bundle):
        _, bundle = signing_bundle("bundle.txt")

        # Bundles are not directly comparable, but a round-trip preserves their
        # underlying object structure.
        assert json.loads(Bundle.from_json(bundle.to_json()).to_json()) == json.loads(
            bundle.to_json()
        )
