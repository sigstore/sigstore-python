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

from sigstore.verify.models import Bundle, InvalidBundle


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
