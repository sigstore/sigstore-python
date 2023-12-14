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

import pretend
import pytest

from sigstore._internal.rekor.client import RekorClient
from sigstore._internal.trustroot import CustomTrustedRoot
from sigstore.verify.models import (
    InvalidMaterials,
    InvalidRekorEntry,
    RekorEntryMissing,
    VerificationMaterials,
)


class TestVerificationMaterials:
    def test_rekor_entry_inconsistent_cve_2022_36056(
        self, signing_materials, signing_bundle
    ):
        a_materials = signing_materials("a.txt")
        offline_rekor_materials = signing_bundle("bundle.txt")

        # Stuff a valid but incompatible Rekor entry into the verification
        # materials for "a.txt".
        a_materials._rekor_entry = offline_rekor_materials._rekor_entry
        a_materials._offline = True

        with pytest.raises(InvalidRekorEntry):
            a_materials.rekor_entry(pretend.stub())

    @pytest.mark.online
    def test_verification_materials_retrieves_rekor_entry(self, signing_materials):
        materials = signing_materials("a.txt")
        assert materials._rekor_entry is None

        trust_root = CustomTrustedRoot.staging()
        client = RekorClient.staging(trust_root)
        entry = materials.rekor_entry(client)
        assert entry is not None

    def test_rekor_entry_missing(self, signing_materials):
        a_materials = signing_materials("a.txt")

        # stub retriever post returning None RekorEntry
        a_materials._rekor_entry = None
        client = pretend.stub(
            log=pretend.stub(
                entries=pretend.stub(retrieve=pretend.stub(post=lambda a: None))
            )
        )

        with pytest.raises(RekorEntryMissing):
            a_materials.rekor_entry(client)

    def test_verification_materials_offline_no_log_entry(self, signing_materials):
        with pytest.raises(
            InvalidMaterials, match="offline verification requires a Rekor entry"
        ):
            signing_materials("a.txt", offline=True)

    def test_verification_materials_bundle_no_cert(self, signing_bundle):
        with pytest.raises(
            InvalidMaterials, match="expected non-empty certificate chain in bundle"
        ):
            signing_bundle("bundle_no_cert.txt")

    def test_verification_materials_bundle_no_log_entry(self, signing_bundle):
        with pytest.raises(
            InvalidMaterials, match="expected exactly one log entry, got 0"
        ):
            signing_bundle("bundle_no_log_entry.txt")

    def test_verification_materials_offline_no_checkpoint(self, signing_bundle):
        with pytest.raises(
            InvalidMaterials, match="expected checkpoint in inclusion proof"
        ):
            signing_bundle("bundle_no_checkpoint.txt", offline=True)

    def test_verification_materials_to_bundle_round_trip(self, asset, signing_bundle):
        bundle = signing_bundle("bundle.txt").to_bundle()

        with asset("bundle.txt").open(mode="rb", buffering=0) as io:
            round_tripped_bundle = VerificationMaterials.from_bundle(
                input_=io, bundle=bundle, offline=True
            ).to_bundle()

        assert bundle == round_tripped_bundle

    def test_verification_materials_to_bundle_no_rekor_entry(
        self, asset, signing_materials
    ):
        materials = signing_materials("bundle.txt")

        with pytest.raises(
            InvalidMaterials,
            match="Must have Rekor entry before converting to a Bundle",
        ):
            materials.to_bundle()
