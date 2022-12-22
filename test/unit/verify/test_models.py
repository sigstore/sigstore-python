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
from sigstore._internal.tuf import TrustUpdater
from sigstore._verify.models import InvalidRekorEntry


class TestVerificationMaterials:
    def test_rekor_entry_inconsistent_cve_2022_36056(self, signing_materials):
        a_materials = signing_materials("a.txt")
        offline_rekor_materials = signing_materials("offline-rekor.txt")

        # Stuff a valid but incompatible Rekor entry into the verification
        # materials for "a.txt".
        a_materials._offline_rekor_entry = offline_rekor_materials._offline_rekor_entry

        with pytest.raises(InvalidRekorEntry):
            a_materials.rekor_entry(pretend.stub())

    @pytest.mark.online
    def test_verification_materials_retrieves_rekor_entry(self, signing_materials):
        materials = signing_materials("a.txt")
        assert materials._offline_rekor_entry is None

        tuf = TrustUpdater.staging()
        client = RekorClient.staging(tuf)
        entry = materials.rekor_entry(client)
        assert entry is not None
