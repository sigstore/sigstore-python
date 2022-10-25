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

from sigstore._internal.ctfe import CTKeyring


class TestCTKeyring:
    def test_keyring_cardinalities(self):
        production = CTKeyring.production()
        staging = CTKeyring.staging()

        assert len(production._keyring) == 2
        assert len(staging._keyring) == 3

    def test_production_staging_both_initialize(self):
        keyrings = [CTKeyring.production(), CTKeyring.staging()]
        for keyring in keyrings:
            assert keyring is not None

    def test_production_staging_keyrings_are_disjoint(self):
        production = CTKeyring.production()
        staging = CTKeyring.staging()

        production_key_ids = production._keyring.keys()
        staging_key_ids = staging._keyring.keys()

        # The key IDs (and therefore keys) in the production and staging instances
        # should never overlap. Overlapping would imply loading keys intended
        # for the wrong instance.
        assert production_key_ids.isdisjoint(staging_key_ids)
