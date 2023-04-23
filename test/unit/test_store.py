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

from sigstore._utils import read_embedded


@pytest.mark.parametrize("env", ["prod", "staging"])
def test_store_reads_root_json(env):
    root_json = read_embedded("root.json", env)
    assert json.loads(root_json)


@pytest.mark.parametrize("env", ["prod", "staging"])
def test_store_reads_targets_json(env):
    trusted_root_json = read_embedded("trusted_root.json", env)
    assert json.loads(trusted_root_json)
