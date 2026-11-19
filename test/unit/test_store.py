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
from tuf.api.metadata import Metadata

from sigstore._utils import read_embedded


@pytest.mark.parametrize(
    "env",
    [
        "https://tuf-repo-cdn.sigstore.dev",
        "https://tuf-repo-cdn.sigstage.dev",
        "https://tuf.v2.sigstage.dev",
    ],
)
def test_store_reads_root_json(env):
    root_json = read_embedded("root.json", env)
    assert json.loads(root_json)
    md = Metadata.from_bytes(root_json)
    md.verify_delegate("root", md)


@pytest.mark.parametrize(
    "env",
    [
        "https://tuf-repo-cdn.sigstore.dev",
        "https://tuf-repo-cdn.sigstage.dev",
        "https://tuf.v2.sigstage.dev",
    ],
)
def test_store_reads_targets_json(env):
    trusted_root_json = read_embedded("trusted_root.json", env)
    assert json.loads(trusted_root_json)
    signing_config_json = read_embedded("signing_config.v0.2.json", env)
    assert json.loads(signing_config_json)
