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

import secrets

import pytest

from sigstore._internal.oidc.ambient import detect_credential
from sigstore._sign import Signer


def test_signer_production():
    signer = Signer.production()
    assert signer is not None


def test_signer_staging():
    signer = Signer.staging()
    assert signer is not None


@pytest.mark.online
@pytest.mark.ambient_oidc
@pytest.mark.parametrize("signer", [Signer.production(), Signer.staging()])
def test_sign_rekor_entry_consistent(signer):
    token = detect_credential()
    assert token is not None

    payload = secrets.token_bytes(32)
    expected_entry = signer.sign(payload, token).log_entry
    actual_entry = signer._rekor.log.entries.get(log_index=expected_entry.log_index)

    assert expected_entry.uuid == actual_entry.uuid
    assert expected_entry.body == actual_entry.body
    assert expected_entry.integrated_time == actual_entry.integrated_time
    assert expected_entry.log_id == actual_entry.log_id
    assert expected_entry.log_index == actual_entry.log_index
