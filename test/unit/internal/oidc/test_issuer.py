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

import pytest

from sigstore.oidc import IdentityError, Issuer, IssuerError


@pytest.mark.online
def test_fail_init_url():
    with pytest.raises(IssuerError):
        Issuer("https://google.com")


@pytest.mark.online
def test_init_url():
    Issuer("https://accounts.google.com")


@pytest.mark.online
def test_get_identity_token_bad_code(monkeypatch):
    monkeypatch.setattr("builtins.input", lambda _: "hunter2")

    with pytest.raises(IdentityError, match=r"^Token request failed with .+$"):
        Issuer("https://oauth2.sigstage.dev/auth").identity_token(force_oob=True)
