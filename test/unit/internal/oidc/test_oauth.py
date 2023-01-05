# Copyright 2023 The Sigstore Authors
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

from sigstore._internal.oidc import oauth
from sigstore._internal.oidc.issuer import Issuer


@pytest.mark.online
def test_get_identity_token_token_error(monkeypatch):
    import requests

    monkeypatch.setenv("SIGSTORE_OAUTH_FORCE_OOB", "")
    monkeypatch.setattr("builtins.input", pretend.call_recorder(lambda _: "hunter2"))
    monkeypatch.setattr(
        requests.Response, "raise_for_status", pretend.call_recorder(lambda _: None)
    )

    with pytest.raises(
        oauth.IdentityError, match="Error response from token endpoint: invalid_grant"
    ):
        oauth.get_identity_token(
            client_id="sigstore",
            client_secret="",
            issuer=Issuer(oauth.DEFAULT_OAUTH_ISSUER),
        )


@pytest.mark.online
def test_get_identity_token_http_error(monkeypatch):
    monkeypatch.setenv("SIGSTORE_OAUTH_FORCE_OOB", "")
    monkeypatch.setattr("builtins.input", pretend.call_recorder(lambda _: "hunter2"))

    with pytest.raises(oauth.IdentityError):
        oauth.get_identity_token(
            client_id="sigstore",
            client_secret="",
            issuer=Issuer(oauth.DEFAULT_OAUTH_ISSUER),
        )
