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

from unittest.mock import MagicMock, patch

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
        Issuer.staging().identity_token(force_oob=True)


def test_identity_token_csrf_protection():
    """
    Verify that identity_token() raises IdentityError when the returned state
    does not match the session state (CSRF protection).
    """
    with (
        patch("sigstore.oidc.webbrowser.open"),
        patch("sigstore._internal.oidc.oauth._OAuthFlow") as MockOAuthFlow,
        patch("sigstore.oidc.requests.Session") as MockSession,
        patch("sigstore.oidc.IdentityToken"),
    ):
        # Setup the mock server returned by _OAuthFlow context manager
        mock_server = MagicMock()
        MockOAuthFlow.return_value.__enter__.return_value = mock_server

        # Simulate a mismatching state
        original_state = "original-secure-state"
        malicious_state = "malicious-state"

        # The session has the original state (we mock the property access)
        # Since we added a property 'state', we need to make sure the mock returns it.
        # But here we are mocking the whole server object.
        # server.oauth_session.state
        mock_server.oauth_session.state = original_state

        mock_server.is_oob.return_value = False
        mock_server.base_uri = "http://localhost:12345"
        mock_server.redirect_uri = "http://localhost:12345/callback"

        # The auth response simulates what the redirect handler receives
        mock_server.auth_response = {
            "code": ["fake-code"],
            "state": [malicious_state],
        }

        # Mock responses for Issuer initialization and token exchange
        mock_session_instance = MockSession.return_value

        # Mock .well-known/openid-configuration response
        mock_config_response = MagicMock()
        mock_config_response.json.return_value = {
            "authorization_endpoint": "https://auth.example.com",
            "token_endpoint": "https://token.example.com",
        }
        mock_config_response.raise_for_status.return_value = None

        mock_session_instance.get.side_effect = [mock_config_response]

        # Initialize Issuer
        issuer = Issuer("https://issuer.example.com")

        # Call identity_token() and expect IdentityError due to state mismatch
        with pytest.raises(IdentityError, match="OAuth state mismatch"):
            issuer.identity_token()
