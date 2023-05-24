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

import datetime
import time
import pytest

from sigstore import oidc


class TestIdentityToken:
    def test_invalid_jwt(self):
        with pytest.raises(
            oidc.IdentityError, match="Identity token is malformed or missing claims"
        ):
            oidc.IdentityToken("invalid jwt")

    def test_missing_iss(self, dummy_jwt):
        now = int(datetime.datetime.now().timestamp())
        jwt = dummy_jwt(
            {
                "aud": "sigstore",
                "iat": now,
                "nbf": now,
                "exp": now + 600,
            }
        )

        with pytest.raises(
            oidc.IdentityError, match="Identity token is malformed or missing claims"
        ):
            oidc.IdentityToken(jwt)

    def test_missing_aud(self, dummy_jwt):
        now = int(datetime.datetime.now().timestamp())
        jwt = dummy_jwt(
            {
                "iat": now,
                "nbf": now,
                "exp": now + 600,
                "iss": "fake-issuer",
            }
        )

        with pytest.raises(
            oidc.IdentityError, match="Identity token is malformed or missing claims"
        ):
            oidc.IdentityToken(jwt)

    @pytest.mark.parametrize("aud", (None, "not-sigstore"))
    def test_invalid_aud(self, dummy_jwt, aud):
        now = int(datetime.datetime.now().timestamp())
        jwt = dummy_jwt(
            {
                "aud": aud,
                "iat": now,
                "nbf": now,
                "exp": now + 600,
                "iss": "fake-issuer",
            }
        )

        with pytest.raises(
            oidc.IdentityError, match="Identity token is malformed or missing claims"
        ):
            oidc.IdentityToken(jwt)

    def test_missing_iat(self, dummy_jwt):
        now = int(datetime.datetime.now().timestamp())
        jwt = dummy_jwt(
            {
                "aud": "sigstore",
                "nbf": now,
                "exp": now + 600,
                "iss": "fake-issuer",
            }
        )

        with pytest.raises(
            oidc.IdentityError, match="Identity token is malformed or missing claims"
        ):
            oidc.IdentityToken(jwt)

    @pytest.mark.parametrize("iat", (None, "not-an-int"))
    def test_invalid_iat(self, dummy_jwt, iat):
        now = int(datetime.datetime.now().timestamp())
        jwt = dummy_jwt(
            {
                "aud": "sigstore",
                "iat": iat,
                "nbf": now,
                "exp": now + 600,
                "iss": "fake-issuer",
            }
        )

        with pytest.raises(
            oidc.IdentityError, match="Identity token is malformed or missing claims"
        ):
            oidc.IdentityToken(jwt)

    def test_missing_nbf(self, dummy_jwt):
        now = int(datetime.datetime.now().timestamp())
        jwt = dummy_jwt(
            {
                "aud": "sigstore",
                "iat": now,
                "exp": now + 600,
                "iss": "fake-issuer",
            }
        )

        with pytest.raises(
            oidc.IdentityError, match="Identity token is malformed or missing claims"
        ):
            oidc.IdentityToken(jwt)

    def test_invalid_nbf(self, dummy_jwt):
        now = int(datetime.datetime.now().timestamp())
        jwt = dummy_jwt(
            {
                "aud": "sigstore",
                "iat": now,
                "nbf": now + 600,
                "exp": now + 601,
                "iss": "fake-issuer",
            }
        )

        with pytest.raises(
            oidc.IdentityError, match="Identity token is malformed or missing claims"
        ):
            oidc.IdentityToken(jwt)

    def test_missing_exp(self, dummy_jwt):
        now = int(datetime.datetime.now().timestamp())
        jwt = dummy_jwt(
            {
                "aud": "sigstore",
                "iat": now,
                "nbf": now,
                "iss": "fake-issuer",
            }
        )

        with pytest.raises(
            oidc.IdentityError, match="Identity token is malformed or missing claims"
        ):
            oidc.IdentityToken(jwt)

    def test_invalid_exp(self, dummy_jwt):
        now = int(datetime.datetime.now().timestamp())
        jwt = dummy_jwt(
            {
                "aud": "sigstore",
                "iat": now - 600,
                "nbf": now - 300,
                "exp": now - 1,
                "iss": "fake-issuer",
            }
        )

        with pytest.raises(
            oidc.IdentityError, match="Identity token is malformed or missing claims"
        ):
            oidc.IdentityToken(jwt)

    @pytest.mark.parametrize("iss", oidc._KNOWN_OIDC_ISSUERS.keys())
    def test_missing_identity_claim(self, dummy_jwt, iss):
        now = int(datetime.datetime.now().timestamp())
        jwt = dummy_jwt(
            {
                "aud": "sigstore",
                "iat": now,
                "nbf": now,
                "exp": now + 600,
                "iss": iss,
            }
        )

        with pytest.raises(
            oidc.IdentityError,
            match=r"Identity token is missing the required '.+' claim",
        ):
            oidc.IdentityToken(jwt)

    @pytest.mark.parametrize("fed", ("notadict", {"connector_id": 123}))
    def test_invalid_federated_claims(self, dummy_jwt, fed):
        now = int(datetime.datetime.now().timestamp())
        jwt = dummy_jwt(
            {
                "aud": "sigstore",
                "iat": now,
                "nbf": now,
                "exp": now + 600,
                "iss": "https://accounts.google.com",
                "email": "example@example.com",
                "federated_claims": fed,
            }
        )

        with pytest.raises(
            oidc.IdentityError,
            match="unexpected claim type: federated_claims.*",
        ):
            oidc.IdentityToken(jwt)

    @pytest.mark.parametrize(
        ("iss", "identity_claim", "identity_value", "fed_iss"),
        [
            ("https://accounts.google.com", "email", "example@example.com", None),
            (
                "https://oauth2.sigstore.dev/auth",
                "email",
                "example@example.com",
                "https://accounts.google.com",
            ),
            ("https://oauth2.sigstore.dev/auth", "email", "example@example.com", None),
            (
                "https://token.actions.githubusercontent.com",
                "sub",
                "some-subject",
                None,
            ),
            ("hxxps://unknown.issuer.example.com/auth", "sub", "some-subject", None),
        ],
    )
    def test_ok(self, dummy_jwt, iss, identity_claim, identity_value, fed_iss):
        now = int(datetime.datetime.now().timestamp())
        jwt = dummy_jwt(
            {
                "aud": "sigstore",
                "iat": now,
                "nbf": now,
                "exp": now + 600,
                "iss": iss,
                identity_claim: identity_value,
                "federated_claims": {"connector_id": fed_iss},
            }
        )

        identity = oidc.IdentityToken(jwt)
        assert identity.in_validity_period()
        assert identity.identity == identity_value
        assert identity.issuer == iss
        assert identity.expected_certificate_subject == iss if not fed_iss else fed_iss
