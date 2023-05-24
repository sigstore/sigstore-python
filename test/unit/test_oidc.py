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

from sigstore import oidc


class TestIdentityToken:
    def test_invalid_jwt(self):
        with pytest.raises(oidc.IdentityError, match="invalid identity token"):
            oidc.IdentityToken("invalid jwt")

    def test_missing_iss(self):
        # HS256 for testing, empty claim set
        jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.RX-vj8lcO2nwYZa_ALhrQkO55BGH-x4AOC0LzW7IFew"
        with pytest.raises(
            oidc.IdentityError, match="Identity token missing the required `iss` claim"
        ):
            oidc.IdentityToken(jwt)

    def test_missing_aud(self):
        # HS256 for testing, `{ "iss": "https://example.com" }`
        jwt = (
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2V4YW1wbGUuY29tIn0"
            ".ajiTV42uC6T7M9AH-gS0DyzpJoGY4xLXCSrL0U6ELmE"
        )
        with pytest.raises(
            oidc.IdentityError, match="Identity token missing the required `aud` claim"
        ):
            oidc.IdentityToken(jwt)

    def test_wrong_aud(self):
        # HS256 for testing, `{ "iss": "https://example.com", "aud": "notsigstore" }`
        jwt = (
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2V4YW1wbGUuY29tI"
            "iwiYXVkIjoibm90c2lnc3RvcmUifQ.vM6kUdGyaabfyYaQY3YfNhcR1Hy59rrdVKHFExWA0Bo"
        )
        with pytest.raises(
            oidc.IdentityError, match="Audience should be 'sigstore', not 'notsigstore'"
        ):
            oidc.IdentityToken(jwt)

    def test_known_issuer_missing_identity_claim(self):
        # HS256 for testing; no `email` claim
        #
        # {
        #   "iss": "https://accounts.google.com",
        #   "aud": "sigstore"
        # }
        jwt = (
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZ"
            "S5jb20iLCJhdWQiOiJzaWdzdG9yZSJ9.qcgUH_e0s7lg6wZuzwBT5SdB0SlbsZM6gk8li2OVOmg"
        )
        with pytest.raises(
            oidc.IdentityError,
            match="Identity token missing the required 'email' claim",
        ):
            oidc.IdentityToken(jwt)

    def test_known_issuer_ok(self):
        jwt = (
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5"
            "jb20iLCJhdWQiOiJzaWdzdG9yZSIsImVtYWlsIjoiZXhhbXBsZUBleGFtcGxlLmNvbSJ9.NDvzhMRf7O"
            "ueWpesIyqBFDkL9mGmcOK0S3UC3tMx_Ws"
        )
        token = oidc.IdentityToken(jwt)

        assert str(token) == jwt == token._raw_token
        assert token.identity == "example@example.com"
        assert token.issuer == "https://accounts.google.com"

    def test_unknown_issuer_missing_sub(self):
        # HS256 for testing; no `sub` claim
        #
        # {
        #  "iss": "https://example.com",
        #  "aud": "sigstore"
        # }
        jwt = (
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2V4YW1wbGUuY29tIiwiY"
            "XVkIjoic2lnc3RvcmUifQ.t3qwWcGfy5dj_NAFliPviVSmI3Us4mV9mEkDpKrgLn0"
        )
        with pytest.raises(
            oidc.IdentityError,
            match="Identity token missing the required 'sub' claim",
        ):
            oidc.IdentityToken(jwt)

    def test_unknown_issuer_ok(self):
        jwt = (
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2V4YW1wbGUuY29tIiwiYXV"
            "kIjoic2lnc3RvcmUiLCJzdWIiOiJzb21lLWlkZW50aXR5In0.xdmbAw5jagKqsHCUmwLyA7JR1fWo8nk"
            "8AHFVIJo-gfY"
        )
        token = oidc.IdentityToken(jwt)

        assert str(token) == jwt == token._raw_token
        assert token.identity == "some-identity"
        assert token.issuer == "https://example.com"
        assert token.expected_certificate_subject == "https://example.com"

    def test_unknown_issuer_federated_ok(self):
        jwt = (
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2V4YW1wbGUuY29tIiwiYXV"
            "kIjoic2lnc3RvcmUiLCJzdWIiOiJzb21lLWlkZW50aXR5IiwiZmVkZXJhdGVkX2NsYWltcyI6eyJjb25"
            "uZWN0b3JfaWQiOiJodHRwczovL290aGVyLmV4YW1wbGUuY29tIn19.EkpGq-4TZnHyxMaTd0AlEJrMtv"
            "wxJ8TZH_0qZ-8CfuE"
        )

        token = oidc.IdentityToken(jwt)

        assert str(token) == jwt == token._raw_token
        assert token.identity == "some-identity"
        assert token.issuer == "https://example.com"
        assert token.expected_certificate_subject == "https://other.example.com"
