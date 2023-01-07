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

"""
API for retrieving OIDC tokens.
"""

from __future__ import annotations

import logging
import os
import time
import urllib.parse
import webbrowser
from typing import Callable, List, Optional

import requests

DEFAULT_OAUTH_ISSUER_URL = "https://oauth2.sigstore.dev/auth"
STAGING_OAUTH_ISSUER_URL = "https://oauth2.sigstage.dev/auth"


class IssuerError(Exception):
    """
    Raised on any communication or format error with an OIDC issuer.
    """

    pass


class Issuer:
    """
    Represents an OIDC issuer (IdP).
    """

    def __init__(self, base_url: str) -> None:
        """
        Create a new `Issuer` from the given base URL.

        This URL is used to locate an OpenID Connect configuration file,
        which is then used to bootstrap the issuer's state (such
        as authorization and token endpoints).
        """
        oidc_config_url = urllib.parse.urljoin(
            f"{base_url}/", ".well-known/openid-configuration"
        )

        resp: requests.Response = requests.get(oidc_config_url)
        try:
            resp.raise_for_status()
        except requests.HTTPError as http_error:
            raise IssuerError from http_error

        struct = resp.json()

        try:
            self.auth_endpoint: str = struct["authorization_endpoint"]
        except KeyError as key_error:
            raise IssuerError(
                f"OIDC configuration does not contain authorization endpoint: {struct}"
            ) from key_error

        try:
            self.token_endpoint: str = struct["token_endpoint"]
        except KeyError as key_error:
            raise IssuerError(
                f"OIDC configuration does not contain token endpoint: {struct}"
            ) from key_error

    @classmethod
    def production(cls) -> Issuer:
        """
        Returns an `Issuer` configured against Sigstore's production-level services.
        """
        return cls(DEFAULT_OAUTH_ISSUER_URL)

    @classmethod
    def staging(cls) -> Issuer:
        """
        Returns an `Issuer` configured against Sigstore's staging-level services.
        """
        return cls(STAGING_OAUTH_ISSUER_URL)

    def identity_token(  # nosec: B107
        self, client_id: str = "sigstore", client_secret: str = ""
    ) -> str:
        """
        Retrieves and returns an OpenID Connect token from the current `Issuer`, via OAuth.

        This function blocks on user interaction, either via a web browser or an out-of-band
        OAuth flow.
        """

        # This function and the components that it relies on are based off of:
        # https://github.com/psteniusubi/python-sample

        from sigstore._internal.oidc.oauth import _OAuthFlow

        force_oob = os.getenv("SIGSTORE_OAUTH_FORCE_OOB") is not None

        code: str
        with _OAuthFlow(client_id, client_secret, self) as server:
            # Launch web browser
            if not force_oob and webbrowser.open(server.base_uri):
                print("Waiting for browser interaction...")
            else:
                server.enable_oob()
                print(
                    f"Go to the following link in a browser:\n\n\t{server.auth_endpoint}"
                )

            if not server.is_oob():
                # Wait until the redirect server populates the response
                while server.auth_response is None:
                    time.sleep(0.1)

                auth_error = server.auth_response.get("error")
                if auth_error is not None:
                    raise IdentityError(
                        f"Error response from auth endpoint: {auth_error[0]}"
                    )
                code = server.auth_response["code"][0]
            else:
                # In the out-of-band case, we wait until the user provides the code
                code = input("Enter verification code: ")

        # Provide code to token endpoint
        data = {
            "grant_type": "authorization_code",
            "redirect_uri": server.redirect_uri,
            "code": code,
            "code_verifier": server.oauth_session.code_verifier,
        }
        auth = (
            client_id,
            client_secret,
        )
        logging.debug(f"PAYLOAD: data={data}")
        resp: requests.Response = requests.post(
            self.token_endpoint,
            data=data,
            auth=auth,
        )

        try:
            resp.raise_for_status()
        except requests.HTTPError as http_error:
            raise IdentityError from http_error

        token_json = resp.json()
        token_error = token_json.get("error")
        if token_error is not None:
            raise IdentityError(f"Error response from token endpoint: {token_error}")

        return str(token_json["access_token"])


class IdentityError(Exception):
    """
    Raised on any OIDC token format or claim error.
    """

    pass


class AmbientCredentialError(IdentityError):
    """
    Raised when an ambient credential should be present, but
    can't be retrieved (e.g. network failure).
    """

    pass


class GitHubOidcPermissionCredentialError(AmbientCredentialError):
    """
    Raised when the current GitHub Actions environment doesn't have permission
    to retrieve an OIDC token.
    """

    pass


def detect_credential() -> Optional[str]:
    """
    Try each ambient credential detector, returning the first one to succeed
    or `None` if all fail.

    Raises `AmbientCredentialError` if any detector fails internally (i.e.
    detects a credential, but cannot retrieve it).
    """
    from sigstore._internal.oidc.ambient import detect_gcp, detect_github

    detectors: List[Callable[..., Optional[str]]] = [detect_github, detect_gcp]
    for detector in detectors:
        credential = detector()
        if credential is not None:
            return credential
    return None
