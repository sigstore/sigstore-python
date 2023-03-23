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
import sys
import time
import urllib.parse
import webbrowser
from typing import NoReturn, Optional, cast

import id
import requests
from pydantic import BaseModel, StrictStr

from sigstore.errors import Error, NetworkError

DEFAULT_OAUTH_ISSUER_URL = "https://oauth2.sigstore.dev/auth"
STAGING_OAUTH_ISSUER_URL = "https://oauth2.sigstage.dev/auth"


class IssuerError(Exception):
    """
    Raised on any communication or format error with an OIDC issuer.
    """

    pass


class _OpenIDConfiguration(BaseModel):
    """
    Represents a (subset) of the fields provided by an OpenID Connect provider's
    `.well-known/openid-configuration` response, as defined by OpenID Connect Discovery.

    See: <https://openid.net/specs/openid-connect-discovery-1_0.html>
    """

    authorization_endpoint: StrictStr
    token_endpoint: StrictStr


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

        try:
            resp: requests.Response = requests.get(oidc_config_url, timeout=30)
        except (requests.ConnectionError, requests.Timeout) as exc:
            raise NetworkError from exc

        try:
            resp.raise_for_status()
        except requests.HTTPError as http_error:
            raise IssuerError from http_error

        try:
            # We don't generally expect this to fail (since the provider should
            # return a non-success HTTP code which we catch above), but we
            # check just in case we have a misbehaving OIDC issuer.
            self.oidc_config = _OpenIDConfiguration.parse_obj(resp.json())
        except ValueError as exc:
            raise IssuerError(f"OIDC issuer returned invalid configuration: {exc}")

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
                print("Waiting for browser interaction...", file=sys.stderr)
            else:
                server.enable_oob()
                print(
                    f"Go to the following link in a browser:\n\n\t{server.auth_endpoint}",
                    file=sys.stderr,
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
        try:
            resp: requests.Response = requests.post(
                self.oidc_config.token_endpoint,
                data=data,
                auth=auth,
                timeout=30,
            )
        except (requests.ConnectionError, requests.Timeout) as exc:
            raise NetworkError from exc

        try:
            resp.raise_for_status()
        except requests.HTTPError as http_error:
            raise IdentityError from http_error

        token_json = resp.json()
        token_error = token_json.get("error")
        if token_error is not None:
            raise IdentityError(f"Error response from token endpoint: {token_error}")

        return str(token_json["access_token"])


class IdentityError(Error):
    """
    Wraps `id`'s IdentityError.
    """

    @classmethod
    def raise_from_id(cls, exc: id.IdentityError) -> NoReturn:
        """Raises a wrapped IdentityError from the provided `id.IdentityError`."""
        raise IdentityError(str(exc)) from exc

    def diagnostics(self) -> str:
        """Returns diagnostics for the error."""
        if isinstance(self.__cause__, id.GitHubOidcPermissionCredentialError):
            return f"""
                Insufficient permissions for GitHub Actions workflow.

                The most common reason for this is incorrect
                configuration of the top-level `permissions` setting of the
                workflow YAML file. It should be configured like so:

                    permissions:
                      id-token: write

                Relevant documentation here:

                    https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect#adding-permissions-settings

                Another possible reason is that the workflow run has been
                triggered by a PR from a forked repository. PRs from forked
                repositories typically cannot be granted write access.

                Relevant documentation here:

                    https://docs.github.com/en/actions/security-guides/automatic-token-authentication#modifying-the-permissions-for-the-github_token

                Additional context:

                {self.__cause__}
                """
        else:
            return f"""
                An issue occurred with ambient credential detection.

                Additional context:

                {self}
            """


def detect_credential(audience: str) -> Optional[str]:
    """Calls `id.detect_credential`, but wraps exceptions with our own exception type."""
    try:
        return cast(Optional[str], id.detect_credential(audience))
    except id.IdentityError as exc:
        IdentityError.raise_from_id(exc)
