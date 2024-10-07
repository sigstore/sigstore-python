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
import sys
import time
import urllib.parse
import webbrowser
from datetime import datetime, timezone
from typing import NoReturn, Optional, cast

import id
import jwt
import requests
from pydantic import BaseModel, StrictStr

from sigstore._internal import USER_AGENT
from sigstore.errors import Error, NetworkError

DEFAULT_OAUTH_ISSUER_URL = "https://oauth2.sigstore.dev/auth"
STAGING_OAUTH_ISSUER_URL = "https://oauth2.sigstage.dev/auth"

# See: https://github.com/sigstore/fulcio/blob/b2186c0/pkg/config/config.go#L182-L201
_KNOWN_OIDC_ISSUERS = {
    "https://accounts.google.com": "email",
    "https://oauth2.sigstore.dev/auth": "email",
    "https://oauth2.sigstage.dev/auth": "email",
    "https://token.actions.githubusercontent.com": "sub",
}
_DEFAULT_AUDIENCE = "sigstore"


class _OpenIDConfiguration(BaseModel):
    """
    Represents a (subset) of the fields provided by an OpenID Connect provider's
    `.well-known/openid-configuration` response, as defined by OpenID Connect Discovery.

    See: <https://openid.net/specs/openid-connect-discovery-1_0.html>
    """

    authorization_endpoint: StrictStr
    token_endpoint: StrictStr


class ExpiredIdentity(Exception):
    """An error raised when an identity token is expired."""


class IdentityToken:
    """
    An OIDC "identity", corresponding to an underlying OIDC token with
    a sensible subject, issuer, and audience for Sigstore purposes.
    """

    def __init__(self, raw_token: str) -> None:
        """
        Create a new `IdentityToken` from the given OIDC token.
        """

        self._raw_token = raw_token

        # NOTE: The lack of verification here is intentional, and is part of
        # Sigstore's verification model: clients like sigstore-python are
        # responsible only for forwarding the OIDC identity to Fulcio for
        # certificate binding and issuance.
        try:
            self._unverified_claims = jwt.decode(
                raw_token,
                options={
                    "verify_signature": False,
                    "verify_aud": True,
                    "verify_iat": True,
                    "verify_exp": True,
                    # These claims are required by OpenID Connect, so
                    # we can strongly enforce their presence.
                    # See: https://openid.net/specs/openid-connect-basic-1_0.html#IDToken
                    "require": ["aud", "sub", "iat", "exp", "iss"],
                },
                audience=_DEFAULT_AUDIENCE,
                # NOTE: This leeway shouldn't be strictly necessary, but is
                # included to preempt any (small) skew between the host
                # and the originating IdP.
                leeway=5,
            )
        except Exception as exc:
            raise IdentityError(
                "Identity token is malformed or missing claims"
            ) from exc

        self._iss: str = self._unverified_claims["iss"]
        self._nbf: int | None = self._unverified_claims.get("nbf")
        self._exp: int = self._unverified_claims["exp"]

        # Fail early if this token isn't within its validity period.
        if not self.in_validity_period():
            raise IdentityError("Identity token is not within its validity period")

        # When verifying the private key possession proof, Fulcio uses
        # different claims depending on the token's issuer.
        # We currently special-case a handful of these, and fall back
        # on signing the "sub" claim otherwise.
        identity_claim = _KNOWN_OIDC_ISSUERS.get(self.issuer)
        if identity_claim is not None:
            if identity_claim not in self._unverified_claims:
                raise IdentityError(
                    f"Identity token is missing the required {identity_claim!r} claim"
                )

            self._identity = str(self._unverified_claims.get(identity_claim))
        else:
            try:
                self._identity = str(self._unverified_claims["sub"])
            except KeyError:
                raise IdentityError(
                    "Identity token is missing the required 'sub' claim"
                )

        # This identity token might have been retrieved directly from
        # an identity provider, or it might be a "federated" identity token
        # retrieved from a federated IdP (e.g., Sigstore's own Dex instance).
        # In the latter case, the claims will also include a `federated_claims`
        # set, which in turn should include a `connector_id` that reflects
        # the "real" token issuer. We retrieve this, despite technically
        # being an implementation detail, because it has value to client
        # users: a client might want to make sure that its user is identifying
        # with a *particular* IdP, which means that they need to pierce the
        # federation layer to check which IdP is actually being used.
        self._federated_issuer: str | None = None
        federated_claims = self._unverified_claims.get("federated_claims")
        if federated_claims is not None:
            if not isinstance(federated_claims, dict):
                raise IdentityError(
                    "unexpected claim type: federated_claims is not a dict"
                )

            federated_issuer = federated_claims.get("connector_id")
            if federated_issuer is not None:
                if not isinstance(federated_issuer, str):
                    raise IdentityError(
                        "unexpected claim type: federated_claims.connector_id is not a string"
                    )

                self._federated_issuer = federated_issuer

    def in_validity_period(self) -> bool:
        """
        Returns whether or not this `Identity` is currently within its self-stated validity period.

        NOTE: As noted in `Identity.__init__`, this is not a verifying wrapper;
        the check here only asserts whether the *unverified* identity's claims
        are within their validity period.
        """

        now = datetime.now(timezone.utc).timestamp()

        if self._nbf is not None:
            return self._nbf <= now < self._exp
        else:
            return now < self._exp

    @property
    def identity(self) -> str:
        """
        Returns this `IdentityToken`'s underlying "subject".

        Note that this is **not** always the `sub` claim in the corresponding
        identity token: depending onm the token's issuer, it may be a *different*
        claim, such as `email`. This corresponds to the Sigstore ecosystem's
        behavior, e.g. in each issued certificate's SAN.
        """
        return self._identity

    @property
    def issuer(self) -> str:
        """
        Returns a URL identifying this `IdentityToken`'s issuer.
        """
        return self._iss

    @property
    def federated_issuer(self) -> str:
        """
        Returns a URL identifying the **federated** issuer for any Sigstore
        certificate issued against this identity token.

        The behavior of this field is slightly subtle: for non-federated
        identity providers (like a token issued directly by Google's IdP) it
        should be exactly equivalent to `IdentityToken.issuer`. For federated
        issuers (like Sigstore's own federated IdP) it should be equivalent to
        the underlying federated issuer's URL, which is kept in an
        implementation-defined claim.

        This attribute exists so that clients who wish to inspect the expected
        underlying issuer of their certificates can do so without relying on
        implementation-specific behavior.
        """
        if self._federated_issuer is not None:
            return self._federated_issuer

        return self.issuer

    def __str__(self) -> str:
        """
        Returns the underlying OIDC token for this identity.

        That this token is secret in nature and **MUST NOT** be disclosed.
        """
        return self._raw_token


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
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": USER_AGENT})

        oidc_config_url = urllib.parse.urljoin(
            f"{base_url}/", ".well-known/openid-configuration"
        )

        try:
            resp: requests.Response = self.session.get(oidc_config_url, timeout=30)
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
            self.oidc_config = _OpenIDConfiguration.model_validate(resp.json())
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
        self,
        client_id: str = "sigstore",
        client_secret: str = "",
        force_oob: bool = False,
    ) -> IdentityToken:
        """
        Retrieves and returns an `IdentityToken` from the current `Issuer`, via OAuth.

        This function blocks on user interaction.

        The `force_oob` flag controls the kind of flow performed. When `False` (the default),
        this function attempts to open the user's web browser before falling back to
        an out-of-band flow. When `True`, the out-of-band flow is always used.
        """

        # This function and the components that it relies on are based off of:
        # https://github.com/psteniusubi/python-sample

        from sigstore._internal.oidc.oauth import _OAuthFlow

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
            resp = self.session.post(
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
            raise IdentityError(
                f"Token request failed with {resp.status_code}"
            ) from http_error

        token_json = resp.json()
        token_error = token_json.get("error")
        if token_error is not None:
            raise IdentityError(f"Error response from token endpoint: {token_error}")

        return IdentityToken(token_json["access_token"])


class IdentityError(Error):
    """
    Wraps `id`'s IdentityError.
    """

    @classmethod
    def raise_from_id(cls, exc: id.IdentityError) -> NoReturn:
        """Raises a wrapped IdentityError from the provided `id.IdentityError`."""
        raise cls(str(exc)) from exc

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


def detect_credential() -> Optional[str]:
    """Calls `id.detect_credential`, but wraps exceptions with our own exception type."""
    try:
        return cast(Optional[str], id.detect_credential(_DEFAULT_AUDIENCE))
    except id.IdentityError as exc:
        IdentityError.raise_from_id(exc)
