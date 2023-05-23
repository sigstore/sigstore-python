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
OIDC functionality for sigstore-python.
"""

from datetime import datetime, timezone

import jwt
from id import IdentityError

# See: https://github.com/sigstore/fulcio/blob/b2186c0/pkg/config/config.go#L182-L201
_KNOWN_OIDC_ISSUERS = {
    "https://accounts.google.com": "email",
    "https://oauth2.sigstore.dev/auth": "email",
    "https://oauth2.sigstage.dev/auth": "email",
    "https://token.actions.githubusercontent.com": "sub",
}
DEFAULT_AUDIENCE = "sigstore"


class ExpiredIdentity(Exception):
    """An error raised when an identity token is expired."""


class Identity:
    """
    A wrapper for an OIDC "identity", as extracted from an OIDC token.
    """

    def __init__(self, identity_token: str) -> None:
        """
        Create a new `Identity` from the given OIDC token. The token must
        contain a set of basic claims (`aud`, `iat`, `nbf`, `exp`, and `iss`),
        as well as whatever "core identity" claim corresponds to the token's
        `iss`.

        The token must also be non-expired (according to its claims)
        at the time of construction. It may become expired over the lifetime
        of the `Identity` object.

        NOTE: This is **not** a verifying wrapper: the given OIDC token's
        signature is not verified.
        """

        try:
            identity_jwt = jwt.decode(
                identity_token,
                options={
                    "verify_signature": False,
                    "verify_aud": True,
                    "verify_iat": True,
                    "verify_nbf": True,
                    "verify_exp": True,
                    "require": ["aud", "iat", "nbf", "exp", "iss"],
                },
                audience=DEFAULT_AUDIENCE,
            )
        except Exception as exc:
            raise IdentityError(
                "Identity token is malformed or missing claims"
            ) from exc

        self.issuer = identity_jwt["iss"]
        self._nbf: int = identity_jwt["nbf"]
        self._exp: int = identity_jwt["exp"]

        # When verifying the private key possession proof, Fulcio uses
        # different claims depending on the token's issuer.
        # We currently special-case a handful of these, and fall back
        # on signing the "sub" claim otherwise.
        proof_claim = _KNOWN_OIDC_ISSUERS.get(self.issuer)
        if proof_claim is not None:
            if proof_claim not in identity_jwt:
                raise IdentityError(
                    f"Identity token missing the required `{proof_claim!r}` claim"
                )

            self.proof = str(identity_jwt.get(proof_claim))
        else:
            try:
                self.proof = str(identity_jwt["sub"])
            except KeyError:
                raise IdentityError("Identity token missing `sub` claim")

    def in_validity_period(self) -> bool:
        """
        Returns whether or not this `Identity` is currently within its self-stated validity period.

        NOTE: As noted in `Identity.__init__`, this is not a verifying wrapper;
        the check here only asserts whether the *unverified* identity's claims
        are within their validity period.
        """

        now = datetime.now(timezone.utc).timestamp()

        return self._nbf <= now <= self._exp
