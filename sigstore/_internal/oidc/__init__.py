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

import jwt

# See: https://github.com/sigstore/fulcio/blob/b2186c0/pkg/config/config.go#L182-L201
_KNOWN_OIDC_ISSUERS = {
    "https://accounts.google.com": "email",
    "https://oauth2.sigstore.dev/auth": "email",
    "https://oauth2.sigstage.dev/auth": "email",
    "https://token.actions.githubusercontent.com": "sub",
}
DEFAULT_AUDIENCE = "sigstore"


class IdentityError(Exception):
    """
    Raised on any OIDC token format or claim error.
    """

    pass


class Identity:
    """
    A wrapper for an OIDC "identity", as extracted from an OIDC token.
    """

    def __init__(self, identity_token: str) -> None:
        """
        Create a new `Identity` from the given OIDC token.
        """
        identity_jwt = jwt.decode(identity_token, options={"verify_signature": False})

        iss = identity_jwt.get("iss")
        if iss is None:
            raise IdentityError("Identity token missing the required `iss` claim")

        if "aud" not in identity_jwt:
            raise IdentityError("Identity token missing the required `aud` claim")

        aud = identity_jwt.get("aud")

        if aud != DEFAULT_AUDIENCE:
            raise IdentityError(f"Audience should be {DEFAULT_AUDIENCE!r}, not {aud!r}")

        # When verifying the private key possession proof, Fulcio uses
        # different claims depending on the token's issuer.
        # We currently special-case a handful of these, and fall back
        # on signing the "sub" claim otherwise.
        proof_claim = _KNOWN_OIDC_ISSUERS.get(iss)
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
