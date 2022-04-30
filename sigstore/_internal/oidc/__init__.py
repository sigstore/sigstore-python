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

import jwt

# From https://github.com/sigstore/fulcio/blob/b2186c0/pkg/config/config.go#L182-L201
OIDC_ISSUERS = {
    "https://accounts.google.com": "email",
    "https://oauth2.sigstore.dev/auth": "email",
    "https://token.actions.githubusercontent.com": "sub",
}
AUDIENCE = "sigstore"


class IdentityError(Exception):
    pass


class Identity:
    def __init__(self, identity_token: str) -> None:
        identity_jwt = jwt.decode(identity_token, options={"verify_signature": False})

        if "iss" not in identity_jwt:
            raise IdentityError("Identity token  missing the required 'iss' claim")

        iss = identity_jwt.get("iss")

        if iss not in OIDC_ISSUERS:
            raise IdentityError(f"Not a valid OIDC issuer: {iss!r}")

        if "aud" not in identity_jwt:
            raise IdentityError("Identity token missing the required 'aud' claim")

        aud = identity_jwt.get("aud")

        if aud != AUDIENCE:
            raise IdentityError(f"Audience should be {AUDIENCE!r}, not {aud!r}")

        proof_claim = OIDC_ISSUERS[iss]
        if proof_claim not in identity_jwt:
            raise IdentityError(
                f"Identity token missing the required {proof_claim!r} claim"
            )

        self.proof: str = str(identity_jwt.get(proof_claim))
