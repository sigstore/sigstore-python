import jwt

# From https://github.com/sigstore/fulcio/blob/b2186c01da1ddf807bde3ea8c450226d8e001d88/pkg/config/config.go#L182-L201  # noqa
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

        self.proof = identity_jwt.get(proof_claim)
