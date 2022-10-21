from textwrap import dedent
from typing import cast

from sigstore._internal.oidc.ambient import (
    detect_credential,
    GitHubOidcPermissionCredentialError
)
from sigstore._internal.oidc.issuer import Issuer
from sigstore._internal.oidc.oauth import (
    DEFAULT_OAUTH_ISSUER,
    get_identity_token,
)
from sigstore._sign import Signer, SigningResult
from sigstore._verify import (
    VerificationFailure,
    Verifier,
)

# Sign an artifact using sigstore-python. Returns SigningResult
def sign(artifact, signer=Signer.production(), identity_token=None, disable_oidc_ambient_providers=False, oidc_issuer=DEFAULT_OAUTH_ISSUER, oidc_client_id="sigstore", oidc_client_secret="") -> SigningResult:
    # Attempt to detect Github ambient credentials if an identity token is not provided.
    if not identity_token and not disable_oidc_ambient_providers:
        try:
            identity_token = detect_credential()
        except GitHubOidcPermissionCredentialError as exception:
            # Provide some common reasons for why we hit permission errors in
            # GitHub Actions.
            print(
                dedent(
                    f"""
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

                    {exception}
                    """
                )
            )
            raise exception
    if not identity_token:
        issuer = Issuer(oidc_issuer)
        identity_token = get_identity_token(
            oidc_client_id,
            oidc_client_secret, # oidc client secret
            issuer,
        )

    return signer.sign(
        input_=artifact,
        identity_token=identity_token
    )


# Verify an artifact, signature, and certificate using sigstore-python. Returns bool
def verify(artifact, crt, sig, verifier=Verifier.production()) -> bool:
    result = verifier.verify(
        input_=artifact,
        certificate=crt,
        signature=sig
    )

    if result:
        print("Sigstore verification: OK")
        return True
    else:
        result = cast(VerificationFailure, result)
        print("Sigstore verification: FAIL")
        print(f"Failure reason: {result.reason}")
        return False
