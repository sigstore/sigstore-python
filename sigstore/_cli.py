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

from importlib import resources

import click

from sigstore import sign, verify
from sigstore._internal.oidc.ambient import detect_credential
from sigstore._internal.oidc.issuer import Issuer
from sigstore._internal.oidc.oauth import get_identity_token


@click.group()
def main():
    pass


@main.command("sign")
@click.option("identity_token", "--identity-token", metavar="TOKEN", type=click.STRING)
@click.option(
    "ctfe_pem",
    "--ctfe",
    type=click.File("rb"),
    default=resources.open_binary("sigstore._store", "ctfe.pub"),
)
@click.option(
    "oidc_client_id",
    "--oidc-client-id",
    metavar="ID",
    type=click.STRING,
    default="sigstore",
)
@click.option(
    "oidc_client_secret",
    "--oidc-client-secret",
    metavar="SECRET",
    type=click.STRING,
    default=str(),
)
@click.option(
    "oidc_issuer",
    "--oidc-issuer",
    metavar="URL",
    type=click.STRING,
    default="https://oauth2.sigstore.dev/auth",
)
@click.argument(
    "files", metavar="FILE [FILE ...]", type=click.File("rb"), nargs=-1, required=True
)
def _sign(
    files, identity_token, ctfe_pem, oidc_client_id, oidc_client_secret, oidc_issuer
):
    # The order of precedence is as follows:
    #
    # 1) Explicitly supplied identity token
    # 2) Ambient credential detected in the environment
    # 3) Interactive OAuth flow
    if not identity_token:
        identity_token = detect_credential()
    if not identity_token:
        issuer = Issuer(oidc_issuer)
        identity_token = get_identity_token(
            oidc_client_id,
            oidc_client_secret,
            issuer,
        )

    ctfe_pem = ctfe_pem.read()
    for file in files:
        click.echo(
            sign(
                file=file,
                identity_token=identity_token,
                ctfe_pem=ctfe_pem,
                output=click.echo,
            )
        )


@main.command("verify")
@click.option("certificate_path", "--cert", type=click.File("rb"), required=True)
@click.option("signature_path", "--signature", type=click.File("rb"), required=True)
@click.option("cert_email", "--cert-email", type=str)
@click.argument(
    "files", metavar="FILE [FILE ...]", type=click.File("rb"), nargs=-1, required=True
)
def _verify(files, certificate_path, signature_path, cert_email):
    # Load the signing certificate
    click.echo(f"Using certificate from: {certificate_path.name}")
    certificate = certificate_path.read()

    # Load the signature
    click.echo(f"Using signature from: {signature_path.name}")
    signature = signature_path.read()

    for file in files:
        click.echo(
            verify(
                file=file,
                certificate=certificate,
                signature=signature,
                cert_email=cert_email,
                output=click.echo,
            )
        )
