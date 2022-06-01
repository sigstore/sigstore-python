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

import logging
from importlib import resources
from typing import BinaryIO, List, Optional

import click

from sigstore import __version__
from sigstore._internal.fulcio.client import DEFAULT_FULCIO_URL
from sigstore._internal.oidc.ambient import detect_credential
from sigstore._internal.oidc.issuer import Issuer
from sigstore._internal.oidc.oauth import get_identity_token
from sigstore._internal.rekor.client import DEFAULT_REKOR_URL
from sigstore._sign import sign
from sigstore._verify import verify

logger = logging.getLogger(__name__)


@click.group()
@click.version_option(version=__version__)
def main() -> None:
    pass


@main.command("sign")
@click.option(
    "identity_token",
    "--identity-token",
    metavar="TOKEN",
    type=click.STRING,
    help="the OIDC identity token to use",
)
@click.option(
    "ctfe_pem",
    "--ctfe",
    type=click.File("rb"),
    default=resources.open_binary("sigstore._store", "ctfe.pub"),
    help="A PEM-encoded public key for the CT log",
)
@click.option(
    "oidc_client_id",
    "--oidc-client-id",
    metavar="ID",
    type=click.STRING,
    default="sigstore",
    help="The custom OpenID Connect client ID to use",
)
@click.option(
    "oidc_client_secret",
    "--oidc-client-secret",
    metavar="SECRET",
    type=click.STRING,
    default=str(),
    help="The custom OpenID Connect client secret to use",
)
@click.option(
    "oidc_issuer",
    "--oidc-issuer",
    metavar="URL",
    type=click.STRING,
    default="https://oauth2.sigstore.dev/auth",
    help="The custom OpenID Connect issuer to use",
)
@click.option(
    "oidc_disable_ambient_providers",
    "--oidc-disable-ambient-providers",
    is_flag=True,
    default=False,
    help="Disable ambient OIDC detection (e.g. on GitHub Actions)",
)
@click.option(
    "fulcio_url",
    "--fulcio-url",
    metavar="URL",
    type=click.STRING,
    default=DEFAULT_FULCIO_URL,
    show_default=True,
    help="The Fulcio instance to use",
)
@click.option(
    "rekor_url",
    "--rekor-url",
    metavar="URL",
    type=click.STRING,
    default=DEFAULT_REKOR_URL,
    show_default=True,
    help="The Rekor instance to use",
)
@click.argument(
    "files",
    metavar="FILE [FILE ...]",
    type=click.File("rb"),
    nargs=-1,
    required=True,
)
def _sign(
    files: List[BinaryIO],
    identity_token: Optional[str],
    ctfe_pem: BinaryIO,
    oidc_client_id: str,
    oidc_client_secret: str,
    oidc_issuer: str,
    oidc_disable_ambient_providers: bool,
    fulcio_url: str,
    rekor_url: str,
) -> None:
    # The order of precedence is as follows:
    #
    # 1) Explicitly supplied identity token
    # 2) Ambient credential detected in the environment, unless disabled
    # 3) Interactive OAuth flow
    if not identity_token and not oidc_disable_ambient_providers:
        identity_token = detect_credential()
    if not identity_token:
        issuer = Issuer(oidc_issuer)
        identity_token = get_identity_token(
            oidc_client_id,
            oidc_client_secret,
            issuer,
        )
    if not identity_token:
        click.echo("No identity token supplied or detected!", err=True)
        raise click.Abort

    ctfe_pem = ctfe_pem.read()
    for file in files:
        result = sign(
            fulcio_url=fulcio_url,
            rekor_url=rekor_url,
            file=file,
            identity_token=identity_token,
            ctfe_pem=ctfe_pem,
        )

        click.echo("Using ephemeral certificate:")
        click.echo(result.cert_pem)
        click.echo(
            f"Transparency log entry created at index: {result.log_entry.log_index}"
        )
        click.echo(f"Signature: {result.b64_signature}")


@main.command("verify")
@click.option("certificate_path", "--cert", type=click.File("rb"), required=True)
@click.option("signature_path", "--signature", type=click.File("rb"), required=True)
@click.option("cert_email", "--cert-email", type=str)
@click.argument(
    "files", metavar="FILE [FILE ...]", type=click.File("rb"), nargs=-1, required=True
)
def _verify(
    files: List[BinaryIO],
    certificate_path: BinaryIO,
    signature_path: BinaryIO,
    cert_email: Optional[str],
) -> None:
    # Load the signing certificate
    logger.debug(f"Using certificate from: {certificate_path.name}")
    certificate = certificate_path.read()

    # Load the signature
    logger.debug(f"Using signature from: {signature_path.name}")
    signature = signature_path.read()

    verified = True
    for file in files:
        if verify(
            file=file,
            certificate=certificate,
            signature=signature,
            cert_email=cert_email,
        ):
            click.echo(f"OK: {file.name}")
        else:
            click.echo(f"FAIL: {file.name}")
            verified = False

    if not verified:
        raise click.Abort
