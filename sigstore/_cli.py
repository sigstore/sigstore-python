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

import click

from sigstore._internal.oidc.ambient import detect_credential
from sigstore._internal.oidc.oauth import get_identity_token
from sigstore._sign import sign
from sigstore._verify import verify

logger = logging.getLogger(__name__)


@click.group()
def main():
    pass


@main.command("sign")
@click.option("identity_token", "--identity-token", type=click.STRING)
@click.option(
    "ctfe_pem",
    "--ctfe",
    type=click.File("rb"),
    default=resources.open_binary("sigstore._store", "ctfe.pub"),
)
@click.argument(
    "files", metavar="FILE [FILE ...]", type=click.File("rb"), nargs=-1, required=True
)
def _sign(files, identity_token, ctfe_pem):
    # The order of precedence is as follows:
    #
    # 1) Explicitly supplied identity token
    # 2) Ambient credential detected in the environment
    # 3) Interactive OAuth flow
    if not identity_token:
        identity_token = detect_credential()
    if not identity_token:
        identity_token = get_identity_token()

    ctfe_pem = ctfe_pem.read()
    for file in files:
        result = sign(
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
def _verify(files, certificate_path, signature_path, cert_email):
    # Load the signing certificate
    logger.debug(f"Using certificate from: {certificate_path.name}")
    certificate = certificate_path.read()

    # Load the signature
    logger.debug(f"Using signature from: {signature_path.name}")
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
