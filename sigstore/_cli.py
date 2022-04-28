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
    if not identity_token:
        click.echo("Error: missing identity token for signing", err=True)
        raise click.Abort

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
@click.option("certificate_path", "--cert", type=click.File("r"), required=True)
@click.option("signature_path", "--signature", type=click.File("r"), required=True)
@click.option("cert_email", "--cert-email", type=str)
@click.argument(
    "files", metavar="FILE [FILE ...]", type=click.File("rb"), nargs=-1, required=True
)
def _verify(files, certificate_path, signature_path, cert_email):
    for file in files:
        click.echo(
            verify(
                file=file,
                certificate_path=certificate_path,
                signature_path=signature_path,
                cert_email=cert_email,
                output=click.echo,
            )
        )
