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
import os
import sys
from importlib import resources
from textwrap import dedent
from typing import BinaryIO, List, Optional, TextIO, cast

import click

from sigstore import __version__
from sigstore._internal.fulcio.client import (
    DEFAULT_FULCIO_URL,
    STAGING_FULCIO_URL,
)
from sigstore._internal.oidc.ambient import detect_credential
from sigstore._internal.oidc.issuer import Issuer
from sigstore._internal.oidc.oauth import (
    DEFAULT_OAUTH_ISSUER,
    STAGING_OAUTH_ISSUER,
    get_identity_token,
)
from sigstore._internal.rekor.client import (
    DEFAULT_REKOR_URL,
    STAGING_REKOR_URL,
)
from sigstore._sign import sign
from sigstore._verify import (
    CertificateVerificationFailure,
    VerificationFailure,
    verify,
)

logger = logging.getLogger(__name__)
logging.basicConfig(level=os.environ.get("SIGSTORE_LOGLEVEL", "INFO").upper())


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
    help="A PEM-encoded public key for the CT log (conflicts with --staging)",
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
    default=DEFAULT_OAUTH_ISSUER,
    help="The custom OpenID Connect issuer to use (conflicts with --staging)",
)
@click.option(
    "staging",
    "--staging",
    is_flag=True,
    default=False,
    help=(
        "Use the sigstore project's staging instances, "
        "instead of the default production instances"
    ),
)
@click.option(
    "oidc_disable_ambient_providers",
    "--oidc-disable-ambient-providers",
    is_flag=True,
    default=False,
    help="Disable ambient OIDC detection (e.g. on GitHub Actions)",
)
@click.option(
    "output_signature",
    "--output-signature",
    is_flag=False,
    flag_value=str(),
    metavar="FILE",
    type=click.STRING,
    help=(
        "With a value, write a single signature to the given file; "
        "without a value, write each signing result to {input}.sig"
    ),
)
@click.option(
    "output_certificate",
    "--output-certificate",
    is_flag=False,
    flag_value=str(),
    metavar="FILE",
    type=click.STRING,
    help=(
        "With a value, write a single signing certificate to the given file; "
        "without a value, write each signing certificate to {input}.cert"
    ),
)
@click.option(
    "--fulcio-url",
    metavar="URL",
    type=click.STRING,
    default=DEFAULT_FULCIO_URL,
    show_default=True,
    help="The Fulcio instance to use (conflicts with --staging)",
)
@click.option(
    "rekor_url",
    "--rekor-url",
    metavar="URL",
    type=click.STRING,
    default=DEFAULT_REKOR_URL,
    show_default=True,
    help="The Rekor instance to use (conflicts with --staging)",
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
    output_signature: Optional[str],
    output_certificate: Optional[str],
    fulcio_url: str,
    rekor_url: str,
    staging: bool,
) -> None:
    # Fail if `--output-signature` or `--output-certificate` is specified with
    # a value *and* we have more than one input. If passed without values,
    # then treat them as an instruction to generate default {input}.sig and
    # {input}.cert outputs for each {input}.
    multiple_inputs = len(files) > 1
    if (output_signature or output_certificate) and multiple_inputs:
        click.echo(
            "Error: --output-signature and --output-certificate can't be used with "
            "explicit outputs for multiple inputs",
            err=True,
        )
        raise click.Abort

    # If the user has explicitly requested the staging instance,
    # we need to override some of the CLI's defaults.
    if staging:
        logger.debug("sign: staging instances requested")
        oidc_issuer = STAGING_OAUTH_ISSUER
        ctfe_pem = resources.open_binary("sigstore._store", "ctfe.staging.pub")
        fulcio_url = STAGING_FULCIO_URL
        rekor_url = STAGING_REKOR_URL

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

        sig_output: TextIO
        if output_signature is None:
            sig_output = sys.stdout
        else:
            if output_signature == "":
                output_signature = f"{file.name}.sig"
            sig_output = open(output_signature, "w")

        print(result.b64_signature, file=sig_output)
        if output_signature:
            click.echo(f"Signature written to file {output_signature}")

        if output_certificate is not None:
            if output_certificate == "":
                output_certificate = f"{file.name}.crt"
            cert_output = open(output_certificate, "w")
            print(result.cert_pem, file=cert_output)
            click.echo(f"Certificate written to file {output_certificate}")


@main.command("verify")
@click.option(
    "certificate_path",
    "--cert",
    type=click.File("rb"),
    required=True,
    help="The PEM-encoded certificate to verify against",
)
@click.option(
    "signature_path",
    "--signature",
    type=click.File("rb"),
    required=True,
    help="The signature to verify against",
)
@click.option(
    "cert_email",
    "--cert-email",
    type=str,
    help=(
        "The email address (or other identity string) to check for in the "
        "certificate's Subject Alternative Name"
    ),
)
@click.option(
    "cert_oidc_issuer",
    "--cert-oidc-issuer",
    type=str,
    help=(
        "The OIDC issuer URL to check for in the certificate's OIDC issuer extension"
    ),
)
@click.option(
    "staging",
    "--staging",
    is_flag=True,
    default=False,
    help=(
        "Use the sigstore project's staging instances, "
        "instead of the default production instances"
    ),
)
@click.option(
    "rekor_url",
    "--rekor-url",
    metavar="URL",
    type=click.STRING,
    default=DEFAULT_REKOR_URL,
    show_default=True,
    help="The Rekor instance to use (conflicts with --staging)",
)
@click.argument(
    "files", metavar="FILE [FILE ...]", type=click.File("rb"), nargs=-1, required=True
)
def _verify(
    files: List[BinaryIO],
    certificate_path: BinaryIO,
    signature_path: BinaryIO,
    cert_email: Optional[str],
    cert_oidc_issuer: Optional[str],
    rekor_url: str,
    staging: bool,
) -> None:
    # If the user has explicitly requested the staging instance,
    # we need to override some of the CLI's defaults.
    if staging:
        logger.debug("verify: staging instances requested")
        rekor_url = STAGING_REKOR_URL

    # Load the signing certificate
    logger.debug(f"Using certificate from: {certificate_path.name}")
    certificate = certificate_path.read()

    # Load the signature
    logger.debug(f"Using signature from: {signature_path.name}")
    signature = signature_path.read()

    verified = True
    for file in files:
        result = verify(
            rekor_url=rekor_url,
            file=file,
            certificate=certificate,
            signature=signature,
            expected_cert_email=cert_email,
            expected_cert_oidc_issuer=cert_oidc_issuer,
        )

        if result:
            click.echo(f"OK: {file.name}")
        else:
            result = cast(VerificationFailure, result)
            click.echo(f"FAIL: {file.name}")

            if isinstance(result, CertificateVerificationFailure):
                # If certificate verification failed, it's either because of
                # a chain issue or some outdated state in sigstore itself.
                # These might already be resolved in a newer version, so
                # we suggest that users try to upgrade and retry before
                # anything else.
                click.echo(result.reason, err=True)
                click.echo(
                    dedent(
                        f"""
                        This may be a result of an outdated `sigstore` installation.

                        Consider upgrading with:

                            python -m pip install --upgrade sigstore

                        Additional context:

                        {result.exception}
                        """
                    ),
                    err=True,
                )
            else:
                click.echo(result.reason, err=True)
            verified = False

    if not verified:
        raise click.Abort
