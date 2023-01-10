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

from __future__ import annotations

import argparse
import base64
import logging
import os
import sys
from pathlib import Path
from textwrap import dedent
from typing import Optional, TextIO, Union, cast

from cryptography.x509 import load_pem_x509_certificates

from sigstore import __version__
from sigstore._internal.ctfe import CTKeyring
from sigstore._internal.fulcio.client import DEFAULT_FULCIO_URL, FulcioClient
from sigstore._internal.rekor.client import (
    DEFAULT_REKOR_URL,
    RekorBundle,
    RekorClient,
)
from sigstore._internal.tuf import TrustUpdater
from sigstore.oidc import (
    DEFAULT_OAUTH_ISSUER_URL,
    STAGING_OAUTH_ISSUER_URL,
    GitHubOidcPermissionCredentialError,
    Issuer,
    detect_credential,
)
from sigstore.sign import Signer
from sigstore.transparency import LogEntry
from sigstore.verify import (
    CertificateVerificationFailure,
    LogEntryMissing,
    VerificationFailure,
    VerificationMaterials,
    Verifier,
    policy,
)

logging.basicConfig()
logger = logging.getLogger(__name__)

# NOTE: We configure the top package logger, rather than the root logger,
# to avoid overly verbose logging in third-party code by default.
package_logger = logging.getLogger("sigstore")
package_logger.setLevel(os.environ.get("SIGSTORE_LOGLEVEL", "INFO").upper())


def _boolify_env(envvar: str) -> bool:
    """
    An `argparse` helper for turning an environment variable into a boolean.

    The semantics here closely mirror `distutils.util.strtobool`.

    See: <https://docs.python.org/3/distutils/apiref.html#distutils.util.strtobool>
    """
    val = os.getenv(envvar)
    if val is None:
        return False

    val = val.lower()
    if val in {"y", "yes", "true", "t", "on", "1"}:
        return True
    elif val in {"n", "no", "false", "f", "off", "0"}:
        return False
    else:
        raise ValueError(f"can't coerce '{val}' to a boolean")


def _set_default_verify_subparser(parser: argparse.ArgumentParser, name: str) -> None:
    """
    An argparse patch for configuring a default subparser for `sigstore verify`.

    Adapted from <https://stackoverflow.com/a/26379693>
    """
    subparser_found = False
    for arg in sys.argv[1:]:
        if arg in ["-h", "--help"]:  # global help if no subparser
            break
    else:
        for x in parser._subparsers._actions:  # type: ignore[union-attr]
            if not isinstance(x, argparse._SubParsersAction):
                continue
            for sp_name in x._name_parser_map.keys():
                if sp_name in sys.argv[1:]:
                    subparser_found = True
        if not subparser_found:
            try:
                # If `sigstore verify identity` wasn't passed explicitly, we need
                # to insert the `identity` subcommand into the correct position
                # within `sys.argv`. To do that, we get the index of the `verify`
                # subcommand, and insert it directly after it.
                verify_idx = sys.argv.index("verify")
                sys.argv.insert(verify_idx + 1, name)
                logger.warning(
                    "`sigstore verify` without a subcommand will be treated as "
                    "`sigstore verify identity`, but this behavior will be deprecated "
                    "in a future release"
                )
            except ValueError:
                # This happens when we invoke `sigstore sign`, since there's no
                # `verify` subcommand to insert under. We do nothing in this case.
                pass


def _add_shared_instance_options(group: argparse._ArgumentGroup) -> None:
    """
    Common Sigstore instance options, shared between all `sigstore` subcommands.
    """
    group.add_argument(
        "--staging",
        dest="__deprecated_staging",
        action="store_true",
        default=False,
        help=(
            "Use sigstore's staging instances, instead of the default production instances. "
            "This option will be deprecated in favor of the global `--staging` option "
            "in a future release."
        ),
    )
    group.add_argument(
        "--rekor-url",
        dest="__deprecated_rekor_url",
        metavar="URL",
        type=str,
        default=None,
        help=(
            "The Rekor instance to use (conflicts with --staging). "
            "This option will be deprecated in favor of the global `--rekor-url` option "
            "in a future release."
        ),
    )
    group.add_argument(
        "--rekor-root-pubkey",
        dest="__deprecated_rekor_root_pubkey",
        metavar="FILE",
        type=argparse.FileType("rb"),
        default=None,
        help=(
            "A PEM-encoded root public key for Rekor itself (conflicts with --staging). "
            "This option will be deprecated in favor of the global `--rekor-root-pubkey` option "
            "in a future release."
        ),
    )


def _add_shared_input_options(group: argparse._ArgumentGroup) -> None:
    """
    Common input options, shared between all `sigstore verify` subcommands.
    """
    group.add_argument(
        "--certificate",
        "--cert",
        metavar="FILE",
        type=Path,
        default=os.getenv("SIGSTORE_CERTIFICATE"),
        help="The PEM-encoded certificate to verify against; not used with multiple inputs",
    )
    group.add_argument(
        "--signature",
        metavar="FILE",
        type=Path,
        default=os.getenv("SIGSTORE_SIGNATURE"),
        help="The signature to verify against; not used with multiple inputs",
    )
    group.add_argument(
        "--rekor-bundle",
        metavar="FILE",
        type=Path,
        default=os.getenv("SIGSTORE_REKOR_BUNDLE"),
        help="The offline Rekor bundle to verify with; not used with multiple inputs",
    )
    group.add_argument(
        "files",
        metavar="FILE",
        type=Path,
        nargs="+",
        help="The file to verify",
    )


def _add_shared_verification_options(group: argparse._ArgumentGroup) -> None:
    group.add_argument(
        "--cert-identity",
        metavar="IDENTITY",
        type=str,
        default=os.getenv("SIGSTORE_CERT_IDENTITY"),
        help="The identity to check for in the certificate's Subject Alternative Name",
        required=True,
    )
    group.add_argument(
        "--require-rekor-offline",
        action="store_true",
        default=_boolify_env("SIGSTORE_REQUIRE_REKOR_OFFLINE"),
        help="Require offline Rekor verification with a bundle; implied by --rekor-bundle",
    )


def _add_shared_oidc_options(
    group: Union[argparse._ArgumentGroup, argparse.ArgumentParser]
) -> None:
    """
    Common OIDC options, shared between `sigstore sign` and `sigstore get-identity-token`.
    """
    group.add_argument(
        "--oidc-client-id",
        metavar="ID",
        type=str,
        default=os.getenv("SIGSTORE_OIDC_CLIENT_ID", "sigstore"),
        help="The custom OpenID Connect client ID to use during OAuth2",
    )
    group.add_argument(
        "--oidc-client-secret",
        metavar="SECRET",
        type=str,
        default=os.getenv("SIGSTORE_OIDC_CLIENT_SECRET"),
        help="The custom OpenID Connect client secret to use during OAuth2",
    )
    group.add_argument(
        "--oidc-disable-ambient-providers",
        action="store_true",
        default=_boolify_env("SIGSTORE_OIDC_DISABLE_AMBIENT_PROVIDERS"),
        help="Disable ambient OpenID Connect credential detection (e.g. on GitHub Actions)",
    )
    group.add_argument(
        "--oidc-issuer",
        metavar="URL",
        type=str,
        default=os.getenv("SIGSTORE_OIDC_ISSUER", DEFAULT_OAUTH_ISSUER_URL),
        help="The OpenID Connect issuer to use (conflicts with --staging)",
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sigstore",
        description="a tool for signing and verifying Python package distributions",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "-V", "--version", action="version", version=f"%(prog)s {__version__}"
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="run with additional debug logging; supply multiple times to increase verbosity",
    )

    global_instance_options = parser.add_argument_group("Sigstore instance options")
    global_instance_options.add_argument(
        "--staging",
        action="store_true",
        default=_boolify_env("SIGSTORE_STAGING"),
        help="Use sigstore's staging instances, instead of the default production instances",
    )
    global_instance_options.add_argument(
        "--rekor-url",
        metavar="URL",
        type=str,
        default=os.getenv("SIGSTORE_REKOR_URL", DEFAULT_REKOR_URL),
        help="The Rekor instance to use (conflicts with --staging)",
    )
    global_instance_options.add_argument(
        "--rekor-root-pubkey",
        metavar="FILE",
        type=argparse.FileType("rb"),
        help="A PEM-encoded root public key for Rekor itself (conflicts with --staging)",
        default=os.getenv("SIGSTORE_REKOR_ROOT_PUBKEY"),
    )

    subcommands = parser.add_subparsers(required=True, dest="subcommand")

    # `sigstore sign`
    sign = subcommands.add_parser(
        "sign", formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )

    oidc_options = sign.add_argument_group("OpenID Connect options")
    oidc_options.add_argument(
        "--identity-token",
        metavar="TOKEN",
        type=str,
        default=os.getenv("SIGSTORE_IDENTITY_TOKEN"),
        help="the OIDC identity token to use",
    )
    _add_shared_oidc_options(oidc_options)

    output_options = sign.add_argument_group("Output options")
    output_options.add_argument(
        "--no-default-files",
        action="store_true",
        default=_boolify_env("SIGSTORE_NO_DEFAULT_FILES"),
        help="Don't emit the default output files ({input}.sig, {input}.crt, {input}.rekor)",
    )
    output_options.add_argument(
        "--signature",
        "--output-signature",
        metavar="FILE",
        type=Path,
        default=os.getenv("SIGSTORE_OUTPUT_SIGNATURE"),
        help=(
            "Write a single signature to the given file; does not work with multiple input files"
        ),
    )
    output_options.add_argument(
        "--certificate",
        "--output-certificate",
        metavar="FILE",
        type=Path,
        default=os.getenv("SIGSTORE_OUTPUT_CERTIFICATE"),
        help=(
            "Write a single certificate to the given file; does not work with multiple input files"
        ),
    )
    output_options.add_argument(
        "--rekor-bundle",
        "--output-rekor-bundle",
        metavar="FILE",
        type=Path,
        default=os.getenv("SIGSTORE_OUTPUT_BUNDLE"),
        help=(
            "Write a single offline Rekor bundle to the given file; does not work with "
            "multiple input files"
        ),
    )
    output_options.add_argument(
        "--overwrite",
        action="store_true",
        default=_boolify_env("SIGSTORE_OVERWRITE"),
        help="Overwrite preexisting signature and certificate outputs, if present",
    )

    instance_options = sign.add_argument_group("Sigstore instance options")
    _add_shared_instance_options(instance_options)
    instance_options.add_argument(
        "--fulcio-url",
        metavar="URL",
        type=str,
        default=os.getenv("SIGSTORE_FULCIO_URL", DEFAULT_FULCIO_URL),
        help="The Fulcio instance to use (conflicts with --staging)",
    )
    instance_options.add_argument(
        "--ctfe",
        dest="ctfe_pem",
        metavar="FILE",
        type=argparse.FileType("rb"),
        help="A PEM-encoded public key for the CT log (conflicts with --staging)",
        default=os.getenv("SIGSTORE_CTFE"),
    )

    sign.add_argument(
        "files",
        metavar="FILE",
        type=Path,
        nargs="+",
        help="The file to sign",
    )

    # `sigstore verify`
    verify = subcommands.add_parser(
        "verify",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    verify_subcommand = verify.add_subparsers(dest="verify_subcommand")

    # `sigstore verify identity`
    verify_identity = verify_subcommand.add_parser(
        "identity",
        help="verify against a known identity and identity provider",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    input_options = verify_identity.add_argument_group("Verification inputs")
    _add_shared_input_options(input_options)

    verification_options = verify_identity.add_argument_group("Verification options")
    _add_shared_verification_options(verification_options)
    verification_options.add_argument(
        "--cert-oidc-issuer",
        metavar="URL",
        type=str,
        default=os.getenv("SIGSTORE_CERT_OIDC_ISSUER"),
        help="The OIDC issuer URL to check for in the certificate's OIDC issuer extension",
        required=True,
    )

    instance_options = verify_identity.add_argument_group("Sigstore instance options")
    _add_shared_instance_options(instance_options)
    instance_options.add_argument(
        "--certificate-chain",
        metavar="FILE",
        type=argparse.FileType("r"),
        help=(
            "Path to a list of CA certificates in PEM format which will be needed when building "
            "the certificate chain for the Fulcio signing certificate"
        ),
    )

    # `sigstore verify github`
    verify_github = verify_subcommand.add_parser(
        "github",
        help="verify against GitHub Actions-specific claims",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    input_options = verify_github.add_argument_group("Verification inputs")
    _add_shared_input_options(input_options)

    verification_options = verify_github.add_argument_group("Verification options")
    _add_shared_verification_options(verification_options)
    verification_options.add_argument(
        "--trigger",
        dest="workflow_trigger",
        metavar="EVENT",
        type=str,
        default=os.getenv("SIGSTORE_VERIFY_GITHUB_WORKFLOW_TRIGGER"),
        help="The GitHub Actions event name that triggered the workflow",
    )
    verification_options.add_argument(
        "--sha",
        dest="workflow_sha",
        metavar="SHA",
        type=str,
        default=os.getenv("SIGSTORE_VERIFY_GITHUB_WORKFLOW_SHA"),
        help="The `git` commit SHA that the workflow run was invoked with",
    )
    verification_options.add_argument(
        "--name",
        dest="workflow_name",
        metavar="NAME",
        type=str,
        default=os.getenv("SIGSTORE_VERIFY_GITHUB_WORKFLOW_NAME"),
        help="The name of the workflow that was triggered",
    )
    verification_options.add_argument(
        "--repository",
        dest="workflow_repository",
        metavar="REPO",
        type=str,
        default=os.getenv("SIGSTORE_VERIFY_GITHUB_WORKFLOW_REPOSITORY"),
        help="The repository slug that the workflow was triggered under",
    )
    verification_options.add_argument(
        "--ref",
        dest="workflow_ref",
        metavar="REF",
        type=str,
        default=os.getenv("SIGSTORE_VERIFY_GITHUB_WORKFLOW_REF"),
        help="The `git` ref that the workflow was invoked with",
    )

    instance_options = verify_github.add_argument_group("Sigstore instance options")
    _add_shared_instance_options(instance_options)
    instance_options.add_argument(
        "--certificate-chain",
        metavar="FILE",
        type=argparse.FileType("r"),
        help=(
            "Path to a list of CA certificates in PEM format which will be needed when building "
            "the certificate chain for the Fulcio signing certificate"
        ),
    )

    # `sigstore verify` defaults to `sigstore verify identity`, for backwards
    # compatibility.
    _set_default_verify_subparser(verify, "identity")

    # `sigstore get-identity-token`
    get_identity_token = subcommands.add_parser("get-identity-token")
    _add_shared_oidc_options(get_identity_token)

    return parser


def main() -> None:
    parser = _parser()
    args = parser.parse_args()

    # Configure logging upfront, so that we don't miss anything.
    if args.verbose >= 1:
        package_logger.setLevel("DEBUG")
    if args.verbose >= 2:
        logging.getLogger().setLevel("DEBUG")

    logger.debug(f"parsed arguments {args}")

    # A few instance flags (like `--staging` and `--rekor-url`) are supported at both the
    # top-level `sigstore` level and the subcommand level (e.g. `sigstore verify --staging`),
    # but the former is preferred.
    if getattr(args, "__deprecated_staging", False):
        logger.warning(
            "`--staging` should be used as a global option, rather than a subcommand option. "
            "Passing `--staging` as a subcommand option will be deprecated in a future release."
        )
        args.staging = args.__deprecated_staging
    if getattr(args, "__deprecated_rekor_url", None):
        logger.warning(
            "`--rekor-url` should be used as a global option, rather than a subcommand option. "
            "Passing `--rekor-url` as a subcommand option will be deprecated in a future release."
        )
        args.rekor_url = args.__deprecated_rekor_url
    if getattr(args, "__deprecated_rekor_root_pubkey", None):
        logger.warning(
            "`--rekor-root-pubkey` should be used as a global option, rather than a "
            "subcommand option. Passing `--rekor-root-pubkey` as a subcommand option will be "
            "deprecated in a future release."
        )
        args.rekor_root_pubkey = args.__deprecated_rekor_root_pubkey

    # Stuff the parser back into our namespace, so that we can use it for
    # error handling later.
    args._parser = parser

    if args.subcommand == "sign":
        _sign(args)
    elif args.subcommand == "verify":
        if args.verify_subcommand == "identity":
            _verify_identity(args)
        elif args.verify_subcommand == "github":
            _verify_github(args)
        else:
            parser.error(f"Unknown verify subcommand: {args.verify_subcommand}")
    elif args.subcommand == "get-identity-token":
        token = _get_identity_token(args)
        if token:
            print(token)
        else:
            args._parser.error("No identity token supplied or detected!")

    else:
        parser.error(f"Unknown subcommand: {args.subcommand}")


def _sign(args: argparse.Namespace) -> None:
    # `--rekor-bundle` is a temporary option, pending stabilization of the
    # Sigstore bundle format.
    if args.rekor_bundle:
        logger.warning(
            "--rekor-bundle is a temporary format, and will be removed in an "
            "upcoming release of sigstore-python in favor of Sigstore-style bundles"
        )

    # `--no-default-files` has no effect on `--{signature,certificate,rekor-bundle}`, but we
    # forbid it because it indicates user confusion.
    if args.no_default_files and (
        args.signature or args.certificate or args.rekor_bundle
    ):
        args._parser.error(
            "--no-default-files may not be combined with --signature, "
            "--certificate, or --rekor-bundle",
        )

    # Fail if `--signature` or `--certificate` is specified *and* we have more
    # than one input.
    if (args.signature or args.certificate or args.rekor_bundle) and len(
        args.files
    ) > 1:
        args._parser.error(
            "Error: --signature, --certificate, and --rekor-bundle can't be used "
            "with explicit outputs for multiple inputs",
        )

    # Build up the map of inputs -> outputs ahead of any signing operations,
    # so that we can fail early if overwriting without `--overwrite`.
    output_map = {}
    for file in args.files:
        if not file.is_file():
            args._parser.error(f"Input must be a file: {file}")

        sig, cert, bundle = args.signature, args.certificate, args.rekor_bundle
        if not sig and not cert and not bundle and not args.no_default_files:
            sig = file.parent / f"{file.name}.sig"
            cert = file.parent / f"{file.name}.crt"
            bundle = file.parent / f"{file.name}.rekor"

        if not args.overwrite:
            extants = []
            if sig and sig.exists():
                extants.append(str(sig))
            if cert and cert.exists():
                extants.append(str(cert))
            if bundle and bundle.exists():
                extants.append(str(bundle))

            if extants:
                args._parser.error(
                    "Refusing to overwrite outputs without --overwrite: "
                    f"{', '.join(extants)}"
                )

        output_map[file] = {"cert": cert, "sig": sig, "bundle": bundle}

    # Select the signer to use.
    if args.staging:
        logger.debug("sign: staging instances requested")
        signer = Signer.staging()
        args.oidc_issuer = STAGING_OAUTH_ISSUER_URL
    elif args.fulcio_url == DEFAULT_FULCIO_URL and args.rekor_url == DEFAULT_REKOR_URL:
        signer = Signer.production()
    else:
        # Assume "production" keys if none are given as arguments
        updater = TrustUpdater.production()
        if args.ctfe_pem is not None:
            ctfe_keys = [args.ctfe_pem.read()]
        else:
            ctfe_keys = updater.get_ctfe_keys()
        if args.rekor_root_pubkey is not None:
            rekor_key = args.rekor_root_pubkey.read()
        else:
            rekor_key = updater.get_rekor_key()

        ct_keyring = CTKeyring(ctfe_keys)
        signer = Signer(
            fulcio=FulcioClient(args.fulcio_url),
            rekor=RekorClient(args.rekor_url, rekor_key, ct_keyring),
        )

    # The order of precedence is as follows:
    #
    # 1) Explicitly supplied identity token
    # 2) Ambient credential detected in the environment, unless disabled
    # 3) Interactive OAuth flow
    if not args.identity_token:
        args.identity_token = _get_identity_token(args)
    if not args.identity_token:
        args._parser.error("No identity token supplied or detected!")

    for file, outputs in output_map.items():
        logger.debug(f"signing for {file.name}")
        with file.open(mode="rb", buffering=0) as io:
            result = signer.sign(
                input_=io,
                identity_token=args.identity_token,
            )

        print("Using ephemeral certificate:")
        print(result.cert_pem)

        print(f"Transparency log entry created at index: {result.log_entry.log_index}")

        sig_output: TextIO
        if outputs["sig"]:
            sig_output = outputs["sig"].open("w")
        else:
            sig_output = sys.stdout

        print(result.b64_signature, file=sig_output)
        if outputs["sig"] is not None:
            print(f"Signature written to {outputs['sig']}")

        if outputs["cert"] is not None:
            with outputs["cert"].open(mode="w") as io:
                print(result.cert_pem, file=io)
            print(f"Certificate written to {outputs['cert']}")

        if outputs["bundle"] is not None:
            with outputs["bundle"].open(mode="w") as io:
                bundle = RekorBundle.from_entry(result.log_entry)
                print(bundle.json(by_alias=True), file=io)
            print(f"Rekor bundle written to {outputs['bundle']}")


def _collect_verification_state(
    args: argparse.Namespace,
) -> tuple[Verifier, list[tuple[Path, VerificationMaterials]]]:
    """
    Performs CLI functionality common across all `sigstore verify` subcommands.

    Returns a tuple of the active verifier instance and a list of `(file, materials)`
    tuples, where `file` is the path to the file being verified (for display
    purposes) and `materials` is the `VerificationMaterials` to verify with.
    """

    # `--rekor-bundle` is a temporary option, pending stabilization of the
    # Sigstore bundle format.
    if args.rekor_bundle:
        logger.warning(
            "--rekor-bundle is a temporary format, and will be removed in an "
            "upcoming release of sigstore-python in favor of Sigstore-style bundles"
        )

    # The presence of --rekor-bundle implies --require-rekor-offline.
    args.require_rekor_offline = args.require_rekor_offline or args.rekor_bundle

    # Fail if --certificate, --signature, or --rekor-bundle is specified and we
    # have more than one input.
    if (args.certificate or args.signature or args.rekor_bundle) and len(
        args.files
    ) > 1:
        args._parser.error(
            "--certificate, --signature, and --rekor-bundle can only be used "
            "with a single input file"
        )

    # The converse of `sign`: we build up an expected input map and check
    # that we have everything so that we can fail early.
    input_map = {}
    for file in args.files:
        if not file.is_file():
            args._parser.error(f"Input must be a file: {file}")

        sig, cert, bundle = args.signature, args.certificate, args.rekor_bundle
        if sig is None:
            sig = file.parent / f"{file.name}.sig"
        if cert is None:
            cert = file.parent / f"{file.name}.crt"
        if bundle is None:
            bundle = file.parent / f"{file.name}.rekor"

        missing = []
        if not sig.is_file():
            missing.append(str(sig))
        if not cert.is_file():
            missing.append(str(cert))
        if not bundle.is_file() and args.require_rekor_offline:
            # NOTE: We only produce errors on missing bundle files
            # if the user has explicitly requested offline-only verification.
            # Otherwise, we fall back on online verification.
            missing.append(str(bundle))

        if missing:
            args._parser.error(
                f"Missing verification materials for {(file)}: {', '.join(missing)}"
            )

        input_map[file] = {"cert": cert, "sig": sig, "bundle": bundle}

    if args.staging:
        logger.debug("verify: staging instances requested")
        verifier = Verifier.staging()
    elif args.rekor_url == DEFAULT_REKOR_URL:
        verifier = Verifier.production()
    else:
        if not args.certificate_chain:
            args._parser.error(
                "Custom Rekor URL used without specifying --certificate-chain"
            )

        try:
            certificate_chain = load_pem_x509_certificates(
                args.certificate_chain.read()
            )
        except ValueError as error:
            args._parser.error(f"Invalid certificate chain: {error}")

        if args.rekor_root_pubkey is not None:
            rekor_key = args.rekor_root_pubkey.read()
        else:
            updater = TrustUpdater.production()
            rekor_key = updater.get_rekor_key()

        verifier = Verifier(
            rekor=RekorClient(
                url=args.rekor_url,
                pubkey=rekor_key,
                # We don't use the CT keyring in verification so we can supply an empty keyring
                ct_keyring=CTKeyring(),
            ),
            fulcio_certificate_chain=certificate_chain,
        )

    all_materials = []
    for file, inputs in input_map.items():
        # Load the signing certificate
        logger.debug(f"Using certificate from: {inputs['cert']}")
        cert_pem = inputs["cert"].read_text()

        # Load the signature
        logger.debug(f"Using signature from: {inputs['sig']}")
        b64_signature = inputs["sig"].read_text()

        entry: Optional[LogEntry] = None
        if inputs["bundle"].is_file():
            logger.debug(f"Using offline Rekor bundle from: {inputs['bundle']}")
            bundle = RekorBundle.parse_file(inputs["bundle"])
            entry = bundle.to_entry()

        logger.debug(f"Verifying contents from: {file}")

        with file.open(mode="rb", buffering=0) as io:
            all_materials.append(
                (
                    file,
                    VerificationMaterials(
                        input_=io,
                        cert_pem=cert_pem,
                        signature=base64.b64decode(b64_signature),
                        offline_rekor_entry=entry,
                    ),
                )
            )

    return (verifier, all_materials)


def _verify_identity(args: argparse.Namespace) -> None:
    verifier, files_with_materials = _collect_verification_state(args)

    for (file, materials) in files_with_materials:
        policy_ = policy.Identity(
            identity=args.cert_identity,
            issuer=args.cert_oidc_issuer,
        )

        result = verifier.verify(
            materials=materials,
            policy=policy_,
        )

        if result:
            print(f"OK: {file}")
        else:
            result = cast(VerificationFailure, result)
            print(f"FAIL: {file}")
            print(f"Failure reason: {result.reason}", file=sys.stderr)

            if isinstance(result, CertificateVerificationFailure):
                # If certificate verification failed, it's either because of
                # a chain issue or some outdated state in sigstore itself.
                # These might already be resolved in a newer version, so
                # we suggest that users try to upgrade and retry before
                # anything else.
                print(
                    dedent(
                        f"""
                        The given certificate could not be verified against the
                        root of trust.

                        This may be a result of connecting to the wrong Fulcio instance
                        (for example, staging instead of production, or vice versa).

                        Additional context:

                        {result.exception}
                        """
                    ),
                    file=sys.stderr,
                )
            elif isinstance(result, LogEntryMissing):
                # If Rekor lookup failed, it's because the certificate either
                # wasn't logged after creation or because the user requested the
                # wrong Rekor instance (e.g., staging instead of production).
                # The latter is significantly more likely, so we add
                # some additional context to the output indicating it.
                #
                # NOTE: Even though the latter is more likely, it's still extremely
                # unlikely that we'd hit this -- we should always fail with
                # `CertificateVerificationFailure` instead, as the cert store should
                # fail to validate due to a mismatch between the leaf and the trusted
                # root + intermediates.
                print(
                    dedent(
                        f"""
                        These signing artifacts could not be matched to a entry
                        in the configured transparency log.

                        This may be a result of connecting to the wrong Rekor instance
                        (for example, staging instead of production, or vice versa).

                        Additional context:

                        Signature: {result.signature}

                        Artifact hash: {result.artifact_hash}
                        """
                    ),
                    file=sys.stderr,
                )

            sys.exit(1)


def _verify_github(args: argparse.Namespace) -> None:
    # Every GitHub verification begins with an identity policy,
    # for which we know the issuer URL ahead of time.
    # We then add more policies, as configured by the user's passed-in options.
    inner_policies: list[policy.VerificationPolicy] = [
        policy.Identity(
            identity=args.cert_identity,
            issuer="https://token.actions.githubusercontent.com",
        )
    ]

    if args.workflow_trigger:
        inner_policies.append(policy.GitHubWorkflowTrigger(args.workflow_trigger))
    if args.workflow_sha:
        inner_policies.append(policy.GitHubWorkflowSHA(args.workflow_sha))
    if args.workflow_name:
        inner_policies.append(policy.GitHubWorkflowName(args.workflow_name))
    if args.workflow_repository:
        inner_policies.append(policy.GitHubWorkflowRepository(args.workflow_repository))
    if args.workflow_ref:
        inner_policies.append(policy.GitHubWorkflowRef(args.workflow_ref))

    policy_ = policy.AllOf(inner_policies)

    verifier, files_with_materials = _collect_verification_state(args)
    for (file, materials) in files_with_materials:
        result = verifier.verify(materials=materials, policy=policy_)

        if result:
            print(f"OK: {file}")
        else:
            result = cast(VerificationFailure, result)
            print(f"FAIL: {file}")
            print(f"Failure reason: {result.reason}", file=sys.stderr)

            if isinstance(result, CertificateVerificationFailure):
                # If certificate verification failed, it's either because of
                # a chain issue or some outdated state in sigstore itself.
                # These might already be resolved in a newer version, so
                # we suggest that users try to upgrade and retry before
                # anything else.
                print(
                    dedent(
                        f"""
                        The given certificate could not be verified against the
                        root of trust.

                        This may be a result of connecting to the wrong Fulcio instance
                        (for example, staging instead of production, or vice versa).

                        Additional context:

                        {result.exception}
                        """
                    ),
                    file=sys.stderr,
                )
            elif isinstance(result, LogEntryMissing):
                # If Rekor lookup failed, it's because the certificate either
                # wasn't logged after creation or because the user requested the
                # wrong Rekor instance (e.g., staging instead of production).
                # The latter is significantly more likely, so we add
                # some additional context to the output indicating it.
                #
                # NOTE: Even though the latter is more likely, it's still extremely
                # unlikely that we'd hit this -- we should always fail with
                # `CertificateVerificationFailure` instead, as the cert store should
                # fail to validate due to a mismatch between the leaf and the trusted
                # root + intermediates.
                print(
                    dedent(
                        f"""
                        These signing artifacts could not be matched to a entry
                        in the configured transparency log.

                        This may be a result of connecting to the wrong Rekor instance
                        (for example, staging instead of production, or vice versa).

                        Additional context:

                        Signature: {result.signature}

                        Artifact hash: {result.artifact_hash}
                        """
                    ),
                    file=sys.stderr,
                )

            sys.exit(1)


def _get_identity_token(args: argparse.Namespace) -> Optional[str]:
    token = None
    if not args.oidc_disable_ambient_providers:
        try:
            token = detect_credential()
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
                ),
                file=sys.stderr,
            )
            sys.exit(1)

    if not token:
        if args.staging:
            issuer = Issuer.staging()
        elif args.oidc_issuer == DEFAULT_OAUTH_ISSUER_URL:
            issuer = Issuer.production()
        else:
            issuer = Issuer(args.oidc_issuer)

        if args.oidc_client_secret is None:
            args.oidc_client_secret = ""  # nosec: B105

        token = issuer.identity_token(
            client_id=args.oidc_client_id, client_secret=args.oidc_client_secret
        )

    return token
