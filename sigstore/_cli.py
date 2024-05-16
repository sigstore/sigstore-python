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
from typing import NoReturn, Optional, TextIO, Union

from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509 import load_pem_x509_certificate
from rich.logging import RichHandler

from sigstore import __version__, dsse
from sigstore._internal.fulcio.client import ExpiredCertificate
from sigstore._internal.rekor import _hashedrekord_from_parts
from sigstore._internal.trust import ClientTrustConfig
from sigstore._utils import sha256_digest
from sigstore.errors import Error, VerificationError
from sigstore.hashes import Hashed
from sigstore.models import Bundle
from sigstore.oidc import (
    DEFAULT_OAUTH_ISSUER_URL,
    ExpiredIdentity,
    IdentityToken,
    Issuer,
    detect_credential,
)
from sigstore.sign import SigningContext
from sigstore.verify import (
    Verifier,
    policy,
)

logging.basicConfig(format="%(message)s", datefmt="[%X]", handlers=[RichHandler()])
_logger = logging.getLogger(__name__)

# NOTE: We configure the top package logger, rather than the root logger,
# to avoid overly verbose logging in third-party code by default.
_package_logger = logging.getLogger("sigstore")
_package_logger.setLevel(os.environ.get("SIGSTORE_LOGLEVEL", "INFO").upper())


def _die(args: argparse.Namespace, message: str) -> NoReturn:
    """
    An `argparse` helper that fixes up the type hints on our use of
    `ArgumentParser.error`.
    """
    args._parser.error(message)
    raise ValueError("unreachable")


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


def _add_shared_verify_input_options(group: argparse._ArgumentGroup) -> None:
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
        "--bundle",
        metavar="FILE",
        type=Path,
        default=os.getenv("SIGSTORE_BUNDLE"),
        help=("The Sigstore bundle to verify with; not used with multiple inputs"),
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
        "--offline",
        action="store_true",
        default=_boolify_env("SIGSTORE_OFFLINE"),
        help="Perform offline verification; requires a Sigstore bundle",
    )


def _add_shared_oidc_options(
    group: Union[argparse._ArgumentGroup, argparse.ArgumentParser],
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
    group.add_argument(
        "--oauth-force-oob",
        action="store_true",
        default=_boolify_env("SIGSTORE_OAUTH_FORCE_OOB"),
        help="Force an out-of-band OAuth flow and do not automatically start the default web browser",
    )


def _parser() -> argparse.ArgumentParser:
    # Arguments in parent_parser can be used for both commands and subcommands
    parent_parser = argparse.ArgumentParser(add_help=False)
    parent_parser.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="run with additional debug logging; supply multiple times to increase verbosity",
    )

    parser = argparse.ArgumentParser(
        prog="sigstore",
        description="a tool for signing and verifying Python package distributions",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        parents=[parent_parser],
    )
    parser.add_argument(
        "-V", "--version", action="version", version=f"sigstore {__version__}"
    )

    global_instance_options = parser.add_mutually_exclusive_group()
    global_instance_options.add_argument(
        "--staging",
        action="store_true",
        default=_boolify_env("SIGSTORE_STAGING"),
        help="Use sigstore's staging instances, instead of the default production instances",
    )
    global_instance_options.add_argument(
        "--trust-config",
        metavar="FILE",
        type=Path,
        help="The client trust configuration to use",
    )
    subcommands = parser.add_subparsers(
        required=True,
        dest="subcommand",
        metavar="COMMAND",
        help="the operation to perform",
    )

    # `sigstore sign`
    sign = subcommands.add_parser(
        "sign",
        help="sign one or more inputs",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        parents=[parent_parser],
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
        help="Don't emit the default output files ({input}.sigstore.json)",
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
        "--bundle",
        metavar="FILE",
        type=Path,
        default=os.getenv("SIGSTORE_BUNDLE"),
        help=(
            "Write a single Sigstore bundle to the given file; does not work with multiple input "
            "files"
        ),
    )
    output_options.add_argument(
        "--output-directory",
        metavar="DIR",
        type=Path,
        default=os.getenv("SIGSTORE_OUTPUT_DIRECTORY"),
        help=(
            "Write default outputs to the given directory (conflicts with --signature, --certificate"
            ", --bundle)"
        ),
    )
    output_options.add_argument(
        "--overwrite",
        action="store_true",
        default=_boolify_env("SIGSTORE_OVERWRITE"),
        help="Overwrite preexisting signature and certificate outputs, if present",
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
        help="verify one or more inputs",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        parents=[parent_parser],
    )
    verify_subcommand = verify.add_subparsers(
        required=True,
        dest="verify_subcommand",
        metavar="COMMAND",
        help="the kind of verification to perform",
    )

    # `sigstore verify identity`
    verify_identity = verify_subcommand.add_parser(
        "identity",
        help="verify against a known identity and identity provider",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        parents=[parent_parser],
    )
    input_options = verify_identity.add_argument_group("Verification inputs")
    _add_shared_verify_input_options(input_options)

    verification_options = verify_identity.add_argument_group("Verification options")
    _add_shared_verification_options(verification_options)
    verification_options.add_argument(
        "--cert-identity",
        metavar="IDENTITY",
        type=str,
        default=os.getenv("SIGSTORE_CERT_IDENTITY"),
        help="The identity to check for in the certificate's Subject Alternative Name",
        required=True,
    )
    verification_options.add_argument(
        "--cert-oidc-issuer",
        metavar="URL",
        type=str,
        default=os.getenv("SIGSTORE_CERT_OIDC_ISSUER"),
        help="The OIDC issuer URL to check for in the certificate's OIDC issuer extension",
        required=True,
    )

    # `sigstore verify github`
    verify_github = verify_subcommand.add_parser(
        "github",
        help="verify against GitHub Actions-specific claims",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        parents=[parent_parser],
    )

    input_options = verify_github.add_argument_group("Verification inputs")
    _add_shared_verify_input_options(input_options)

    verification_options = verify_github.add_argument_group("Verification options")
    _add_shared_verification_options(verification_options)
    verification_options.add_argument(
        "--cert-identity",
        metavar="IDENTITY",
        type=str,
        default=os.getenv("SIGSTORE_CERT_IDENTITY"),
        help="The identity to check for in the certificate's Subject Alternative Name",
    )
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

    # `sigstore get-identity-token`
    get_identity_token = subcommands.add_parser(
        "get-identity-token",
        help="retrieve and return a Sigstore-compatible OpenID Connect token",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        parents=[parent_parser],
    )
    _add_shared_oidc_options(get_identity_token)

    return parser


def main() -> None:
    parser = _parser()
    args = parser.parse_args()

    # Configure logging upfront, so that we don't miss anything.
    if args.verbose >= 1:
        _package_logger.setLevel("DEBUG")
    if args.verbose >= 2:
        logging.getLogger().setLevel("DEBUG")

    _logger.debug(f"parsed arguments {args}")

    # Stuff the parser back into our namespace, so that we can use it for
    # error handling later.
    args._parser = parser

    try:
        if args.subcommand == "sign":
            _sign(args)
        elif args.subcommand == "verify":
            if args.verify_subcommand == "identity":
                _verify_identity(args)
            elif args.verify_subcommand == "github":
                _verify_github(args)
        elif args.subcommand == "get-identity-token":
            identity = _get_identity(args)
            if identity:
                print(identity)
            else:
                _die(args, "No identity token supplied or detected!")

        else:
            _die(args, f"Unknown subcommand: {args.subcommand}")
    except Error as e:
        e.log_and_exit(_logger, args.verbose >= 1)


def _sign(args: argparse.Namespace) -> None:
    has_sig = bool(args.signature)
    has_crt = bool(args.certificate)
    has_bundle = bool(args.bundle)

    # `--no-default-files` has no effect on `--bundle`, but we forbid it because
    # it indicates user confusion.
    if args.no_default_files and has_bundle:
        _die(args, "--no-default-files may not be combined with --bundle.")

    # Fail if `--signature` or `--certificate` is specified *and* we have more
    # than one input.
    if (has_sig or has_crt or has_bundle) and len(args.files) > 1:
        _die(
            args,
            "Error: --signature, --certificate, and --bundle can't be used with "
            "explicit outputs for multiple inputs.",
        )

    if args.output_directory and (has_sig or has_crt or has_bundle):
        _die(
            args,
            "Error: --signature, --certificate, and --bundle can't be used with "
            "an explicit output directory.",
        )

    # Fail if either `--signature` or `--certificate` is specified, but not both.
    if has_sig ^ has_crt:
        _die(args, "Error: --signature and --certificate must be used together.")

    # Build up the map of inputs -> outputs ahead of any signing operations,
    # so that we can fail early if overwriting without `--overwrite`.
    output_map: dict[Path, dict[str, Path | None]] = {}
    for file in args.files:
        if not file.is_file():
            _die(args, f"Input must be a file: {file}")

        sig, cert, bundle = (
            args.signature,
            args.certificate,
            args.bundle,
        )

        output_dir = args.output_directory if args.output_directory else file.parent
        if output_dir.exists() and not output_dir.is_dir():
            _die(args, f"Output directory exists and is not a directory: {output_dir}")
        output_dir.mkdir(parents=True, exist_ok=True)

        if not bundle and not args.no_default_files:
            bundle = output_dir / f"{file.name}.sigstore.json"

        if not args.overwrite:
            extants = []
            if sig and sig.exists():
                extants.append(str(sig))
            if cert and cert.exists():
                extants.append(str(cert))
            if bundle and bundle.exists():
                extants.append(str(bundle))

            if extants:
                _die(
                    args,
                    "Refusing to overwrite outputs without --overwrite: "
                    f"{', '.join(extants)}",
                )

        output_map[file] = {
            "cert": cert,
            "sig": sig,
            "bundle": bundle,
        }

    # Select the signing context to use.
    if args.staging:
        _logger.debug("sign: staging instances requested")
        signing_ctx = SigningContext.staging()
    elif args.trust_config:
        trust_config = ClientTrustConfig.from_json(args.trust_config.read_text())
        signing_ctx = SigningContext._from_trust_config(trust_config)
    else:
        # If the user didn't request the staging instance or pass in an
        # explicit client trust config, we're using the public good (i.e.
        # production) instance.
        signing_ctx = SigningContext.production()

    # The order of precedence for identities is as follows:
    #
    # 1) Explicitly supplied identity token
    # 2) Ambient credential detected in the environment, unless disabled
    # 3) Interactive OAuth flow
    identity: IdentityToken | None
    if args.identity_token:
        identity = IdentityToken(args.identity_token)
    else:
        identity = _get_identity(args)

    if not identity:
        _die(args, "No identity token supplied or detected!")

    with signing_ctx.signer(identity) as signer:
        for file, outputs in output_map.items():
            _logger.debug(f"signing for {file.name}")
            with file.open(mode="rb") as io:
                # The input can be indefinitely large, so we perform a streaming
                # digest and sign the prehash rather than buffering it fully.
                digest = sha256_digest(io)
            try:
                result = signer.sign_artifact(input_=digest)
            except ExpiredIdentity as exp_identity:
                print("Signature failed: identity token has expired")
                raise exp_identity

            except ExpiredCertificate as exp_certificate:
                print("Signature failed: Fulcio signing certificate has expired")
                raise exp_certificate

            print("Using ephemeral certificate:")
            cert = result.signing_certificate
            cert_pem = cert.public_bytes(Encoding.PEM).decode()
            print(cert_pem)

            print(
                f"Transparency log entry created at index: {result.log_entry.log_index}"
            )

            sig_output: TextIO
            if outputs["sig"] is not None:
                sig_output = outputs["sig"].open("w")
            else:
                sig_output = sys.stdout

            signature = base64.b64encode(
                result._inner.message_signature.signature
            ).decode()
            print(signature, file=sig_output)
            if outputs["sig"] is not None:
                print(f"Signature written to {outputs['sig']}")

            if outputs["cert"] is not None:
                with outputs["cert"].open(mode="w") as io:
                    print(cert_pem, file=io)
                print(f"Certificate written to {outputs['cert']}")

            if outputs["bundle"] is not None:
                with outputs["bundle"].open(mode="w") as io:
                    print(result.to_json(), file=io)
                print(f"Sigstore bundle written to {outputs['bundle']}")


def _collect_verification_state(
    args: argparse.Namespace,
) -> tuple[Verifier, list[tuple[Path, Hashed, Bundle]]]:
    """
    Performs CLI functionality common across all `sigstore verify` subcommands.

    Returns a tuple of the active verifier instance and a list of `(path, hashed, bundle)`
    tuples, where `path` is the filename for display purposes, `hashed` is the
    pre-hashed input to the file being verified and `bundle` is the `Bundle` to verify with.
    """

    # Fail if --certificate, --signature, or --bundle is specified and we
    # have more than one input.
    if (args.certificate or args.signature or args.bundle) and len(args.files) > 1:
        _die(
            args,
            "--certificate, --signature, or --bundle can only be used "
            "with a single input file",
        )

    # Fail if `--certificate` or `--signature` is used with `--bundle`.
    if args.bundle and (args.certificate or args.signature):
        _die(args, "--bundle cannot be used with --certificate or --signature")

    # Fail if `--certificate` or `--signature` is used with `--offline`.
    if args.offline and (args.certificate or args.signature):
        _die(args, "--offline cannot be used with --certificate or --signature")

    # The converse of `sign`: we build up an expected input map and check
    # that we have everything so that we can fail early.
    input_map = {}
    for file in args.files:
        if not file.is_file():
            _die(args, f"Input must be a file: {file}")

        sig, cert, bundle = (
            args.signature,
            args.certificate,
            args.bundle,
        )
        if sig is None:
            sig = file.parent / f"{file.name}.sig"
        if cert is None:
            cert = file.parent / f"{file.name}.crt"
        if bundle is None:
            # NOTE(ww): If the user hasn't specified a bundle via `--bundle` and
            # `{input}.sigstore.json` doesn't exist, then we try `{input}.sigstore`
            # for backwards compatibility.
            legacy_default_bundle = file.parent / f"{file.name}.sigstore"
            bundle = file.parent / f"{file.name}.sigstore.json"

            if not bundle.is_file() and legacy_default_bundle.is_file():
                _logger.warning(
                    f"{file}: {legacy_default_bundle} should be named {bundle}. "
                    "Support for discovering 'bare' .sigstore inputs will be deprecated in "
                    "a future release."
                )
                bundle = legacy_default_bundle
            elif bundle.is_file() and legacy_default_bundle.is_file():
                # Don't allow the user to implicitly verify `{input}.sigstore.json` if
                # `{input}.sigstore` is also present, since this implies user confusion.
                _die(
                    args,
                    f"Conflicting inputs: {bundle} and {legacy_default_bundle}",
                )

        missing = []
        if args.signature or args.certificate:
            if not sig.is_file():
                missing.append(str(sig))
            if not cert.is_file():
                missing.append(str(cert))
            input_map[file] = {"cert": cert, "sig": sig}
        else:
            # If a user hasn't explicitly supplied `--signature` or `--certificate`,
            # we expect a bundle either supplied via `--bundle` or with the
            # default `{input}.sigstore(.json)?` name.
            if not bundle.is_file():
                missing.append(str(bundle))

            input_map[file] = {"bundle": bundle}

        if missing:
            _die(
                args,
                f"Missing verification materials for {(file)}: {', '.join(missing)}",
            )
    if args.staging:
        _logger.debug("verify: staging instances requested")
        verifier = Verifier.staging()
    elif args.trust_config:
        trust_config = ClientTrustConfig.from_json(args.trust_config.read_text())
        verifier = Verifier._from_trust_config(trust_config)
    else:
        verifier = Verifier.production()

    all_materials = []
    for file, inputs in input_map.items():
        with file.open(mode="rb") as io:
            hashed = sha256_digest(io)

        if "bundle" in inputs:
            # Load the bundle
            _logger.debug(f"Using bundle from: {inputs['bundle']}")

            bundle_bytes = inputs["bundle"].read_bytes()
            bundle = Bundle.from_json(bundle_bytes)
        else:
            # Load the signing certificate
            _logger.debug(f"Using certificate from: {inputs['cert']}")
            cert = load_pem_x509_certificate(inputs["cert"].read_bytes())

            # Load the signature
            _logger.debug(f"Using signature from: {inputs['sig']}")
            b64_signature = inputs["sig"].read_text()
            signature = base64.b64decode(b64_signature)

            # When using "detached" materials, we *must* retrieve the log
            # entry from the online log.
            # TODO: This should be abstracted somewhere much better.
            log_entry = verifier._rekor.log.entries.retrieve.post(
                _hashedrekord_from_parts(cert, signature, hashed)
            )
            if log_entry is None:
                _die(args, f"No matching log entry for {file}'s verification materials")
            bundle = Bundle.from_parts(cert, signature, log_entry)

        _logger.debug(f"Verifying contents from: {file}")

        all_materials.append((file, hashed, bundle))

    return (verifier, all_materials)


def _verify_identity(args: argparse.Namespace) -> None:
    verifier, materials = _collect_verification_state(args)

    for file, hashed, bundle in materials:
        policy_ = policy.Identity(
            identity=args.cert_identity,
            issuer=args.cert_oidc_issuer,
        )

        try:
            _verify_common(verifier, hashed, bundle, policy_)
            print(f"OK: {file}")
        except Error as exc:
            _logger.error(f"FAIL: {file}")
            exc.log_and_exit(_logger, args.verbose >= 1)


def _verify_github(args: argparse.Namespace) -> None:
    inner_policies: list[policy.VerificationPolicy] = []

    # We require at least one of `--cert-identity` or `--repository`,
    # to minimize the risk of user confusion about what's being verified.
    if not (args.cert_identity or args.workflow_repository):
        _die(args, "--cert-identity or --repository is required")

    # No matter what the user configures above, we require the OIDC issuer to
    # be GitHub Actions.
    inner_policies.append(
        policy.OIDCIssuer("https://token.actions.githubusercontent.com")
    )

    if args.cert_identity:
        inner_policies.append(
            policy.Identity(
                identity=args.cert_identity,
                # We always explicitly check the issuer below, so configuring
                # it here is unnecessary.
                issuer=None,
            )
        )
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

    verifier, materials = _collect_verification_state(args)
    for file, hashed, bundle in materials:
        try:
            _verify_common(verifier, hashed, bundle, policy_)
            print(f"OK: {file}")
        except Error as exc:
            _logger.error(f"FAIL: {file}")
            exc.log_and_exit(_logger, args.verbose >= 1)


def _verify_common(
    verifier: Verifier,
    hashed: Hashed,
    bundle: Bundle,
    policy_: policy.VerificationPolicy,
) -> None:
    """
    Common verification handling.

    This dispatches to either artifact or DSSE verification, depending on
    `bundle`'s inner type.
    """

    # If the bundle specifies a DSSE envelope, perform DSSE verification
    # and assert that the inner payload is an in-toto statement bound
    # to a subject matching the input's digest.
    if bundle._dsse_envelope:
        type_, payload = verifier.verify_dsse(bundle=bundle, policy=policy_)
        if type_ != dsse.Envelope._TYPE:
            raise VerificationError(f"expected JSON payload for DSSE, got {type_}")

        stmt = dsse.Statement(payload)
        if not stmt._matches_digest(hashed):
            raise VerificationError(
                f"in-toto statement has no subject for digest {hashed.digest.hex()}"
            )
    else:
        verifier.verify_artifact(
            input_=hashed,
            bundle=bundle,
            policy=policy_,
        )


def _get_identity(args: argparse.Namespace) -> Optional[IdentityToken]:
    token = None
    if not args.oidc_disable_ambient_providers:
        token = detect_credential()

    # Happy path: we've detected an ambient credential, so we can return early.
    if token:
        return IdentityToken(token)

    if args.staging:
        issuer = Issuer.staging()
    elif args.oidc_issuer == DEFAULT_OAUTH_ISSUER_URL:
        issuer = Issuer.production()
    else:
        issuer = Issuer(args.oidc_issuer)

    if args.oidc_client_secret is None:
        args.oidc_client_secret = ""  # nosec: B105

    token = issuer.identity_token(
        client_id=args.oidc_client_id,
        client_secret=args.oidc_client_secret,
        force_oob=args.oauth_force_oob,
    )

    return token
