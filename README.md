sigstore-python
===============

<!--- @begin-badges@ --->
![CI](https://github.com/sigstore/sigstore-python/workflows/CI/badge.svg)
[![PyPI version](https://badge.fury.io/py/sigstore.svg)](https://pypi.org/project/sigstore)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/sigstore/sigstore-python/badge)](https://securityscorecards.dev/viewer/?uri=github.com/sigstore/sigstore-python)
[![SLSA](https://slsa.dev/images/gh-badge-level3.svg)](https://slsa.dev/)
![Conformance Tests](https://github.com/sigstore/sigstore-python/workflows/Conformance%20Tests/badge.svg)
[![Documentation](https://github.com/sigstore/sigstore-python/actions/workflows/docs.yml/badge.svg)](https://sigstore.github.io/sigstore-python)
<!--- @end-badges@ --->

`sigstore` is a Python tool for generating and verifying Sigstore signatures.
You can use it to sign and verify Python package distributions, or anything
else!

## Index

* [Features](#features)
* [Installation](#installation)
  * [GitHub Actions](#github-actions)
* [Usage](#usage)
  * [Signing](#signing)
  * [Verifying](#verifying)
    * [Generic identities](#generic-identities)
    * [Signatures from GitHub Actions](#signatures-from-github-actions)
* [Example uses](#example-uses)
  * [Signing with ambient credentials](#signing-with-ambient-credentials)
  * [Signing with an email identity](#signing-with-an-email-identity)
  * [Signing with an explicit identity token](#signing-with-an-explicit-identity-token)
  * [Verifying against a signature and certificate](#verifying-against-a-signature-and-certificate)
  * [Verifying signatures from GitHub Actions](#verifying-signatures-from-github-actions)
* [Licensing](#licensing)
* [Community](#community)
* [Contributing](#contributing)
* [Code of Conduct](#code-of-conduct)
* [Security](#security)
* [SLSA Provenance](#slsa-provenance)

## Features

* Support for keyless signature generation and verification with [Sigstore](https://www.sigstore.dev/)
* Support for signing with ["ambient" OpenID Connect identities](https://github.com/sigstore/sigstore-python#signing-with-ambient-credentials)
* A comprehensive [CLI](https://github.com/sigstore/sigstore-python#usage) and corresponding
  [importable Python API](https://sigstore.github.io/sigstore-python)

## Installation

`sigstore` requires Python 3.8 or newer, and can be installed directly via `pip`:

```console
python -m pip install sigstore
```

Optionally, to install `sigstore` and all its dependencies with [hash-checking mode](https://pip.pypa.io/en/stable/topics/secure-installs/#hash-checking-mode) enabled, run the following:

```console
python -m pip install -r https://raw.githubusercontent.com/sigstore/sigstore-python/main/install/requirements.txt
```

This installs the requirements file located [here](https://github.com/sigstore/sigstore-python/blob/main/install/requirements.txt), which is kept up-to-date.

### GitHub Actions

`sigstore-python` has [an official GitHub Action](https://github.com/sigstore/gh-action-sigstore-python)!

You can install it from the
[GitHub Marketplace](https://github.com/marketplace/actions/gh-action-sigstore-python), or
add it to your CI manually:

```yaml
jobs:
  sigstore-python:
    steps:
      - uses: sigstore/gh-action-sigstore-python@v0.2.0
        with:
          inputs: foo.txt
```

See the
[action documentation](https://github.com/sigstore/gh-action-sigstore-python/blob/main/README.md)
for more details and usage examples.

## Usage

For Python API usage, see our [documentation](https://sigstore.github.io/sigstore-python/).

You can run `sigstore` as a standalone program, or via `python -m`:

```console
sigstore --help
python -m sigstore --help
```

Top-level:

<!-- @begin-sigstore-help@ -->
```
usage: sigstore [-h] [-v] [-V] [--staging] [--rekor-url URL]
                [--rekor-root-pubkey FILE]
                COMMAND ...

a tool for signing and verifying Python package distributions

positional arguments:
  COMMAND               the operation to perform
    sign                sign one or more inputs
    verify              verify one or more inputs
    get-identity-token  retrieve and return a Sigstore-compatible OpenID
                        Connect token

optional arguments:
  -h, --help            show this help message and exit
  -v, --verbose         run with additional debug logging; supply multiple
                        times to increase verbosity
  -V, --version         show program's version number and exit

Sigstore instance options:
  --staging             Use sigstore's staging instances, instead of the
                        default production instances (default: False)
  --rekor-url URL       The Rekor instance to use (conflicts with --staging)
                        (default: https://rekor.sigstore.dev)
  --rekor-root-pubkey FILE
                        A PEM-encoded root public key for Rekor itself
                        (conflicts with --staging) (default: None)
```
<!-- @end-sigstore-help@ -->


### Signing

<!-- @begin-sigstore-sign-help@ -->
```
usage: sigstore sign [-h] [-v] [--identity-token TOKEN] [--oidc-client-id ID]
                     [--oidc-client-secret SECRET]
                     [--oidc-disable-ambient-providers] [--oidc-issuer URL]
                     [--oauth-force-oob] [--no-default-files]
                     [--signature FILE] [--certificate FILE] [--bundle FILE]
                     [--output-directory DIR] [--overwrite] [--staging]
                     [--rekor-url URL] [--rekor-root-pubkey FILE]
                     [--fulcio-url URL] [--ctfe FILE]
                     FILE [FILE ...]

positional arguments:
  FILE                  The file to sign

optional arguments:
  -h, --help            show this help message and exit
  -v, --verbose         run with additional debug logging; supply multiple
                        times to increase verbosity

OpenID Connect options:
  --identity-token TOKEN
                        the OIDC identity token to use (default: None)
  --oidc-client-id ID   The custom OpenID Connect client ID to use during
                        OAuth2 (default: sigstore)
  --oidc-client-secret SECRET
                        The custom OpenID Connect client secret to use during
                        OAuth2 (default: None)
  --oidc-disable-ambient-providers
                        Disable ambient OpenID Connect credential detection
                        (e.g. on GitHub Actions) (default: False)
  --oidc-issuer URL     The OpenID Connect issuer to use (conflicts with
                        --staging) (default: https://oauth2.sigstore.dev/auth)
  --oauth-force-oob     Force an out-of-band OAuth flow and do not
                        automatically start the default web browser (default:
                        False)

Output options:
  --no-default-files    Don't emit the default output files ({input}.sigstore)
                        (default: False)
  --signature FILE, --output-signature FILE
                        Write a single signature to the given file; does not
                        work with multiple input files (default: None)
  --certificate FILE, --output-certificate FILE
                        Write a single certificate to the given file; does not
                        work with multiple input files (default: None)
  --bundle FILE         Write a single Sigstore bundle to the given file; does
                        not work with multiple input files (default: None)
  --output-directory DIR
                        Write default outputs to the given directory
                        (conflicts with --signature, --certificate, --bundle)
                        (default: None)
  --overwrite           Overwrite preexisting signature and certificate
                        outputs, if present (default: False)

Sigstore instance options:
  --staging             Use sigstore's staging instances, instead of the
                        default production instances. This option will be
                        deprecated in favor of the global `--staging` option
                        in a future release. (default: False)
  --rekor-url URL       The Rekor instance to use (conflicts with --staging).
                        This option will be deprecated in favor of the global
                        `--rekor-url` option in a future release. (default:
                        None)
  --rekor-root-pubkey FILE
                        A PEM-encoded root public key for Rekor itself
                        (conflicts with --staging). This option will be
                        deprecated in favor of the global `--rekor-root-
                        pubkey` option in a future release. (default: None)
  --fulcio-url URL      The Fulcio instance to use (conflicts with --staging)
                        (default: https://fulcio.sigstore.dev)
  --ctfe FILE           A PEM-encoded public key for the CT log (conflicts
                        with --staging) (default: None)
```
<!-- @end-sigstore-sign-help@ -->

### Verifying

#### Generic identities

This is the most common verification done with `sigstore`, and therefore
the one you probably want: you can use it to verify that a signature was
produced by a particular identity (like `hamilcar@example.com`), as attested
to by a particular OIDC provider (like `https://github.com/login/oauth`).

<!-- @begin-sigstore-verify-identity-help@ -->
```
usage: sigstore verify identity [-h] [-v] [--certificate FILE]
                                [--signature FILE] [--bundle FILE]
                                --cert-identity IDENTITY [--offline]
                                --cert-oidc-issuer URL [--staging]
                                [--rekor-url URL] [--rekor-root-pubkey FILE]
                                [--certificate-chain FILE]
                                FILE [FILE ...]

optional arguments:
  -h, --help            show this help message and exit
  -v, --verbose         run with additional debug logging; supply multiple
                        times to increase verbosity

Verification inputs:
  --certificate FILE, --cert FILE
                        The PEM-encoded certificate to verify against; not
                        used with multiple inputs (default: None)
  --signature FILE      The signature to verify against; not used with
                        multiple inputs (default: None)
  --bundle FILE         The Sigstore bundle to verify with; not used with
                        multiple inputs (default: None)
  FILE                  The file to verify

Verification options:
  --cert-identity IDENTITY
                        The identity to check for in the certificate's Subject
                        Alternative Name (default: None)
  --offline             Perform offline verification; requires a Sigstore
                        bundle (default: False)
  --cert-oidc-issuer URL
                        The OIDC issuer URL to check for in the certificate's
                        OIDC issuer extension (default: None)

Sigstore instance options:
  --staging             Use sigstore's staging instances, instead of the
                        default production instances. This option will be
                        deprecated in favor of the global `--staging` option
                        in a future release. (default: False)
  --rekor-url URL       The Rekor instance to use (conflicts with --staging).
                        This option will be deprecated in favor of the global
                        `--rekor-url` option in a future release. (default:
                        None)
  --rekor-root-pubkey FILE
                        A PEM-encoded root public key for Rekor itself
                        (conflicts with --staging). This option will be
                        deprecated in favor of the global `--rekor-root-
                        pubkey` option in a future release. (default: None)
  --certificate-chain FILE
                        Path to a list of CA certificates in PEM format which
                        will be needed when building the certificate chain for
                        the Fulcio signing certificate (default: None)
```
<!-- @end-sigstore-verify-identity-help@ -->

#### Signatures from GitHub Actions

If your signatures are coming from GitHub Actions (e.g., a workflow
that uses its [ambient credentials](#signing-with-ambient-credentials)),
then you can use the `sigstore verify github` subcommand to verify
claims more precisely than `sigstore verify identity` allows:

<!-- @begin-sigstore-verify-github-help@ -->
```
usage: sigstore verify github [-h] [-v] [--certificate FILE]
                              [--signature FILE] [--bundle FILE]
                              --cert-identity IDENTITY [--offline]
                              [--trigger EVENT] [--sha SHA] [--name NAME]
                              [--repository REPO] [--ref REF] [--staging]
                              [--rekor-url URL] [--rekor-root-pubkey FILE]
                              [--certificate-chain FILE]
                              FILE [FILE ...]

optional arguments:
  -h, --help            show this help message and exit
  -v, --verbose         run with additional debug logging; supply multiple
                        times to increase verbosity

Verification inputs:
  --certificate FILE, --cert FILE
                        The PEM-encoded certificate to verify against; not
                        used with multiple inputs (default: None)
  --signature FILE      The signature to verify against; not used with
                        multiple inputs (default: None)
  --bundle FILE         The Sigstore bundle to verify with; not used with
                        multiple inputs (default: None)
  FILE                  The file to verify

Verification options:
  --cert-identity IDENTITY
                        The identity to check for in the certificate's Subject
                        Alternative Name (default: None)
  --offline             Perform offline verification; requires a Sigstore
                        bundle (default: False)
  --trigger EVENT       The GitHub Actions event name that triggered the
                        workflow (default: None)
  --sha SHA             The `git` commit SHA that the workflow run was invoked
                        with (default: None)
  --name NAME           The name of the workflow that was triggered (default:
                        None)
  --repository REPO     The repository slug that the workflow was triggered
                        under (default: None)
  --ref REF             The `git` ref that the workflow was invoked with
                        (default: None)

Sigstore instance options:
  --staging             Use sigstore's staging instances, instead of the
                        default production instances. This option will be
                        deprecated in favor of the global `--staging` option
                        in a future release. (default: False)
  --rekor-url URL       The Rekor instance to use (conflicts with --staging).
                        This option will be deprecated in favor of the global
                        `--rekor-url` option in a future release. (default:
                        None)
  --rekor-root-pubkey FILE
                        A PEM-encoded root public key for Rekor itself
                        (conflicts with --staging). This option will be
                        deprecated in favor of the global `--rekor-root-
                        pubkey` option in a future release. (default: None)
  --certificate-chain FILE
                        Path to a list of CA certificates in PEM format which
                        will be needed when building the certificate chain for
                        the Fulcio signing certificate (default: None)
```
<!-- @end-sigstore-verify-github-help@ -->

## Example uses

`sigstore` supports a wide variety of workflows and usages. Some common ones are
provided below.

### Signing with ambient credentials

For environments that support OpenID Connect, natively `sigstore` supports ambient credential
detection. This includes many popular CI platforms and cloud providers. See the full list of
supported environments [here](https://github.com/di/id#supported-environments).

Sign a single file (`foo.txt`) using an ambient OpenID Connect credential,
saving the bundle to `foo.txt.sigstore`:

```console
$ python -m sigstore sign foo.txt
```

### Signing with an email identity

`sigstore` can use an OAuth2 + OpenID flow to establish an email identity,
allowing you to request signing certificates that attest to control over
that email.

Sign a single file (`foo.txt`) using the OAuth2 flow, saving the
bundle to `foo.txt.sigstore`:

```console
$ python -m sigstore sign foo.txt
```

By default, `sigstore` attempts to do
[ambient credential detection](#signing-with-ambient-credentials), which may preempt
the OAuth2 flow. To force the OAuth2 flow, you can explicitly disable ambient detection:

```console
$ python -m sigstore sign --oidc-disable-ambient-providers foo.txt
```

### Signing with an explicit identity token

If you can't use an ambient credential or the OAuth2 flow, you can pass a pre-created
identity token directly into `sigstore sign`:

```console
$ python -m sigstore sign --identity-token YOUR-LONG-JWT-HERE foo.txt
```

Note that passing a custom identity token does not circumvent Fulcio's requirements,
namely the Fulcio's supported identity providers and the claims expected within the token.

### Verifying against a signature and certificate

By default, `sigstore verify identity` will attempt to find a `<filename>.sigstore` in the
same directory as the file being verified:

```console
# looks for foo.txt.sigstore
$ python -m sigstore verify identity foo.txt \
    --cert-identity 'hamilcar@example.com' \
    --cert-oidc-issuer 'https://github.com/login/oauth'
```

Multiple files can be verified at once:

```console
# looks for {foo,bar}.txt.sigstore
$ python -m sigstore verify identity foo.txt bar.txt \
    --cert-identity 'hamilcar@example.com' \
    --cert-oidc-issuer 'https://github.com/login/oauth'
```

### Verifying signatures from GitHub Actions

`sigstore verify github` can be used to verify claims specific to signatures coming from GitHub
Actions. `sigstore-python` signs releases via GitHub Actions, so the examples below are working
examples of how you can verify a given `sigstore-python` release.

As with `sigstore verify identity`, the `--cert-identity` flag is required. However, since we know
that the signature was generated with an GitHub Actions ambient credential, the OIDC issuer is
inferred.

```console
$ python -m sigstore verify github sigstore-0.10.0-py3-none-any.whl \
    --bundle sigstore-0.10.0-py3-none-any.whl.bundle \
    --cert-identity https://github.com/sigstore/sigstore-python/.github/workflows/release.yml@refs/tags/v0.10.0
```

Additionally, GitHub Actions specific claims can be verified like so:

```console
$ python -m sigstore verify github sigstore-0.10.0-py3-none-any.whl \
    --bundle sigstore-0.10.0-py3-none-any.whl.bundle \
    --cert-identity https://github.com/sigstore/sigstore-python/.github/workflows/release.yml@refs/tags/v0.10.0 \
    --trigger release \
    --sha 66581529803929c3ccc45334632ccd90f06e0de4 \
    --name Release \
    --repository sigstore/sigstore-python \
    --ref refs/tags/v0.10.0
```

## Licensing

`sigstore` is licensed under the Apache 2.0 License.

## Community

`sigstore-python` is developed as part of the [Sigstore](https://sigstore.dev) project.

We also use a [Slack channel](https://sigstore.slack.com)!
Click [here](https://join.slack.com/t/sigstore/shared_invite/zt-mhs55zh0-XmY3bcfWn4XEyMqUUutbUQ) for the invite link.

## Contributing

See [the contributing docs](https://github.com/sigstore/.github/blob/main/CONTRIBUTING.md) for details.

## Code of Conduct

Everyone interacting with this project is expected to follow the
[sigstore Code of Conduct](https://github.com/sigstore/.github/blob/main/CODE_OF_CONDUCT.md).

## Security

Should you discover any security issues, please refer to sigstore's [security
process](https://github.com/sigstore/.github/blob/main/SECURITY.md).

### SLSA Provenance
This project emits a SLSA provenance on its release! This enables you to verify the integrity
of the downloaded artifacts and ensured that the binary's code really comes from this source code.

To do so, please follow the instructions [here](https://github.com/slsa-framework/slsa-github-generator#verification-of-provenance).
