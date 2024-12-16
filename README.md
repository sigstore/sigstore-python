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
* [Usage](#usage)
  * [Signing](#signing)
  * [Verifying](#verifying)
    * [Generic identities](#generic-identities)
    * [Signatures from GitHub Actions](#signatures-from-github-actions)
  * [Advanced usage](#advanced-usage)
* [Documentation](#documentation)
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

`sigstore` requires Python 3.9 or newer, and can be installed directly via `pip`:

```console
python -m pip install sigstore
```

See the [installation](https://sigstore.github.io/sigstore-python/installation) page in the documentation for more
installation options.

## Usage

For Python API usage, see our [API](https://sigstore.github.io/sigstore-python/api/).

You can run `sigstore` as a standalone program:

```console
sigstore --help
```

Top-level:

<!-- @begin-sigstore-help@ -->
```
usage: sigstore [-h] [-v] [-V] [--staging | --trust-config FILE] COMMAND ...

a tool for signing and verifying Python package distributions

positional arguments:
  COMMAND              the operation to perform
    attest             sign one or more inputs using DSSE
    sign               sign one or more inputs
    verify             verify one or more inputs
    get-identity-token
                       retrieve and return a Sigstore-compatible OpenID
                       Connect token
    plumbing           developer-only plumbing operations

optional arguments:
  -h, --help           show this help message and exit
  -v, --verbose        run with additional debug logging; supply multiple
                       times to increase verbosity (default: 0)
  -V, --version        show program's version number and exit
  --staging            Use sigstore's staging instances, instead of the
                       default production instances (default: False)
  --trust-config FILE  The client trust configuration to use (default: None)
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
                     [--output-directory DIR] [--overwrite]
                     FILE [FILE ...]

positional arguments:
  FILE                  The file to sign

optional arguments:
  -h, --help            show this help message and exit
  -v, --verbose         run with additional debug logging; supply multiple
                        times to increase verbosity (default: 0)

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
  --no-default-files    Don't emit the default output files
                        ({input}.sigstore.json) (default: False)
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
```
<!-- @end-sigstore-sign-help@ -->


### Signing with DSSE envelopes

<!-- @begin-sigstore-attest-help@ -->
```
usage: sigstore attest [-h] [-v] --predicate FILE --predicate-type TYPE
                       [--identity-token TOKEN] [--oidc-client-id ID]
                       [--oidc-client-secret SECRET]
                       [--oidc-disable-ambient-providers] [--oidc-issuer URL]
                       [--oauth-force-oob] [--bundle FILE] [--overwrite]
                       FILE [FILE ...]

positional arguments:
  FILE                  The file to sign

optional arguments:
  -h, --help            show this help message and exit
  -v, --verbose         run with additional debug logging; supply multiple
                        times to increase verbosity (default: 0)

DSSE options:
  --predicate FILE      Path to the predicate file (default: None)
  --predicate-type TYPE
                        Specify a predicate type
                        (https://slsa.dev/provenance/v0.2,
                        https://slsa.dev/provenance/v1) (default: None)

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
  --bundle FILE         Write a single Sigstore bundle to the given file; does
                        not work with multiple input files (default: None)
  --overwrite           Overwrite preexisting bundle outputs, if present
                        (default: False)
```
<!-- @end-sigstore-attest-help@ -->

### Verifying

#### Identities

<!-- @begin-sigstore-verify-identity-help@ -->
```
usage: sigstore verify identity [-h] [-v] [--certificate FILE]
                                [--signature FILE] [--bundle FILE] [--offline]
                                --cert-identity IDENTITY --cert-oidc-issuer
                                URL
                                FILE_OR_DIGEST [FILE_OR_DIGEST ...]

optional arguments:
  -h, --help            show this help message and exit
  -v, --verbose         run with additional debug logging; supply multiple
                        times to increase verbosity (default: 0)

Verification inputs:
  --certificate FILE, --cert FILE
                        The PEM-encoded certificate to verify against; not
                        used with multiple inputs (default: None)
  --signature FILE      The signature to verify against; not used with
                        multiple inputs (default: None)
  --bundle FILE         The Sigstore bundle to verify with; not used with
                        multiple inputs (default: None)
  FILE_OR_DIGEST        The file path or the digest to verify. The digest
                        should start with the 'sha256:' prefix.

Verification options:
  --offline             Perform offline verification; requires a Sigstore
                        bundle (default: False)
  --cert-identity IDENTITY
                        The identity to check for in the certificate's Subject
                        Alternative Name (default: None)
  --cert-oidc-issuer URL
                        The OIDC issuer URL to check for in the certificate's
                        OIDC issuer extension (default: None)
```
<!-- @end-sigstore-verify-identity-help@ -->

#### Signatures from GitHub Actions

<!-- @begin-sigstore-verify-github-help@ -->
```
usage: sigstore verify github [-h] [-v] [--certificate FILE]
                              [--signature FILE] [--bundle FILE] [--offline]
                              [--cert-identity IDENTITY] [--trigger EVENT]
                              [--sha SHA] [--name NAME] [--repository REPO]
                              [--ref REF]
                              FILE_OR_DIGEST [FILE_OR_DIGEST ...]

optional arguments:
  -h, --help            show this help message and exit
  -v, --verbose         run with additional debug logging; supply multiple
                        times to increase verbosity (default: 0)

Verification inputs:
  --certificate FILE, --cert FILE
                        The PEM-encoded certificate to verify against; not
                        used with multiple inputs (default: None)
  --signature FILE      The signature to verify against; not used with
                        multiple inputs (default: None)
  --bundle FILE         The Sigstore bundle to verify with; not used with
                        multiple inputs (default: None)
  FILE_OR_DIGEST        The file path or the digest to verify. The digest
                        should start with the 'sha256:' prefix.

Verification options:
  --offline             Perform offline verification; requires a Sigstore
                        bundle (default: False)
  --cert-identity IDENTITY
                        The identity to check for in the certificate's Subject
                        Alternative Name (default: None)
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
```
<!-- @end-sigstore-verify-github-help@ -->

## Documentation

`sigstore` documentation is available on [https://sigstore.github.io/sigstore-python](https://sigstore.github.io/sigstore-python)

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
