sigstore-python
===============

<!--- @begin-badges@ --->
![CI](https://github.com/sigstore/sigstore-python/workflows/CI/badge.svg)
[![PyPI version](https://badge.fury.io/py/sigstore.svg)](https://pypi.org/project/sigstore)
<!--- @end-badges@ --->

⚠️ This project is not ready for general-purpose use! ⚠️

`sigstore` is a tool for signing and verifying Python package distributions.

## Features

* Support for signing Python package distributions using an OpenID Connect identity
* Support for publishing signatures to a [Rekor](https://github.com/sigstore/rekor) instance
* Support for verifying signatures on Python package distributions

## Installation

`sigstore` requires Python 3.7 or newer, and can be installed directly via `pip`:

```console
python -m pip install sigstore
```

Optionally, to install `sigstore` and all its dependencies with [hash-checking mode](https://pip.pypa.io/en/stable/topics/secure-installs/#hash-checking-mode) enabled, run the following:

```console
python -m pip install -r <(curl -s https://raw.githubusercontent.com/sigstore/sigstore-python/main/install/requirements.txt)
```

This installs the requirements file located [here](https://github.com/sigstore/sigstore-python/blob/main/install/requirements.txt), which is kept up-to-date.

## Usage

You can run `sigstore` as a standalone program, or via `python -m`:

```console
sigstore --help
python -m sigstore --help
```

Top-level:

<!-- @begin-sigstore-help@ -->
```
usage: sigstore [-h] [-V] {sign,verify} ...

a tool for signing and verifying Python package distributions

positional arguments:
  {sign,verify}

options:
  -h, --help     show this help message and exit
  -V, --version  show program's version number and exit
```
<!-- @end-sigstore-help@ -->

Signing:

<!-- @begin-sigstore-sign-help@ -->
```
usage: sigstore sign [-h] [--identity-token TOKEN] [--oidc-client-id ID]
                     [--oidc-client-secret SECRET]
                     [--oidc-disable-ambient-providers] [--output]
                     [--output-signature FILE] [--output-certificate FILE]
                     [--overwrite] [--fulcio-url URL] [--rekor-url URL]
                     [--ctfe FILE] [--rekor-root-pubkey FILE]
                     [--oidc-issuer URL] [--staging]
                     FILE [FILE ...]

positional arguments:
  FILE                  The file to sign

options:
  -h, --help            show this help message and exit

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

Output options:
  --output              Write signature and certificate results to default
                        files ({input}.sig and {input}.crt) (default: False)
  --output-signature FILE
                        Write a single signature to the given file; conflicts
                        with --output and does not work with multiple input
                        files (default: None)
  --output-certificate FILE
                        Write a single certificate to the given file;
                        conflicts with --output and does not work with
                        multiple input files (default: None)
  --overwrite           Overwrite preexisting signature and certificate
                        outputs, if present (default: False)

Sigstore instance options:
  --fulcio-url URL      The Fulcio instance to use (conflicts with --staging)
                        (default: https://fulcio.sigstore.dev)
  --rekor-url URL       The Rekor instance to use (conflicts with --staging)
                        (default: https://rekor.sigstore.dev)
  --ctfe FILE           A PEM-encoded public key for the CT log (conflicts
                        with --staging) (default: ctfe.pub (embedded))
  --rekor-root-pubkey FILE
                        A PEM-encoded root public key for Rekor itself
                        (conflicts with --staging) (default: rekor.pub
                        (embedded))
  --oidc-issuer URL     The OpenID Connect issuer to use (conflicts with
                        --staging) (default: https://oauth2.sigstore.dev/auth)
  --staging             Use sigstore's staging instances, instead of the
                        default production instances (default: False)
```
<!-- @end-sigstore-sign-help@ -->

Verifying:

<!-- @begin-sigstore-verify-help@ -->
```
usage: sigstore verify [-h] --certificate FILE --signature FILE
                       [--cert-email EMAIL] [--cert-oidc-issuer URL]
                       [--rekor-url URL] [--staging]
                       FILE

positional arguments:
  FILE                  The file to verify

options:
  -h, --help            show this help message and exit

Verification inputs:
  --certificate FILE, --cert FILE
                        The PEM-encoded certificate to verify against
                        (default: None)
  --signature FILE      The signature to verify against (default: None)

Extended verification options:
  --cert-email EMAIL    The email address to check for in the certificate's
                        Subject Alternative Name (default: None)
  --cert-oidc-issuer URL
                        The OIDC issuer URL to check for in the certificate's
                        OIDC issuer extension (default: None)

Sigstore instance options:
  --rekor-url URL       The Rekor instance to use (conflicts with --staging)
                        (default: https://rekor.sigstore.dev)
  --staging             Use sigstore's staging instances, instead of the
                        default production instances (default: False)
```
<!-- @end-sigstore-verify-help@ -->

### Ambient credential detection

For environments that support OIDC natively, `sigstore` supports automatic ambient credential detection:

- GitHub:
  - Actions: requires setting the `id-token` permission, see https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect. An example is [here](https://github.com/sigstore/sigstore-python/blob/main/.github/workflows/release.yml).
- Google Cloud:
  - Compute Engine: automatic
  - Cloud Build: requires setting `GOOGLE_SERVICE_ACCOUNT_NAME` to an appropriately configured service account name, see https://cloud.google.com/iam/docs/creating-short-lived-service-account-credentials#sa-credentials-direct. An example is [here](https://github.com/sigstore/sigstore-python/blob/main/cloudbuild.yaml)
- GitLab: planned, see https://github.com/sigstore/sigstore-python/issues/31
- CircleCI: planned, see https://github.com/sigstore/sigstore-python/issues/31

## Licensing

`sigstore` is licensed under the Apache 2.0 License.

## Contributing

See [the contributing docs](https://github.com/sigstore/.github/blob/main/CONTRIBUTING.md) for details.

## Code of Conduct
Everyone interacting with this project is expected to follow the
[sigstore Code of Conduct](https://github.com/sigstore/.github/blob/main/CODE_OF_CONDUCT.md).

## Security

Should you discover any security issues, please refer to sigstore's [security
process](https://github.com/sigstore/.github/blob/main/SECURITY.md).

## Info

`sigstore-python` is developed as part of the [`sigstore`](https://sigstore.dev) project.

We also use a [slack channel](https://sigstore.slack.com)!
Click [here](https://join.slack.com/t/sigstore/shared_invite/zt-mhs55zh0-XmY3bcfWn4XEyMqUUutbUQ) for the invite link.
