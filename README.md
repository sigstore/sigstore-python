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
Usage: sigstore [OPTIONS] COMMAND [ARGS]...

Options:
  --version  Show the version and exit.
  --help     Show this message and exit.

Commands:
  sign
  verify
```
<!-- @end-sigstore-help@ -->

Signing:

<!-- @begin-sigstore-sign-help@ -->
```
Usage: sigstore sign [OPTIONS] FILE [FILE ...]

Options:
  --identity-token TOKEN          the OIDC identity token to use
  --ctfe FILENAME                 A PEM-encoded public key for the CT log
                                  (conflicts with --staging)
  --oidc-client-id ID             The custom OpenID Connect client ID to use
  --oidc-client-secret SECRET     The custom OpenID Connect client secret to
                                  use
  --oidc-issuer URL               The custom OpenID Connect issuer to use
                                  (conflicts with --staging)
  --staging                       Use the sigstore project's staging
                                  instances, instead of the default production
                                  instances
  --oidc-disable-ambient-providers
                                  Disable ambient OIDC detection (e.g. on
                                  GitHub Actions)
  --output-signature FILE         With a value, write a single signature to
                                  the given file; without a value, write each
                                  signing result to {input}.sig
  --output-certificate FILE       With a value, write a single signing
                                  certificate to the given file; without a
                                  value, write each signing certificate to
                                  {input}.cert
  --fulcio-url URL                The Fulcio instance to use (conflicts with
                                  --staging)  [default:
                                  https://fulcio.sigstore.dev]
  --rekor-url URL                 The Rekor instance to use (conflicts with
                                  --staging)  [default:
                                  https://rekor.sigstore.dev]
  --help                          Show this message and exit.
```
<!-- @end-sigstore-sign-help@ -->

Verifying:

<!-- @begin-sigstore-verify-help@ -->
```
Usage: sigstore verify [OPTIONS] FILE [FILE ...]

Options:
  --cert FILENAME          The PEM-encoded certificate to verify against
                           [required]
  --signature FILENAME     The signature to verify against  [required]
  --cert-email TEXT        The email address (or other identity string) to
                           check for in the certificate's Subject Alternative
                           Name
  --cert-oidc-issuer TEXT  The OIDC issuer URL to check for in the
                           certificate's OIDC issuer extension
  --staging                Use the sigstore project's staging instances,
                           instead of the default production instances
  --rekor-url URL          The Rekor instance to use (conflicts with
                           --staging)  [default: https://rekor.sigstore.dev]
  --help                   Show this message and exit.
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
