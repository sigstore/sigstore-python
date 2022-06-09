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
                     [--oidc-disable-ambient-providers] [--no-default-files]
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
  --no-default-files    Don't emit the default output files ({input}.sig and
                        {input}.crt) (default: False)
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
usage: sigstore verify [-h] [--certificate FILE] [--signature FILE]
                       [--cert-email EMAIL] [--cert-oidc-issuer URL]
                       [--rekor-url URL] [--staging]
                       FILE [FILE ...]

positional arguments:
  FILE                  The file to verify

options:
  -h, --help            show this help message and exit

Verification inputs:
  --certificate FILE, --cert FILE
                        The PEM-encoded certificate to verify against; not
                        used with multiple inputs (default: None)
  --signature FILE      The signature to verify against; not used with
                        multiple inputs (default: None)

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

## Example uses

`sigstore` supports a wide variety of workflows and usages. Some common ones are
provided below.

### Signing with ambient credentials

For environments that support OpenID Connect, natively `sigstore` supports ambient credential
detection. This includes many popular CI platforms and cloud providers.

| Service                     | Status    | Notes                                                                                                                                                                                                                                                                                                                  |
|-----------------------------|-----------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| GitHub Actions              | Supported | Requires the `id-token` permission; see [the docs](https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect) and [this example](https://github.com/sigstore/sigstore-python/blob/main/.github/workflows/release.yml)                             |
| Google Compute Engine (GCE) | Supported | Automatic                                                                                                                                                                                                                                                                                                              |
| Google Cloud Build (GCB)    | Supported | Requires setting `GOOGLE_SERVICE_ACCOUNT_NAME` to an appropriately configured service account name; see [the docs](https://cloud.google.com/iam/docs/creating-short-lived-service-account-credentials#sa-credentials-direct) and [this example](https://github.com/sigstore/sigstore-python/blob/main/cloudbuild.yaml) |
| GitLab CI                   | Planned   | See [#31](https://github.com/sigstore/sigstore-python/issues/31)                                                                                                                                                                                                                                                       |
| CircleCI                    | Planned   | See [#31](https://github.com/sigstore/sigstore-python/issues/31)                                                                                                                                                                                                                                                       |

Sign a single file (`foo.txt`) using an ambient OpenID Connect credential,
saving the signature and certificate to `foo.txt.sig` and `foo.txt.crt`:

```console
$ python -m sigstore sign foo.txt
```

### Signing with an email identity

`sigstore` can use an OAuth2 + OpenID flow to establish an email identity,
allowing you to request signing certificates that attest to control over
that email.

Sign a single file (`foo.txt`) using the OAuth2 flow, saving the
signature and certificate to `foo.txt.sig` and `foo.txt.crt`:

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

By default, `sigstore verify` will attempt to find a `<filename>.sig` and `<filename>.crt` in the
same directory as the file being verified:

```console
# looks for foo.txt.sig and foo.txt.crt
$ python -m sigstore verify foo.txt
```

Multiple files can be verified at once:

```console
# looks for {foo,bar}.txt.{sig,crt}
$ python -m sigstore verify foo.txt bar.txt
```

If your signature and certificate are at different paths, you can specify them
explicitly (but only for one file at a time):

```console
$ python -m sigstore verify \
    --certificate some/other/path/foo.crt \
    --signature some/other/path/foo.sig \
    foo.txt
```

### Extended verification against OpenID Connect claims

By default, `sigstore verify` only checks the validity of the certificate,
the correctness of the signature, and the consistency of both with the
certificate transparency log.

To assert further details about the signature (such as *who* or *what* signed for the artifact),
you can test against the OpenID Connect claims embedded within it.

For example, to accept the signature and certificate only if they correspond to a particular
email identity:

```console
$ python -m sigstore verify --cert-email developer@example.com foo.txt
```

Or to accept only if the OpenID Connect issuer is the expected one:

```console
$ python -m sigstore verify --cert-oidc-issuer https://github.com/login/oauth foo.txt
```

These options can be combined, and further extended validation options (e.g., for
signing results from GitHub Actions) are under development.

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
