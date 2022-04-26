sigstore-python
===============

⚠️ This project is not ready for use! ⚠️

`sigstore` is a tool for signing and verifying Python package distributions.

This project is developed by [Trail of Bits](https://www.trailofbits.com/) with
support from Google. This is not an official Google product.

## Features

### Signing

* Support for signing Python package distributions using an OpenID Connect identity
* Support for publishing signatures to a [Rekor](https://github.com/sigstore/rekor) instance

### Verifying

* Support for verifying signatures on Python package distributions

## Installation

`sigstore` requires Python 3.7 or newer, and can be installed directly via `pip`:

```console
python -m pip install sigstore
```

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
  --help  Show this message and exit.

Commands:
  sign
  verify
```
<!-- @end-sigstore-help@ -->

Signing:

<!-- @begin-sigstore-sign-help@ -->
```
Usage: sigstore sign [OPTIONS] FILE

Options:
  --identity-token TEXT
  --ctfe FILENAME
  --help                 Show this message and exit.
```
<!-- @end-sigstore-sign-help@ -->

Verifying

<!-- @begin-sigstore-verify-help@ -->
```
Usage: sigstore verify [OPTIONS] FILE

Options:
  --cert FILENAME       [required]
  --signature FILENAME  [required]
  --cert-email TEXT
  --help                Show this message and exit.
```
<!-- @end-sigstore-verify-help@ -->

## Licensing

`pip-audit` is licensed under the Apache 2.0 License.

## Code of Conduct
Everyone interacting with this project is expected to follow the
[PSF Code of Conduct](https://github.com/pypa/.github/blob/main/CODE_OF_CONDUCT.md).

