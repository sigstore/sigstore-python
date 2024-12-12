# Home

## Introduction

`sigstore` is a Python tool for generating and verifying [Sigstore] signatures.
You can use it to sign and verify Python package distributions, or anything
else!

## Features

* Support for keyless signature generation and verification with [Sigstore](https://www.sigstore.dev/)
* Support for signing with ["ambient" OpenID Connect identities](./signing.md#signing-with-ambient-credentials)
* A comprehensive [CLI](#using-sigstore) and corresponding
  [importable Python API](./API/index.md)

## Installing `sigstore`

```console
python -m pip install sigstore
```

See [installation](./installation.md) for more detailed installation instructions or options.

## Using `sigstore`

You can run `sigstore` as a standalone program, or via `python -m`:

```console
sigstore --help
python -m sigstore --help
```

- Use `sigstore` to [sign](./signing.md)
- Use `sigstore` to [verify](./verify.md)

## SLSA Provenance

This project emits a [SLSA] provenance on its release! This enables you to verify the integrity
of the downloaded artifacts and ensured that the binary's code really comes from this source code.

To do so, please follow the instructions [here](https://github.com/slsa-framework/slsa-github-generator#verification-of-provenance).

[SLSA]: https://slsa.dev/
[Sigstore]: https://www.sigstore.dev/