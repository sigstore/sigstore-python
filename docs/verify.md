# Verifying

## Generic identities

This is the most common verification done with `sigstore`, and therefore
the one you probably want: you can use it to verify that a signature was
produced by a particular identity (like `hamilcar@example.com`), as attested
to by a particular OIDC provider (like `https://github.com/login/oauth`).

```console
$ sigstore verify identity --cert-identity <IDENTITY> --cert-oidc-issuer <URL> FILE_OR_DIGEST
```

The following command will verify that the bundle `tests/assets/bundle.txt.sigstore` was signed by `a@tny.town` using
the staging infrastructure of `sigstore`.

```console
$ sigstore --staging verify identity --cert-identity "a@tny.town" --cert-oidc-issuer "https://github.com/login/oauth" test/assets/bundle.txt
```

## Verifying from GitHub Actions

If your signatures are coming from GitHub Actions (e.g., a workflow that uses its [ambient credentials](./signing.md#signing-with-ambient-credentials)),
then you can use the `sigstore verify github` subcommand to verify
claims more precisely than `sigstore verify identity` allows.

`sigstore verify github` can be used to verify claims specific to signatures coming from GitHub
Actions. `sigstore-python` signs releases via GitHub Actions, so the examples below are working
examples of how you can verify a given `sigstore-python` release.

When using `sigstore verify github`, you must pass `--cert-identity` or `--repository`, or both.
Unlike `sigstore verify identity`, `--cert-oidc-issuer` is **not** required (since it's
inferred to be GitHub Actions).

Verifying with `--cert-identity`:

```console
$ sigstore verify github sigstore-0.10.0-py3-none-any.whl \
    --bundle sigstore-0.10.0-py3-none-any.whl.bundle \
    --cert-identity https://github.com/sigstore/sigstore-python/.github/workflows/release.yml@refs/tags/v0.10.0
```

Verifying with `--repository`:

```console
$ sigstore verify github sigstore-0.10.0-py3-none-any.whl \
    --bundle sigstore-0.10.0-py3-none-any.whl.bundle \
    --repository sigstore/sigstore-python
```

Additional GitHub Actions specific claims can be verified like so:

```console
$ sigstore verify github sigstore-0.10.0-py3-none-any.whl \
    --bundle sigstore-0.10.0-py3-none-any.whl.bundle \
    --cert-identity https://github.com/sigstore/sigstore-python/.github/workflows/release.yml@refs/tags/v0.10.0 \
    --trigger release \
    --sha 66581529803929c3ccc45334632ccd90f06e0de4 \
    --name Release \
    --repository sigstore/sigstore-python \
    --ref refs/tags/v0.10.0
```

## Verifying against a bundle

By default, `sigstore verify identity` will attempt to find a `<filename>.sigstore.json`
or `<filename>.sigstore` in the same directory as the file being verified:

```console
# looks for foo.txt.sigstore.json
$ sigstore verify identity foo.txt \
    --cert-identity 'hamilcar@example.com' \
    --cert-oidc-issuer 'https://github.com/login/oauth'
```

Multiple files can be verified at once:

```console
# looks for {foo,bar}.txt.sigstore.json
$ python -m sigstore verify identity foo.txt bar.txt \
    --cert-identity 'hamilcar@example.com' \
    --cert-oidc-issuer 'https://github.com/login/oauth'
```

## Verifying a digest instead of a file

`sigstore-python` supports verifying digests directly, without requiring the artifact to be
present. The digest should be prefixed with the `sha256:` string:

```console
$ sigstore verify identity sha256:ce8ab2822671752e201ea1e19e8c85e73d497e1c315bfd9c25f380b7625d1691 \
    --cert-identity 'hamilcar@example.com' \
    --cert-oidc-issuer 'https://github.com/login/oauth'
    --bundle 'foo.txt.sigstore.json'
```