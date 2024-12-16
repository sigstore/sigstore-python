# Installation

## With `pip`

`sigstore` requires Python 3.9 or newer, and can be installed directly via `pip`:

```console
python -m pip install sigstore
```

Optionally, to install `sigstore` and all its dependencies with [hash-checking mode](https://pip.pypa.io/en/stable/topics/secure-installs/#hash-checking-mode) enabled, run the following:

```console
python -m pip install -r https://raw.githubusercontent.com/sigstore/sigstore-python/main/install/requirements.txt
```

This installs the requirements file located [here](https://github.com/sigstore/sigstore-python/blob/main/install/requirements.txt), which is kept up-to-date.

## With `uv`

!!! warning
    
    `sigstore` depends on `betterproto` pre-releases versions, which are by default not resolved by `uv`.

```console
uv pip install --prerelease=allow sigstore
```

`sigstore` can also be used as tool:

```console
uvx --prerelease=allow sigstore --help
```

## GitHub Actions

`sigstore-python` has [an official GitHub Action](https://github.com/sigstore/gh-action-sigstore-python)!

You can install it from the [GitHub Marketplace](https://github.com/marketplace/actions/gh-action-sigstore-python), or
add it to your CI manually:

```yaml
jobs:
  sigstore-python:
    steps:
      - uses: sigstore/gh-action-sigstore-python@v3.0.0
        with:
          inputs: foo.txt
```

See the [action documentation](https://github.com/sigstore/gh-action-sigstore-python/blob/main/README.md) for more details and usage examples.