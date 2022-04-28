Contributing to sigstore
========================

Thank you for your interest in contributing to `sigstore`!

The information below will help you set up a local development environment,
as well as performing common development tasks.

## Requirements

`sigstore`'s only development environment requirement *should* be Python 3.7
or newer. Development and testing is actively performed on macOS and Linux,
but Windows and other supported platforms that are supported by Python
should also work.

If you're on a system that has GNU Make, you can use the convenience targets
included in the `Makefile` that comes in the `sigstore` repository detailed
below. But this isn't required; all steps can be done without Make.

## Development steps

First, clone this repository:

```bash
git clone https://github.com/sigstore/sigstore-python
cd sigstore
```

Then, use one of the `Makefile` targets to run a task. The first time this is
run, this will also set up the local development virtual environment, and will
install `sigstore` as an editable package into this environment.

Any changes you make to the `sigstore` source tree will take effect
immediately in the virtual environment.

### Linting

You can lint locally with:

```bash
make lint
```

`sigstore` is automatically linted and formatted with a collection of tools:

* [`black`](https://github.com/psf/black): Code formatting
* [`isort`](https://github.com/PyCQA/isort): Import sorting, ordering
* [`flake8`](https://flake8.pycqa.org/en/latest/): PEP-8 linting, style enforcement
* [`mypy`](https://mypy.readthedocs.io/en/stable/): Static type checking
* [`interrogate`](https://interrogate.readthedocs.io/en/latest/): Documentation coverage


### Testing

You can run the tests locally with:

```bash
make test
```

You can also filter by a pattern (uses `pytest -k`):

```bash
make test TESTS=test_version
```

To test a specific file:

```bash
make test T=path/to/file.py
```

`sigstore` has a [`pytest`](https://docs.pytest.org/)-based unit test suite,
including code coverage with [`coverage.py`](https://coverage.readthedocs.io/).

### Documentation

If you're running Python 3.7 or newer, you can run the documentation build locally:

```bash
make doc
```

`sigstore` uses [`pdoc3`](https://github.com/pdoc3/pdoc) to generate HTML documentation for
the public Python APIs.

Live documentation for the `main` branch is hosted
[here](https://trailofbits.github.io/sigstore/). Only the public APIs are
documented, all undocumented APIs are **intentionally private and unstable.**

### Releasing

**NOTE**: If you're a non-maintaining contributor, you don't need the steps
here! They're documented for completeness and for onboarding future maintainers.

Releases of `sigstore` are managed with [`bump`](https://github.com/di/bump)
and GitHub Actions.

```bash
# default release (patch bump)
make release

# override the default
# vX.Y.Z -> vX.Y.Z-rc.0
make release BUMP_ARGS="--pre rc.0"

# vX.Y.Z -> vN.0.0
make release BUMP_ARGS="--major"
```

`make release` will fail if there are any untracked changes in the source tree.

If `make release` succeeds, you'll see an output like this:

```
RUN ME MANUALLY: git push origin main && git push origin vX.Y.Z
```

Run that last command sequence to complete the release.

## Development practices

Here are some guidelines to follow if you're working on a new feature or changes to
`sigstore`'s internal APIs:

* *Keep the `sigstore` APIs as private as possible*. Nearly all of `sigstore`'s
APIs should be private and treated as unstable and unsuitable for public use.
If you're adding a new module to the source tree, prefix the filename with an underscore to
emphasize that it's an internal (e.g., `sigstore/_foo.py` instead of `sigstore/foo.py`).

* *Perform judicious debug logging.* `sigstore` uses the standard Python
[`logging`](https://docs.python.org/3/library/logging.html) module. Use
`logger.debug` early and often -- users who experience errors can submit better
bug reports when their debug logs include helpful context!

* *Update the [CHANGELOG](./CHANGELOG.md)*. If your changes are public or result
in changes to `sigstore`'s CLI, please record them under the "Unreleased" section,
with an entry in an appropriate subsection ("Added", "Changed", "Removed", or "Fixed").
