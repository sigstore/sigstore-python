# Changelog

All notable changes to `sigstore-python` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

All versions prior to 0.9.0 are untracked.

## [Unreleased]

### Added

* `sigstore` now supports the `-v`/`--verbose` flag as an alternative to
  `SIGSTORE_LOGLEVEL` for debug logging
  ([#372](https://github.com/sigstore/sigstore-python/pull/372))

* The `sigstore verify identity` has been added, and is functionally
  equivalent to the existing `sigstore verify` subcommand.
  `sigstore verify` is unchanged, but will be marked deprecated in a future
  stable version of `sigstore-python`
  ([#379](https://github.com/sigstore/sigstore-python/pull/379))

* `sigstore` now has a public, importable Python API! You can find its
  documentation [here](https://sigstore.github.io/sigstore-python/)
  ([#383](https://github.com/sigstore/sigstore-python/pull/383))

* `sigstore --staging` is now the intended way to request Sigstore's staging
   instance, rather than per-subcommand options like `sigstore sign --staging`.
   The latter is unchanged, but will be marked deprecated in a future stable
   version of `sigstore-python`
   ([#383](https://github.com/sigstore/sigstore-python/pull/383))

* `sigstore verify github` has been added, allowing for verification of
  GitHub-specific claims within given certificate(s)
  ([#381](https://github.com/sigstore/sigstore-python/pull/381))

### Changed

* The default behavior of `SIGSTORE_LOGLEVEL` has changed; the logger
  configured is now the `sigstore.*` hierarchy logger, rather than the "root"
  logger ([#372](https://github.com/sigstore/sigstore-python/pull/372))

* The caching mechanism used for TUF has been changed slightly, to use
  more future-proof paths ([#373](https://github.com/sigstore/sigstore-python/pull/373))

### Fixed

* Fulcio certificate handling now includes "inactive" but still valid certificates,
  allowing users to verify older signatures without custom certificate chains
  ([#386](https://github.com/sigstore/sigstore-python/pull/386))

## [0.9.0]

### Added

* `sigstore verify` now supports `--certificate-chain` and `--rekor-url`
  during verification. Ordinary uses (i.e. the default or `--staging`)
  are not affected ([#323](https://github.com/sigstore/sigstore-python/pull/323))

### Changed

* `sigstore sign` and `sigstore verify` now stream their input, rather than
  consuming it into a single buffer
  ([#329](https://github.com/sigstore/sigstore-python/pull/329))

* A series of Python 3.11 deprecation warnings were eliminated
  ([#341](https://github.com/sigstore/sigstore-python/pull/341))

* The "splash" page presented to users during the OAuth flow has been updated
  to reflect the user-friendly page added to `cosign`
  ([#356](https://github.com/sigstore/sigstore-python/pull/356))

* `sigstore` now uses TUF to retrieve its trust material for Fulcio and Rekor,
  replacing the material that was previously baked into `sigstore._store`
  ([#351](https://github.com/sigstore/sigstore-python/pull/351))

<!--Release URLs -->
[Unreleased]: https://github.com/sigstore/sigstore-python/compare/v0.9.0...HEAD
[0.9.0]: https://github.com/sigstore/sigstore-python/compare/v0.8.3...v0.9.0
