# Changelog

All notable changes to `sigstore-python` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

All versions prior to 0.9.0 are untracked.

## [Unreleased]

## [1.1.1]

### Added

* Network-related errors from the `sigstore._internal.tuf` module now have better
  diagnostics.

### Changed

* Replaced ambient credential detection logic with the `id` package
  ([#535](https://github.com/sigstore/sigstore-python/pull/535))
* Revamped error diagnostics reporting. All errors with diagnostics now implement
  `sigstore.errors.Error`.

### Fixed

* Fixed a bug in TUF target handling revealed by changes to the production
  and staging TUF repos
  ([#522](https://github.com/sigstore/sigstore-python/pull/522))

## [1.1.0]

### Added

* `sigstore sign` now supports Sigstore bundles, which encapsulate the same
  state as the default `{input}.crt`, `{input}.sig`, and `{input}.rekor`
  files combined. The default output for the Sigstore bundle is
  `{input}.sigstore`; this can be disabled with `--no-bundle` or changed with
  `--bundle <FILE>`
  ([#465](https://github.com/sigstore/sigstore-python/pull/465))

* `sigstore verify` now supports Sigstore bundles. By default, `sigstore` looks
  for an `{input}.sigstore`; this can be changed with `--bundle <FILE>` or the
  legacy method of verification can be used instead via the `--signature` and
  `--certificate` flags
  ([#478](https://github.com/sigstore/sigstore-python/pull/478))

* `sigstore verify identity` and `sigstore verify github` now support the
  `--offline` flag, which tells `sigstore` to do offline transparency log
  entry verification. This option replaces the unstable
  `--require-rekor-offline` option, which has been removed
  ([#478](https://github.com/sigstore/sigstore-python/pull/478))

### Fixed

* Constrained our dependency on `pyOpenSSL` to `>= 23.0.0` to prevent
  a runtime error caused by incompatible earlier versions
  ([#448](https://github.com/sigstore/sigstore-python/pull/448))

### Removed

* `--rekor-bundle` and `--require-rekor-offline` have been removed entirely,
  as their functionality have been wholly supplanted by Sigstore bundle support
  and the new `sigstore verify --offline` flag
  ([#478](https://github.com/sigstore/sigstore-python/pull/478))

## [1.0.0]

### Changed

* `sigstore.rekor` is now `sigstore.transparency`, and its constituent APIs
  have been renamed to removed implementation detail references
  ([#402](https://github.com/sigstore/sigstore-python/pull/402))

* `sigstore.transparency.RekorEntryMissing` is now `LogEntryMissing`
  ([#414](https://github.com/sigstore/sigstore-python/pull/414))

### Fixed

* The TUF network timeout has been relaxed from 4 seconds to 30 seconds,
  which should reduce the likelihood of spurious timeout errors in environments
  like GitHub Actions ([#432](https://github.com/sigstore/sigstore-python/pull/432))

## [0.10.0]

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

* The per-subcommand options `--rekor-url` and `--rekor-root-pubkey` have been
  moved to the top-level `sigstore` command. Their subcommand forms are unchanged
  and will continue to work, but will be marked deprecated in a future stable
  version of `sigstore-python`
  ([#381](https://github.com/sigstore/sigstore-python/pull/383))

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
[Unreleased]: https://github.com/sigstore/sigstore-python/compare/v1.1.1...HEAD
[1.1.1]: https://github.com/sigstore/sigstore-python/compare/v1.1.0...v1.1.1
[1.1.0]: https://github.com/sigstore/sigstore-python/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/sigstore/sigstore-python/compare/v0.10.0...v1.0.0
[0.10.0]: https://github.com/sigstore/sigstore-python/compare/v0.9.0...v0.10.0
[0.9.0]: https://github.com/sigstore/sigstore-python/compare/v0.8.3...v0.9.0
