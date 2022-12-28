# Changelog

All notable changes to `sigstore-python` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

All versions prior to 0.9.0 are untracked.

## [Unreleased]

### Added

* `sigstore` now supports the `-v`/`--verbose` flag as an alternative to
  `SIGSTORE_LOGLEVEL` for debug logging
  ([#372](https://github.com/sigstore/sigstore-python/pull/372))

### Changed

* The default behavior of `SIGSTORE_LOGLEVEL` has changed; the logger
  configured is now the `sigstore.*` hierarchy logger, rather than the "root"
  logger ([#372](https://github.com/sigstore/sigstore-python/pull/372))

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
