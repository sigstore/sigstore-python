# Changelog

All notable changes to `sigstore-python` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

All versions prior to 0.9.0 are untracked.

## [Unreleased]

### Added

* Added `LogEntry._kind_version`, which is now parsed earlier upon receipt from the rekor API,
  either from the root of the response, or from the reponse's inner base64-encoded JSON `body`.
  [#1370](https://github.com/sigstore/sigstore-python/pull/1370)

* Added support for ed25519 keys.
  [#1377](https://github.com/sigstore/sigstore-python/pull/1377)
* API: `IdentityToken` now supports `client_id` for audience claim validation.
  [#1402](https://github.com/sigstore/sigstore-python/pull/1402)

* Added a `RekorV2Client` for posting new entries to a Rekor V2 instance.
  [#1400](https://github.com/sigstore/sigstore-python/pull/1422)

* Added a function for determining the `key_details` of a certificate`.
  [#1456](https://github.com/sigstore/sigstore-python/pull/1456)

### Fixed

* Avoid instantiation issues with `TransparencyLogEntry` when `InclusionPromise` is not present.

* TSA: Changed the Timestamp Authority requests to explicitly use sha256 for message digests.
  [#1373](https://github.com/sigstore/sigstore-python/pull/1373)

* TSA: Correctly verify timestamps with hashes other than SHA-256. Currently supported
  algorithms are SHA-256, SHA-384, SHA-512.
  [#1373](https://github.com/sigstore/sigstore-python/pull/1373)

* Fixed the certificate validity period check for Timestamp Authorities (TSA).
  Certificates need not have an end date, while still requiring a start date.
  [#1368](https://github.com/sigstore/sigstore-python/pull/1368)

* Made Rekor client more compatible with Rekor v2 by removing trailing slashes
  from endpoints ([#1366](https://github.com/sigstore/sigstore-python/pull/1366))

* Verify: verify that all established times (timestamps or the log integration time)
  are within the signing certificate validity period. At least one established time is
  still required.
  [#1381](https://github.com/sigstore/sigstore-python/pull/1381)

* CI: Timestamp Authority tests use latest release, not latest tag, of
  [sigstore/timestamp-authority](https://github.com/sigstore/timestamp-authority)
  [#1377](https://github.com/sigstore/sigstore-python/pull/1377)

* Tests: Updated the `staging` and `sign_ctx_and_ident_for_env` fixtures to use the new methods
  for generating a `SigningContext`.
  [#1409](https://github.com/sigstore/sigstore-python/pull/1409)

### Changed

* API:
  * ClientTrustConfig now provides methods `production()`, `staging()`and `from_tuf()`
    to get access to current client configuration (trusted keys & certificates,
    URLs and their validity periods). [#1363](https://github.com/sigstore/sigstore-python/pull/1363)
  * SigningConfig now has methods that return actual clients (like `RekorClient`) instead of
    just URLs. The returned clients are also filtered according to SigningConfig contents.
    [#1407](https://github.com/sigstore/sigstore-python/pull/1407)
  * The ClientTrustConfig class has been moved from the private _internal package to a public
    module (sigstore.models). This change formally adds the class to the project's public API,
    making it available for use in other projects. [#1496](https://github.com/sigstore/sigstore-python/pull/1496)
* `--trust-config` now requires a file with SigningConfig v0.2, and is able to fully
  configure the used Sigstore instance [#1358]/(https://github.com/sigstore/sigstore-python/pull/1358)
* By default (when `--trust-config` is not used) the whole trust configuration now
  comes from the TUF repository [#1363](https://github.com/sigstore/sigstore-python/pull/1363)
* If the user provided TSA urls, rfc3161 timestamps are now fetched **before** submitting
  entries to rekor. [#1463](https://github.com/sigstore/sigstore-python/pull/1463)

### Removed
 * API:
  * `Issuer.production()` and `Issuer.staging()` have been removed: Use
    `Issuer()` instead with relevant URL. The current public good production and
    staging URLs are available via the `ClientTrustConfig` object.
    [#1363](https://github.com/sigstore/sigstore-python/pull/1363)
  * `SigningContext.production()` and `SigningContext.staging()` have been removed:
    Use `SigningContext.from_trust_config()` instead.
    [#1363](https://github.com/sigstore/sigstore-python/pull/1363)

## [3.6.4]

### Fixed

* Bumped the `rfc3161-client` dependency to `>=1.0.3` to fix a security
  vulnerability ([#1451](https://github.com/sigstore/sigstore-python/pull/1451))

## [3.6.3]

### Fixed

* Verify: Avoid hard failure if trusted root contains unsupported keytypes (as verification
  may succeed without that key).
  [#1425](https://github.com/sigstore/sigstore-python/pull/1425)

## [3.6.2]

### Fixed

* Fixed issue where a trust root with multiple rekor keys was not considered valid:
  Now any rekor key listed in the trust root is considered good to verify entries
  [#1350](https://github.com/sigstore/sigstore-python/pull/1350)

### Changed

* Upgraded python-tuf dependency to 6.0: Connections to TUF repository
  now use system certificates (instead of certifi) and have automatic
  retries
* Updated the embedded TUF root to version 12

## [3.6.1]

### Fixed

* Relaxed the transitive dependency on `cryptography` to allow v43 and v44
  to be resolved
  ([#1251](https://github.com/sigstore/sigstore-python/pull/1251))

## [3.6.0]

### Added

* API: The DSSE `Envelope` class now performs automatic validation
  ([#1211](https://github.com/sigstore/sigstore-python/pull/1211))

* API: Added `signature` property to `Envelope` class for accessing raw
  signature bytes ([#1211](https://github.com/sigstore/sigstore-python/pull/1211))

* Signed timestamps embedded in bundles are now automatically verified
  against Timestamp Authorities provided within the Trusted Root ([#1206]
  (https://github.com/sigstore/sigstore-python/pull/1206))

* Bundles are now generated with signed timestamps when signing if the
  Trusted Root contains one or more Timestamp Authorities
  ([#1216](https://github.com/sigstore/sigstore-python/pull/1216))

### Removed

* Support for "detached" SCTs has been fully removed, aligning
  sigstore-python with other sigstore clients
  ([#1236](https://github.com/sigstore/sigstore-python/pull/1236))

### Fixed

* Fixed a CLI parsing bug introduced in 3.5.1 where a warning about
  verifying legacy bundles was never shown
  ([#1198](https://github.com/sigstore/sigstore-python/pull/1198))

* Strengthened the requirement that an inclusion promise is present
  *if* no other source of signed time is present
  ([#1247](https://github.com/sigstore/sigstore-python/pull/1247))

## [3.5.3]

### Fixed

* Corrective release for [3.5.2]

## [3.5.2]

### Fixed

* Pinned `cryptography` dependency strictly to prevent future breakage

## [3.5.1]

### Fixed

* Fixed a CLI parsing bug introduced in 3.5.0 when attempting
  to suppress irrelevant warnings
  ([#1192](https://github.com/sigstore/sigstore-python/pull/1192))

## [3.5.0]

### Added

* CLI: The `sigstore plumbing update-trust-root` command has been added.
  Like other plumbing-level commands, this is considered unstable and
  changes are not subject to our semver policy until explicitly noted
  ([#1174](https://github.com/sigstore/sigstore-python/pull/1174))

### Fixed

* CLI: Fixed an incorrect warning when verifying detached `.crt`/`.sig`
  inputs ([#1179](https://github.com/sigstore/sigstore-python/pull/1179))

## [3.4.0]

### Changed

* CLI: When verifying, the `--offline` flag now fully disables all online
  operations, including routine local TUF repository refreshes
  ([#1143](https://github.com/sigstore/sigstore-python/pull/1143))

* `sigstore-python`'s minimum supported Python version is now 3.9

### Fixed

* CLI: The `sigstore verify` subcommands now always check for a matching
  input file, rather than unconditionally falling back to matching on a
  valid `sha256:...` digest pattern
  ([#1152](https://github.com/sigstore/sigstore-python/pull/1152))

## [3.3.0]

### Added

* CLI: The `sigstore verify` command now outputs the inner in-toto statement
  when verifying DSSE envelopes. If verification is successful, the output
  will be the inner in-toto statement. This allows the user to see the
  statement's predicate, which `sigstore-python` does not verify and should be
  verified by the user.

* CLI: The `sigstore attest` subcommand has been added. This command is
  similar to `cosign attest` in that it signs over an artifact and a
  predicate using a DSSE envelope. This commands requires the user to pass
  a path to the file containing the predicate, and the predicate type.
  Currently only the SLSA Provenance v0.2 and v1.0 types are supported.

* CLI: The `sigstore verify` command now supports verifying digests. This means
  that the user can now pass a digest like `sha256:aaaa....` instead of the
  path to an artifact, and `sigstore-python` will verify it as if it was the
  artifact with that digest.

## [3.2.0]

### Added

* API: `models.Bundle.BundleType` is now a public API
  ([#1089](https://github.com/sigstore/sigstore-python/pull/1089))

* CLI: The `sigstore plumbing` subcommand hierarchy has been added. This
  hierarchy is for *developer-only* interactions, such as fixing malformed
  Sigstore bundles. These subcommands are **not considered stable until
  explicitly documented as such**.
  ([#1089](https://github.com/sigstore/sigstore-python/pull/1089))

### Changed

* CLI: The default console logger now emits to `stderr`, rather than `stdout`
  ([#1089](https://github.com/sigstore/sigstore-python/pull/1089))

## [3.1.0]

### Added

* API: `dsse.StatementBuilder` has been added. It can be used to construct an
  in-toto `Statement` for subsequent enveloping and signing.
  This API is public but is **not considered stable until the next major
  release.**
  ([#1077](https://github.com/sigstore/sigstore-python/pull/1077))

* API: `dsse.Digest`, `dsse.DigestSet`, and `dsse.Subject` have been added.
  These types can be used with the `StatementBuilder` API as part of in-toto
  `Statement` construction.
  These API are public but are **not considered stable until the next major
  release.**
  ([#1078](https://github.com/sigstore/sigstore-python/pull/1078))

### Changed

* API: `verify_dsse` now rejects bundles with DSSE envelopes that have more than
  one signature, rather than checking all signatures against the same key
  ([#1062](https://github.com/sigstore/sigstore-python/pull/1062))

## [3.0.0]

Maintainers' note: this is a major release, with significant public API and CLI
changes. We **strongly** recommend you read the entries below to fully
understand the changes between `2.x` and `3.x`.

### Added

* API: `Signer.sign_artifact()` has been added, replacing the removed
  `Signer.sign()` API

* API: `Signer.sign_dsse()` has been added. It takes an in-toto `Statement`
  as an input, producing a DSSE-formatted signature rather than a "bare"
  signature ([#804](https://github.com/sigstore/sigstore-python/pull/804))

* API: "v3" Sigstore bundles are now supported during verification
  ([#901](https://github.com/sigstore/sigstore-python/pull/901))

* API: `Verifier.verify(...)` can now take a `Hashed` as an input, performing
  signature verification on a pre-computed hash value
  ([#904](https://github.com/sigstore/sigstore-python/pull/904))

* API: The `sigstore.dsse` module has been been added, including APIs
  for representing in-toto statements and DSSE envelopes
  ([#930](https://github.com/sigstore/sigstore-python/pull/930))

* CLI: The `--trust-config` flag has been added as a global option,
  enabling consistent "BYO PKI" uses of `sigstore` with a single flag
  ([#1010](https://github.com/sigstore/sigstore-python/pull/1010))

* CLI: The `sigstore verify` subcommands can now verify bundles containing
  DSSE entries, such as those produced by
  [GitHub Artifact Attestations](https://docs.github.com/en/actions/security-guides/using-artifact-attestations-to-establish-provenance-for-builds)
  ([#1015](https://github.com/sigstore/sigstore-python/pull/1015))

### Removed

* **BREAKING API CHANGE**: `SigningResult` has been removed.
  The public signing APIs now return `sigstore.models.Bundle`.

* **BREAKING API CHANGE**: `VerificationMaterials` has been removed.
  The public verification APIs now accept `sigstore.models.Bundle`.

* **BREAKING API CHANGE**: `Signer.sign(...)` has been removed. Use
  either `sign_artifact(...)` or `sign_dsse(...)`, depending on whether
  you're signing opaque bytes or an in-toto statement.

* **BREAKING API CHANGE**: `VerificationResult` has been removed.
  The public verification and policy APIs now raise
  `sigstore.errors.VerificationError` on failure.

* **BREAKING CLI CHANGE**: The `--rekor-url` and `--fulcio-url`
  flags have been entirely removed. To configure a custom PKI, use
  `--trust-config`
  ([#1010](https://github.com/sigstore/sigstore-python/pull/1010))

### Changed

* **BREAKING API CHANGE**: `Verifier.verify(...)`  now takes a `bytes | Hashed`
  as its verification input, rather than implicitly receiving the input through
  the `VerificationMaterials` parameter
  ([#904](https://github.com/sigstore/sigstore-python/pull/904))

* **BREAKING API CHANGE**: `VerificationMaterials.rekor_entry(...)` now takes
  a `Hashed` parameter to convey the digest used for Rekor entry lookup
  ([#904](https://github.com/sigstore/sigstore-python/pull/904))

* **BREAKING API CHANGE**: `Verifier.verify(...)` now takes a `sigstore.models.Bundle`,
  instead of a `VerificationMaterials` ([#937](https://github.com/sigstore/sigstore-python/pull/937))

* **BREAKING CLI CHANGE**: `sigstore sign` now emits `{input}.sigstore.json`
  by default instead of `{input}.sigstore`, per the client specification
  ([#1007](https://github.com/sigstore/sigstore-python/pull/1007))

* sigstore-python now requires inclusion proofs in all signing and verification
  flows, regardless of bundle version of input types. Inputs that do not
  have an inclusion proof (such as detached materials) cause an online lookup
  before any further processing is performed
  ([#937](https://github.com/sigstore/sigstore-python/pull/937))

* sigstore-python now generates "v3" bundles by default during signing
  ([#937](https://github.com/sigstore/sigstore-python/pull/937))

* CLI: Bundles are now always verified offline. The offline flag has no effect.
  ([#937](https://github.com/sigstore/sigstore-python/pull/937))

* CLI: "Detached" materials are now always verified online, due to a lack of
  an inclusion proof. Passing `--offline` with detached materials will cause
  an error ([#937](https://github.com/sigstore/sigstore-python/pull/937))

* API: `sigstore.transparency` has been removed, and its pre-existing APIs
  have been re-homed under `sigstore.models`
  ([#990](https://github.com/sigstore/sigstore-python/pull/990))

* API: `oidc.IdentityToken.expected_certificate_subject` has been renamed
  to `oidc.IdentityToken.federated_issuer` to better describe what it actually
  contains. No functional changes have been made to it
  ([#1016](https://github.com/sigstore/sigstore-python/pull/1016))

* API: `policy.Identity` now takes an **optional** OIDC issuer, rather than a
  required one ([#1015](https://github.com/sigstore/sigstore-python/pull/1015))

* CLI: `sigstore verify github` now requires `--cert-identity` **or**
  `--repository`, not just `--cert-identity`
  ([#1015](https://github.com/sigstore/sigstore-python/pull/1015))

## [2.1.5]

## Fixed

* Backported b32ad1bd (slsa-github-generator upgrade) to make release possible

## [2.1.4]

## Fixed

* Pinned `securesystemslib` dependency strictly to prevent future breakage

## [2.1.3]

## Fixed

* Loosened a version constraint on the `sigstore-protobuf-specs` dependency,
  to ease use in testing environments
  ([#943](https://github.com/sigstore/sigstore-python/pull/943))

## [2.1.2]

This is a corrective release for [2.1.1].

## [2.1.1]

### Fixed

* Fixed an incorrect assumption about Rekor checkpoints that future releases
  of Rekor will not uphold ([#891](https://github.com/sigstore/sigstore-python/pull/891))

## [2.1.0]

### Added

* CLI: `sigstore verify`'s subcommands now discover `{input}.sigstore.json`
  by default, in addition to the previous `{input}.sigstore`. The former now
  takes precedence over the latter, and supplying both results in an error
  ([#820](https://github.com/sigstore/sigstore-python/pull/820))

## [2.0.1]

### Fixed

* CLI: When using `--certificate-chain`, read as `bytes` instead of `str`
  as expected by the underlying API ([#796](https://github.com/sigstore/sigstore-python/pull/796))

## [2.0.0]

### Added

* CLI: `sigstore sign` and `sigstore get-identity-token` now support the
  `--oauth-force-oob` option; which has the same behavior as the
  preexisting `SIGSTORE_OAUTH_FORCE_OOB` environment variable
  ([#667](https://github.com/sigstore/sigstore-python/pull/667))

* Version `0.2` of the Sigstore bundle format is now supported
  ([#705](https://github.com/sigstore/sigstore-python/pull/705))

* API addition: `VerificationMaterials.to_bundle()` is a new public API for
  producing a standard Sigstore bundle from `sigstore-python`'s internal
  representation ([#719](https://github.com/sigstore/sigstore-python/pull/719))

* API addition: New method `sign.SigningResult.to_bundle()` allows signing
  applications to serialize to the bundle format that is already usable in
  verification with `verify.VerificationMaterials.from_bundle()`
  ([#765](https://github.com/sigstore/sigstore-python/pull/765))

### Changed

* `sigstore verify` now performs additional verification of Rekor's inclusion
  proofs by cross-checking them against signed checkpoints
  ([#634](https://github.com/sigstore/sigstore-python/pull/634))

* A cached copy of the trust bundle is now included with the distribution
  ([#611](https://github.com/sigstore/sigstore-python/pull/611))

* Stopped emitting .sig and .crt signing outputs by default in `sigstore sign`.
  Sigstore bundles are now preferred
  ([#614](https://github.com/sigstore/sigstore-python/pull/614))

* Trust root configuration now assumes that the TUF repository contains a trust
  bundle, rather than falling back to deprecated individual targets
  ([#626](https://github.com/sigstore/sigstore-python/pull/626))

* API change: the `sigstore.oidc.IdentityToken` API has been stabilized as
  a wrapper for OIDC tokens
  ([#635](https://github.com/sigstore/sigstore-python/pull/635))

* API change: `Signer.sign` now takes a `sigstore.oidc.IdentityToken` for
  its `identity` argument, rather than a "raw" OIDC token
  ([#635](https://github.com/sigstore/sigstore-python/pull/635))

* API change: `Issuer.identity_token` now returns a
  `sigstore.oidc.IdentityToken`, rather than a "raw" OIDC token
  ([#635](https://github.com/sigstore/sigstore-python/pull/635))

* `sigstore verify` is not longer a backwards-compatible alias for
  `sigstore verify identity`, as it was during the 1.0 release series
  ([#642](https://github.com/sigstore/sigstore-python/pull/642))

* API change: the `Signer` API has been broken up into `SigningContext`
  and `Signer`, allowing a `SigningContext` to create individual `Signer`
  instances that correspond to a single `IdentityToken`. This new API
  also enables ephemeral key and certificate reuse across multiple inputs,
  reducing the number of cryptographic operations and network roundtrips
  required when signing more than one input
  ([#645](https://github.com/sigstore/sigstore-python/pull/645))

* `sigstore sign` now uses an ephemeral P-256 keypair, rather than P-384
  ([#662](https://github.com/sigstore/sigstore-python/pull/662))

* API change: `RekorClientError` does not try to always parse response
  content as JSON
  ([#694](https://github.com/sigstore/sigstore-python/pull/694))

* API change: `LogEntry.inclusion_promise` can now be `None`, but only
  if `LogEntry.inclusion_proof` is not `None`
  ([#705](https://github.com/sigstore/sigstore-python/pull/705))

* `sigstore-python`'s minimum supported Python version is now 3.8
  ([#745](https://github.com/sigstore/sigstore-python/pull/745))

### Fixed

* Fixed a case where `sigstore verify` would fail to verify an otherwise valid
  inclusion proof due to an incorrect timerange check
  ([#633](https://github.com/sigstore/sigstore-python/pull/633))

* Removed an unnecessary and backwards-incompatible parameter from the
  `sigstore.oidc.detect_credential` API
  ([#641](https://github.com/sigstore/sigstore-python/pull/641))

* Fixed a case where `sigstore sign` (and `sigstore verify`) could fail while
  using a private instance due to a missing due to a missing `ExtendedKeyUsage`
  in the CA. We now enforce the fact that the TBSPrecertificate signer must be
  a valid CA ([#658](https://github.com/sigstore/sigstore-python/pull/658))

* Fixed a case where identity token retrieval would produce an unhelpful
  error message ([#767](https://github.com/sigstore/sigstore-python/pull/767))

## [1.1.2]

### Fixed

* Updated the `staging-root.json` for recent changes to the Sigstore staging
  instance ([#602](https://github.com/sigstore/sigstore-python/pull/602))

* Switched TUF requests to their CDN endpoints, rather than direct GCS
  access ([#609](https://github.com/sigstore/sigstore-python/pull/609))

## [1.1.1]

### Added

* `sigstore sign` now supports the `--output-directory` flag, which places
  default outputs in the specified directory. Without this flag, default outputs
  are placed adjacent to the signing input.
  ([#627](https://github.com/sigstore/sigstore-python/pull/627))

* The whole test suite can now be run locally with `make test-interactive`.
  ([#576](https://github.com/sigstore/sigstore-python/pull/576))
  Users will be prompted to authenticate with their identity provider twice to
  generate staging and production OIDC tokens, which are used to test the
  `sigstore.sign` module. All signing tests need to be completed before token
  expiry, which is currently 60 seconds after issuance.

* Network-related errors from the `sigstore._internal.tuf` module now have better
  diagnostics.
  ([#525](https://github.com/sigstore/sigstore-python/pull/525))

### Changed

* Replaced ambient credential detection logic with the `id` package
  ([#535](https://github.com/sigstore/sigstore-python/pull/535))

* Revamped error diagnostics reporting. All errors with diagnostics now implement
  `sigstore.errors.Error`.

* Trust root materials are now retrieved from a single trust bundle,
  if it is available via TUF
  ([#542](https://github.com/sigstore/sigstore-python/pull/542))

* Improved diagnostics around Signed Certificate Timestamp verification failures.
  ([#555](https://github.com/sigstore/sigstore-python/pull/555))

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

### Removed
* CLI: The `--certificate-chain`, `--rekor-root-pubkey` and `-ctfe` flags have been entirely removed ([#936](https://github.com/sigstore/sigstore-python/pull/936))


<!--Release URLs -->
[Unreleased]: https://github.com/sigstore/sigstore-python/compare/v3.6.4...HEAD
[3.6.4]: https://github.com/sigstore/sigstore-python/compare/v3.6.3...v3.6.4
[3.6.3]: https://github.com/sigstore/sigstore-python/compare/v3.6.2...v3.6.3
[3.6.2]: https://github.com/sigstore/sigstore-python/compare/v3.6.1...v3.6.2
[3.6.1]: https://github.com/sigstore/sigstore-python/compare/v3.6.0...v3.6.1
[3.6.0]: https://github.com/sigstore/sigstore-python/compare/v3.5.3...v3.6.0
[3.5.3]: https://github.com/sigstore/sigstore-python/compare/v3.5.2...v3.5.3
[3.5.2]: https://github.com/sigstore/sigstore-python/compare/v3.5.1...v3.5.2
[3.5.1]: https://github.com/sigstore/sigstore-python/compare/v3.5.0...v3.5.1
[3.5.0]: https://github.com/sigstore/sigstore-python/compare/v3.4.0...v3.5.0
[3.4.0]: https://github.com/sigstore/sigstore-python/compare/v3.3.0...v3.4.0
[3.3.0]: https://github.com/sigstore/sigstore-python/compare/v3.2.0...v3.3.0
[3.2.0]: https://github.com/sigstore/sigstore-python/compare/v3.1.0...v3.2.0
[3.1.0]: https://github.com/sigstore/sigstore-python/compare/v3.0.0...v3.1.0
[3.0.0]: https://github.com/sigstore/sigstore-python/compare/v2.1.5...v3.0.0
[2.1.5]: https://github.com/sigstore/sigstore-python/compare/v2.1.4...v2.1.5
[2.1.4]: https://github.com/sigstore/sigstore-python/compare/v2.1.3...v2.1.4
[2.1.3]: https://github.com/sigstore/sigstore-python/compare/v2.1.2...v2.1.3
[2.1.2]: https://github.com/sigstore/sigstore-python/compare/v2.1.1...v2.1.2
[2.1.1]: https://github.com/sigstore/sigstore-python/compare/v2.1.0...v2.1.1
[2.1.0]: https://github.com/sigstore/sigstore-python/compare/v2.0.1...v2.1.0
[2.0.1]: https://github.com/sigstore/sigstore-python/compare/v2.0.0...v2.0.1
[2.0.0]: https://github.com/sigstore/sigstore-python/compare/v1.1.2...v2.0.0
[1.1.2]: https://github.com/sigstore/sigstore-python/compare/v1.1.1...v1.1.2
[1.1.1]: https://github.com/sigstore/sigstore-python/compare/v1.1.0...v1.1.1
[1.1.0]: https://github.com/sigstore/sigstore-python/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/sigstore/sigstore-python/compare/v0.10.0...v1.0.0
[0.10.0]: https://github.com/sigstore/sigstore-python/compare/v0.9.0...v0.10.0
[0.9.0]: https://github.com/sigstore/sigstore-python/compare/v0.8.3...v0.9.0
