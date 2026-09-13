# Public npm provenance regression

`sigstore-3.1.0.sigstore.json` is the public SLSA provenance bundle for the
Apache-2.0-licensed [sigstore-js](https://github.com/sigstore/sigstore-js) npm
package `sigstore@3.1.0`, referenced in
[sigstore-python #1384](https://github.com/sigstore/sigstore-python/issues/1384).
It was retrieved on 2026-09-13 from:

<https://registry.npmjs.org/-/npm/v1/attestations/sigstore@3.1.0>

The original response SHA-256 is
`92aa0e0815803592d89cd2c0e2f30811ac6c7c379c2d60deb0b8770d7c65976e`.
The fixture selects `.attestations[]` with
`predicateType == "https://slsa.dev/provenance/v1"`, extracts `.bundle`, and
pretty-prints JSON with two-space indentation and a final newline. No signed
payload, certificate, canonicalized log body, proof, or signature was changed.
Fixture SHA-256:
`ec47e8d5a9804173596eafcbead2f248ae0442f8ab4aa66b51c88bd85f5fd4a1`.

The recorded identity is the sigstore-js release workflow on `refs/heads/main`,
issued by `https://token.actions.githubusercontent.com`. These are public
certificates and signatures, not private keys or test-generated attestations.
The regression verifies against the project's embedded production trust root
without fetching npm, TUF, Fulcio, or Rekor during the test. Success verifies
the configured identity and bundle bindings; it does not assess the package's
behavior or assert that its build was safe.
