# Policies

This document describes the set of policies followed by `sigstore-python` 
when signing or verifying a bundle.

`sigstore-python` follows the [Sigstore: Client Spec] and this document 
outline mimic the one from the spec.

## Signing

### Authentication

`sigstore-python` supports several authentication mechanisms :

- An OAuth flow: this mode is preferred for interactive workflows.
- An _ambient_ detection: this mode is preferred for un-attended workflows 
  (i.e., continuous integration system)

### Key generation

`sigstore-python` uses [ECDSA] as its signing algorithm.

### Certificate Issuance

_using Fulcio_

### Signing

When needed, the payload pre-hashing algorithm is `SHA2_256`.

### Timestamping

If Timestamp Authorities have been provided in the Signing Config, a 
Timestamp Request using the hash of the signature is automatically sent to the 
provided Timestamp Authorities.

This step allows to attest of the signature time.

### Submission of Signing Metadata to Transparency Service

The Transparency Service, [rekor], is used by `sigstore-python` to provide a
public, immutable record of signing events. This step is crucial for ensuring
the integrity and transparency of the signing process.

!!! warning

    This step is performed before the `Timestamping` step in the worfklow.

### Signing Choices

Here's a summary of the key choices in the `sigstore-python` signing process:

| Option                        | `sigstore-python`            |
|-------------------------------|------------------------------|
| Digital signature algorithm   | ECDSA                        |
| Signature metadata format     | ???                          |
| Payload pre-hashing algorithm | SHA2 (256)                   |
| Long-lived signing keys       | not used                     |
| Timestamping                  | Used if provided             |
| Transparency                  | Always used (rekor)          |
| Other workflows               | no other workflows supported |

## Verification

`sigstore-python` supports configuring the verification process using policies
but this must be done using the [api](./api/index.md). By default, the CLI uses
the [`Identity`][sigstore.verify.policy] verification policy.

### Establishing a Time for the Signature

If the bundle contains one or more signed times from Timestamping Authorities,
they will be used as the time source. In this case, a Timestamp Authority 
configuration must be provided in the `ClientTrustConfig`. When verifying 
Timestamp Authorities Responses, at least one must be valid.

If there is a Transparency Service Timestamp, this is also used as a source 
of trusted time.

The verification will fail if no sources of time are found.

### Certificate

For a signature to be considered valid, it must meet two key criteria:

- The signature must have an associated timestamp.
- Every certificate in the chain, from the signing certificate up to the root
  certificate, must be valid at the time of signing.

This approach is known as the “hybrid model” of certificate verification, as
described by [Braun et al.].

This validation process is repeated for each available source of trusted time.
The signature is only considered valid if it passes the validation checks
against all of these time sources.

#### SignedCertificateTimestamp

The `SignedCertificateTimestamp` is extracted from the leaf certificate and 
verified using the verification key from the Certificate Transparency Log.

#### Identity Verification Policy

The system verifies that the signing certificate conforms to the Sigstore X. 509
profile as well as `Identity Policy`.

### Transparency Log Entry

The Verifier now verifies the inclusion proof and signed checkpoint for the 
log entry using [rekor].

If there is an inclusion promise, this is also verified.

#### Time insertion check

The system verifies that the transparency log entry’s insertion timestamp falls
within the certificate’s validity period.

If the insertion timestamp is outside the certificate’s validity period, it
could indicate potential backdating or use of an expired certificate, and the
verification will fail.


### Signature Verification

The next verification step is to verify the actual signature. This ensures
that the signed content has not been tampered with and was indeed signed by the
claimed entity.

The verification process differs slightly depending on the type of signed
content:

- DSSE: The entire envelope structure is used as the verification payload. 
- Artifacts: The raw bytes of the artifacts serve as the verification payload.

#### Final step

Finally, a last consistency check is performed to verify that the constructed 
payload is indeed the one that has been signed. This step is ussed to prevent
variants of [CVE-2022-36056]. 

[Sigstore: Client Spec]: https://docs.google.com/document/d/1kbhK2qyPPk8SLavHzYSDM8-Ueul9_oxIMVFuWMWKz0E/edit?usp=sharing
[ECDSA]: https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm
[rekor]: https://github.com/sigstore/rekor
[Braun et al.]: https://research.tue.nl/en/publications/how-to-avoid-the-breakdown-of-public-key-infrastructures-forward-
[CVE-2022-36056]: https://github.com/sigstore/cosign/security/advisories/GHSA-8gw7-4j42-w388