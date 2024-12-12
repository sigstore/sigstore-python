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

_Warning_: this step is performed before the `Timestamping`

The Transparency Service used by `sigstore-python` is [rekor].
This step ends every signing workflow performed by `sigstore-python`.

### Signing Choices

To summarize the choices:

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

`sigstore-python` supports configuring the verification process 
using policies but this must be done at a programmatic level.
By default, the CLI uses the `Identity` verification policy.

### Establishing a Time for the Signature

If the Bundle contains one or more signed times from Timestamping Authorities,
they will be used as the time source. In this case, a Timestamp Authority 
configuration must be provided in the `ClientTrustConfig`. When verifying 
Timestamp Authorities Responses, at least one must be valid.

If there is a Transparency Service Timestamp, this is also used as a source 
of trusted time.

The verification will fail if no sources of time are found.

### Certificate

For a signature with a given certificate to be considered valid, it must 
have a timestamp while every certificate in the chain up to the root is valid 
(the so-called “hybrid model” of certificate verification per [Braun et al.]).

The validation is repeated for each source of time and must be valid for all 
of them.


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

The transparency log entry insertion timestamp is verified to be generated
during the certificate's validity period.


### Signature Verification

The signature itself is now verified.

- DSSE: The envelope is used as the verification payload.
- Artifacts: The raw bytes of the artifacts are used as the verification 
  payload.

#### Final step

Finally, a last consistency check is performed to verify that the constructed 
payload is indeed the one that has been signed.

[Sigstore: Client Spec]: https://docs.google.com/document/d/1kbhK2qyPPk8SLavHzYSDM8-Ueul9_oxIMVFuWMWKz0E/edit?usp=sharing
[ECDSA]: https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm
[rekor]: https://github.com/sigstore/rekor
[Braun et al.]: https://research.tue.nl/en/publications/how-to-avoid-the-breakdown-of-public-key-infrastructures-forward-