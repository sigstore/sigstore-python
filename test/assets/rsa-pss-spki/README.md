# RSA-PSS subject-SPKI regression fixtures

These synthetic Rekor v1 bundles contain a 2048-bit RSA signing certificate
whose **subject** SubjectPublicKeyInfo algorithm is `id-RSASSA-PSS`
(`1.2.840.113549.1.1.10`). Its issuer signs the certificate with ECDSA/SHA-256.
The artifact and DSSE signatures are mathematically valid PKCS#1 v1.5/SHA-256
signatures, but that algorithm is not authorized by this PSS-only subject key.
Both public verifier entry points must reject the certificate's subject profile.
This is distinct from an unrestricted RSA subject whose issuer uses PSS.

The bundles include genuine synthetic CA, SCT, checkpoint and SET signatures.
Replay tests verify those underlying signatures independently, then require
the public verifier to reject the unsupported subject profile. No verification
step is mocked. This is not evidence of enrollment in Fulcio or public Rekor.
Only public certificates, public keys and signed artifacts are stored; all
private keys were generated in memory and discarded.

The fixtures were generated with cryptography 50.0.1. Reading them does not
require cryptography 49's certificate-builder extension, so the regression
also runs on the project's minimum supported cryptography version. Regenerate
from the repository root with a development environment using cryptography 49
or newer:

```sh
python test/assets/rsa-pss-spki/generate.py
```

Regeneration reuses the synthetic full-bundle builder and adjusts only RSA
subject-key encoding during certificate creation. It overwrites the four data
files in this directory with fresh random keys and signatures; it is not
byte-reproducible and never runs during tests.
