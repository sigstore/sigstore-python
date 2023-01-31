# Copyright 2022 The Sigstore Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
API for verifying artifact signatures.

Example:
```python
import base64
from pathlib import Path

from sigstore.verify import Verifier, VerificationMaterials
from sigstore.verify.policy import Identity

# The artifact to verify
artifact = Path("foo.txt")

# The signing certificate
cert = Path("foo.txt.crt")

# The signature to verify
signature = Path("foo.txt.sig")

with artifact.open("rb") as a, cert.open("r") as c, signature.open("rb") as s:
    materials = VerificationMaterials(
        input_=a,
        cert_pem=c.read(),
        signature=base64.b64decode(s.read()),
        rekor_entry=None,
    )
    verifier = Verifier.production()
    result = verifier.verify(
        materials,
        Identity(
            identity="foo@bar.com",
            issuer="https://accounts.google.com",
        ),
    )
    print(result)
```
"""

from sigstore.verify.models import (
    VerificationFailure,
    VerificationMaterials,
    VerificationResult,
    VerificationSuccess,
)
from sigstore.verify.verifier import (
    CertificateVerificationFailure,
    LogEntryMissing,
    Verifier,
)

__all__ = [
    "CertificateVerificationFailure",
    "LogEntryMissing",
    "Verifier",
    "VerificationResult",
    "VerificationSuccess",
    "VerificationFailure",
    "VerificationMaterials",
    "policy",
    "models",
    "verifier",
]
