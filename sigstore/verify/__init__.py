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

from sigstore.models import Bundle
from sigstore.verify import Verifier
from sigstore.verify.policy import Identity

# The input to verify
input_ = Path("foo.txt").read_bytes()

# The bundle to verify with
bundle = Bundle.from_json(Path("foo.txt.sigstore.json").read_bytes())

verifier = Verifier.production()
result = verifier.verify(
    input_,
    bundle,
    Identity(
        identity="foo@bar.com",
        issuer="https://accounts.google.com",
    ),
)
print(result)
```
"""

from sigstore.verify.verifier import Verifier

__all__ = [
    "Verifier",
    "policy",
    "verifier",
]
