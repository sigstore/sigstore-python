# Copyright 2026 The Sigstore Authors
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

import hashlib
import json

import pytest
from sigstore_models.trustroot.v1 import TrustedRoot as _TrustedRoot

from sigstore._internal.tuf import DEFAULT_TUF_URL
from sigstore._utils import read_embedded
from sigstore.errors import VerificationError
from sigstore.models import Bundle, TrustedRoot
from sigstore.verify import Verifier
from sigstore.verify.policy import Identity


def test_real_npm_intoto_bundle(asset):
    """Verify the public bundle from #1384 entirely offline, with no verifier mocks."""
    raw = asset("npm/sigstore-3.1.0.sigstore.json").read_bytes()
    assert hashlib.sha256(raw).hexdigest() == (
        "ec47e8d5a9804173596eafcbead2f248ae0442f8ab4aa66b51c88bd85f5fd4a1"
    )
    bundle = Bundle.from_json(raw)
    verifier = Verifier(
        trusted_root=TrustedRoot(
            _TrustedRoot.from_json(read_embedded("trusted_root.json", DEFAULT_TUF_URL))
        )
    )
    identity = (
        "https://github.com/sigstore/sigstore-js/.github/workflows/"
        "release.yml@refs/heads/main"
    )
    issuer = "https://token.actions.githubusercontent.com"
    payload_type, payload = verifier.verify_dsse(
        bundle, Identity(identity=identity, issuer=issuer)
    )
    assert payload_type == "application/vnd.in-toto+json"
    statement = json.loads(payload)
    assert statement["predicateType"] == "https://slsa.dev/provenance/v1"
    assert statement["subject"][0]["name"] == "pkg:npm/sigstore@3.1.0"

    with pytest.raises(VerificationError, match="SANs do not match"):
        verifier.verify_dsse(
            bundle, Identity(identity="wrong@example.com", issuer=issuer)
        )
    with pytest.raises(VerificationError, match="OIDCIssuer"):
        verifier.verify_dsse(
            bundle, Identity(identity=identity, issuer="https://wrong.invalid")
        )
