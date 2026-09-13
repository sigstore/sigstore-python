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

"""Regenerate public-only RSA-PSS subject-SPKI fixtures with cryptography >= 49.

Run from the repository root in its development environment. All keys are
generated in memory and discarded. This does not contact any external service.
"""

import json
import sys
from pathlib import Path
from unittest.mock import patch

import cryptography
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding, rsa

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
from test.unit.verify import test_verifier_rsa_bundle as fixture  # noqa: E402


def main():
    if int(cryptography.__version__.split(".")[0]) < 49:
        raise SystemExit("Regeneration requires cryptography >= 49; replay does not")

    public_key = x509.CertificateBuilder.public_key

    def pss_subject(builder, key, *args, **kwargs):
        if isinstance(key, rsa.RSAPublicKey):
            kwargs["rsa_padding"] = padding.PSS
        return public_key(builder, key, *args, **kwargs)

    # Change only certificate generation. Every signature and verification
    # operation remains real; no verifier is replaced here or in replay tests.
    with patch.object(x509.CertificateBuilder, "public_key", pss_subject):
        materials = fixture.rsa_bundle_materials.__wrapped__()

    files = {
        "trusted-root.json": materials[3]._inner.to_json(),
        "artifact.sigstore.json": fixture._bundle(materials, False).to_json(),
        "dsse.sigstore.json": fixture._bundle(materials, True).to_json(),
    }
    directory = Path(__file__).resolve().parent
    for name, contents in files.items():
        # Only public certificates, public keys and signed messages are exported.
        (directory / name).write_text(
            json.dumps(json.loads(contents), indent=2) + "\n", encoding="utf-8"
        )
    (directory / "artifact.txt").write_bytes(fixture._ARTIFACT)


if __name__ == "__main__":
    main()
