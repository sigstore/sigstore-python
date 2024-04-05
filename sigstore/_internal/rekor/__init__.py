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
APIs for interacting with Rekor.
"""

import base64

import rekor_types
from cryptography.x509 import Certificate

from sigstore import dsse
from sigstore._utils import base64_encode_pem_cert
from sigstore.hashes import Hashed

from .checkpoint import SignedCheckpoint
from .client import RekorClient

__all__ = ["RekorClient", "SignedCheckpoint"]


def _dsse_from_parts(cert: Certificate, evp: dsse.Envelope) -> rekor_types.Dsse:
    signature = rekor_types.dsse.Signature(
        signature=evp._inner.signatures[0].sig,
        verifier=base64_encode_pem_cert(cert),
    )
    return rekor_types.Dsse(
        spec=rekor_types.dsse.DsseV001Schema(
            signatures=[signature],
            envelope_hash=rekor_types.dsse.EnvelopeHash(
                algorithm=rekor_types.dsse.Algorithm.SHA256,
                value=None,
            ),
            payload_hash=rekor_types.dsse.PayloadHash(
                algorithm=rekor_types.dsse.Algorithm.SHA256,
                value=None,
            ),
        )
    )


# TODO: This should probably live somewhere better.
def _hashedrekord_from_parts(
    cert: Certificate, sig: bytes, hashed: Hashed
) -> rekor_types.Hashedrekord:
    return rekor_types.Hashedrekord(
        spec=rekor_types.hashedrekord.HashedrekordV001Schema(
            signature=rekor_types.hashedrekord.Signature(
                content=base64.b64encode(sig).decode(),
                public_key=rekor_types.hashedrekord.PublicKey(
                    content=base64_encode_pem_cert(cert),
                ),
            ),
            data=rekor_types.hashedrekord.Data(
                hash=rekor_types.hashedrekord.Hash(
                    algorithm=hashed._as_hashedrekord_algorithm(),
                    value=hashed.digest.hex(),
                )
            ),
        )
    )
