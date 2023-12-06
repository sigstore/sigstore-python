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
Functionality for building and manipulating DSSE envelopes.
"""

import base64

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from google.protobuf.json_format import MessageToJson
from in_toto_attestation.v1.statement import Statement
from sigstore_protobuf_specs.io.intoto import Envelope, Signature


def sign_intoto(key: ec.EllipticCurvePrivateKey, payload: Statement) -> Envelope:
    """
    Create a DSSE envelope containing a signature over an in-toto formatted
    attestation.
    """

    # See:
    # https://github.com/secure-systems-lab/dsse/blob/v1.0.0/envelope.md
    # https://github.com/in-toto/attestation/blob/v1.0/spec/v1.0/envelope.md

    type_ = "application/vnd.in-toto+json"
    payload_b64 = base64.b64encode(MessageToJson(payload.pb).encode()).decode()
    pae = f"DSSEv1 {len(type_)} {type} {len(payload_b64)} {payload_b64}"

    signature = key.sign(pae.encode(), ec.ECDSA(hashes.SHA256()))
    return Envelope(
        payload=payload_b64.encode(),
        payload_type=type_,
        signatures=[Signature(sig=signature, keyid=None)],
    )
