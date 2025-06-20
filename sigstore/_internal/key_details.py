# Copyright 2025 The Sigstore Authors
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
Utilities for getting the sigstore_protobuf_specs.dev.sigstore.common.v1.PublicKeyDetails.
"""

from cryptography.hazmat.primitives.asymmetric import ec
from sigstore_protobuf_specs.dev.sigstore.common import v1


def _get_key_details(public_key: v1.PublicKey) -> v1.PublicKeyDetails:
    """
    Determine PublicKeyDetails from the public key.
    See https://github.com/sigstore/architecture-docs/blob/6a8d78108ef4bb403046817fbcead211a9dca71d/algorithm-registry.md.
    """
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        if isinstance(public_key.curve, ec.SECP256R1):
            return v1.PublicKeyDetails.PKIX_ECDSA_P256_SHA_256
        elif isinstance(public_key.curve, ec.SECP384R1):
            return v1.PublicKeyDetails.PKIX_ECDSA_P384_SHA_384
        elif isinstance(public_key.curve, ec.SECP521R1):
            return v1.PublicKeyDetails.PKIX_ECDSA_P521_SHA_512
        else:
            raise ValueError(f"Unsupported EC curve: {public_key.curve.name}")
    else:
        raise ValueError(f"Unsupported public key type: {type(public_key)}")
