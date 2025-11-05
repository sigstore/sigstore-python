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
Utilities for getting PublicKeyDetails.
"""

from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.x509 import Certificate
from sigstore_models.common.v1 import PublicKeyDetails


def _get_key_details(certificate: Certificate) -> PublicKeyDetails:
    """
    Determine PublicKeyDetails from the Certificate.
    We disclude the unrecommended types.
    See
    - https://github.com/sigstore/architecture-docs/blob/6a8d78108ef4bb403046817fbcead211a9dca71d/algorithm-registry.md.
    - https://github.com/sigstore/protobuf-specs/blob/3aaae418f76fb4b34df4def4cd093c464f20fed3/protos/sigstore_common.proto
    """
    public_key = certificate.public_key()
    params = certificate.signature_algorithm_parameters
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        if isinstance(public_key.curve, ec.SECP256R1):
            key_details = PublicKeyDetails.PKIX_ECDSA_P256_SHA_256
        elif isinstance(public_key.curve, ec.SECP384R1):
            key_details = PublicKeyDetails.PKIX_ECDSA_P384_SHA_384
        elif isinstance(public_key.curve, ec.SECP521R1):
            key_details = PublicKeyDetails.PKIX_ECDSA_P521_SHA_512
        else:
            raise ValueError(f"Unsupported EC curve: {public_key.curve.name}")
    elif isinstance(public_key, rsa.RSAPublicKey):
        if public_key.key_size == 3072:
            if isinstance(params, padding.PKCS1v15):
                key_details = PublicKeyDetails.PKIX_RSA_PKCS1V15_3072_SHA256
            else:
                raise ValueError(
                    f"Unsupported public key type, size, and padding: {type(public_key)}, {public_key.key_size}, {params}"
                )
        elif public_key.key_size == 4096:
            if isinstance(params, padding.PKCS1v15):
                key_details = PublicKeyDetails.PKIX_RSA_PKCS1V15_4096_SHA256
            else:
                raise ValueError(
                    f"Unsupported public key type, size, and padding: {type(public_key)}, {public_key.key_size}, {params}"
                )
        else:
            raise ValueError(f"Unsupported RSA key size: {public_key.key_size}")
    elif isinstance(public_key, ed25519.Ed25519PublicKey):
        key_details = PublicKeyDetails.PKIX_ED25519
    # There is likely no need to explicitly detect PKIX_ED25519_PH, especially since the cryptography
    # library does not yet support Ed25519ph.
    else:
        raise ValueError(f"Unsupported public key type: {type(public_key)}")
    return key_details
