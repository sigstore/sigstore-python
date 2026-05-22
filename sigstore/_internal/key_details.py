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
Utilities for PublicKeyDetails and the algorithm registry.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.x509 import Certificate
from sigstore_models.common.v1 import HashAlgorithm, PublicKeyDetails


@dataclass(frozen=True)
class AlgorithmDetails:
    """Details for a single entry in the algorithm registry."""

    key_details: PublicKeyDetails
    hash_algorithm: HashAlgorithm | None
    hash_func: Callable[[bytes], hashlib._Hash] | None


# Algorithm registry table.
# See https://github.com/sigstore/architecture-docs/blob/main/algorithm-registry.md
_ALGORITHM_REGISTRY: list[AlgorithmDetails] = [
    # RSA PKCS1v15
    AlgorithmDetails(
        PublicKeyDetails.PKIX_RSA_PKCS1V15_2048_SHA256,
        HashAlgorithm.SHA2_256,
        hashlib.sha256,
    ),
    AlgorithmDetails(
        PublicKeyDetails.PKIX_RSA_PKCS1V15_3072_SHA256,
        HashAlgorithm.SHA2_256,
        hashlib.sha256,
    ),
    AlgorithmDetails(
        PublicKeyDetails.PKIX_RSA_PKCS1V15_4096_SHA256,
        HashAlgorithm.SHA2_256,
        hashlib.sha256,
    ),
    # ECDSA
    AlgorithmDetails(
        PublicKeyDetails.PKIX_ECDSA_P256_SHA_256,
        HashAlgorithm.SHA2_256,
        hashlib.sha256,
    ),
    AlgorithmDetails(
        PublicKeyDetails.PKIX_ECDSA_P384_SHA_384,
        HashAlgorithm.SHA2_384,
        hashlib.sha384,
    ),
    AlgorithmDetails(
        PublicKeyDetails.PKIX_ECDSA_P521_SHA_512,
        HashAlgorithm.SHA2_512,
        hashlib.sha512,
    ),
    # Ed25519
    AlgorithmDetails(
        PublicKeyDetails.PKIX_ED25519,
        None,
        None,
    ),
    AlgorithmDetails(
        PublicKeyDetails.PKIX_ED25519_PH,
        HashAlgorithm.SHA2_512,
        hashlib.sha512,
    ),
]

_DETAILS_BY_KEY: dict[PublicKeyDetails, AlgorithmDetails] = {
    entry.key_details: entry for entry in _ALGORITHM_REGISTRY
}


def _get_algorithm_details(key_details: PublicKeyDetails) -> AlgorithmDetails:
    """
    Look up algorithm details by ``PublicKeyDetails`` enum value.
    """
    details = _DETAILS_BY_KEY.get(key_details)
    if details is None:
        raise ValueError(f"unknown signature algorithm: {key_details}")
    return details


def _get_prehash(
    key_details: PublicKeyDetails,
) -> tuple[HashAlgorithm, Callable[[bytes], hashlib._Hash]]:
    """
    Return the externalized hash function for a signing algorithm.

    Only algorithms with an externalized prehash can be used in hashedrekord
    entries. Pure ed25519 (no prehash) raises ``ValueError``.
    """
    details = _get_algorithm_details(key_details)
    if details.hash_func is None:
        raise ValueError(
            f"signing algorithm {key_details} has no externalized prehash; "
            "cannot be used for a hashedrekord entry (rekor-v2-spec §6.1.4)"
        )
    return details.hash_algorithm, details.hash_func


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
        if public_key.key_size == 2048:
            if isinstance(params, padding.PKCS1v15):
                key_details = PublicKeyDetails.PKIX_RSA_PKCS1V15_2048_SHA256
            else:
                raise ValueError(
                    f"Unsupported public key type, size, and padding: {type(public_key)}, {public_key.key_size}, {params}"
                )
        elif public_key.key_size == 3072:
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
