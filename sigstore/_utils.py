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
Shared utilities.
"""

import base64
import hashlib
from typing import List, Union

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509 import Certificate

PublicKey = Union[rsa.RSAPublicKey, ec.EllipticCurvePublicKey]


class InvalidKey(Exception):
    pass


def load_pem_public_key(key_pem: bytes) -> PublicKey:
    """
    A specialization of `cryptography`'s `serialization.load_pem_public_key`
    with a uniform exception type (`InvalidKey`) and additional restrictions
    on key validity (only RSA and ECDSA keys are valid).
    """

    try:
        key = serialization.load_pem_public_key(key_pem)
    except Exception as exc:
        raise InvalidKey("could not load PEM-formatted public key") from exc

    if not isinstance(key, (rsa.RSAPublicKey, ec.EllipticCurvePublicKey)):
        raise InvalidKey(f"invalid key format (not ECDSA or RSA): {key}")

    return key


def base64_encode_pem_cert(cert: Certificate) -> str:
    """
    Returns a string containing a base64-encoded PEM-encoded X.509 certificate.
    """

    return base64.b64encode(cert.public_bytes(serialization.Encoding.PEM)).decode()


def key_id(key: PublicKey) -> bytes:
    """
    Returns an RFC 6962-style "key ID" for the given public key.

    See: <https://www.rfc-editor.org/rfc/rfc6962#section-3.2>
    """
    public_bytes = key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    return hashlib.sha256(public_bytes).digest()


class SplitCertificateChainError(Exception):
    pass


def split_certificate_chain(chain_pem: str) -> List[bytes]:
    """
    Returns a list of PEM bytes for each individual certificate in the chain.
    """
    PEM_BEGIN_CERTIFICATE = "-----BEGIN CERTIFICATE-----"

    # Check for no certificates
    if not chain_pem:
        raise SplitCertificateChainError("empty PEM file")

    # Use the "begin certificate" marker as a delimiter to split the chain
    certificate_chain = chain_pem.split(PEM_BEGIN_CERTIFICATE)

    # The first entry in the list should be empty since we split by the "begin certificate" marker
    # and there should be nothing before the first certificate
    if certificate_chain[0]:
        raise SplitCertificateChainError(
            "encountered unrecognized content before first PEM entry"
        )

    # Remove the empty entry
    certificate_chain = certificate_chain[1:]

    # Add the delimiters back into each entry since this is required for valid PEM
    certificate_chain = [
        (PEM_BEGIN_CERTIFICATE + c).encode() for c in certificate_chain
    ]

    return certificate_chain
