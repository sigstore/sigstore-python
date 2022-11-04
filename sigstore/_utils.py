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
from typing import Union

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509 import (
    Certificate,
    ObjectIdentifier,
    OtherName,
    RFC822Name,
    SubjectAlternativeName,
    UniformResourceIdentifier,
)

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


def cert_contains_identity(cert: Certificate, expected_cert_identity: str) -> bool:
    """
    Check that the certificate's SubjectAlternativeName contains a given identity.
    """
    san_ext = cert.extensions.get_extension_for_class(SubjectAlternativeName)
    return (
        expected_cert_identity in san_ext.value.get_values_for_type(RFC822Name)
        or expected_cert_identity
        in san_ext.value.get_values_for_type(UniformResourceIdentifier)
        or OtherName(
            ObjectIdentifier("1.3.6.1.4.1.57264.1.7"), expected_cert_identity.encode()
        )
        in san_ext.value.get_values_for_type(OtherName)
    )
