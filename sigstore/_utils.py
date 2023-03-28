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

from __future__ import annotations

import base64
import hashlib
import sys
from typing import IO, NewType, Union

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509 import Certificate

from sigstore.errors import Error

if sys.version_info < (3, 11):
    import importlib_resources as resources
else:
    from importlib import resources


PublicKey = Union[rsa.RSAPublicKey, ec.EllipticCurvePublicKey]

HexStr = NewType("HexStr", str)
"""
A newtype for `str` objects that contain hexadecimal strings (e.g. `ffabcd00ff`).
"""
B64Str = NewType("B64Str", str)
"""
A newtype for `str` objects that contain base64 encoded strings.
"""
PEMCert = NewType("PEMCert", str)
"""
A newtype for `str` objects that contain PEM-encoded certificates.
"""
DERCert = NewType("DERCert", bytes)
"""
A newtype for `bytes` objects that contain DER-encoded certificates.
"""
KeyID = NewType("KeyID", bytes)
"""
A newtype for `bytes` objects that contain a key id.
"""


class InvalidKeyError(Error):
    """
    Raised when loading a key fails.
    """

    pass


class UnexpectedKeyFormatError(InvalidKeyError):
    """
    Raised when loading a key produces a key of an unexpected type.
    """

    pass


def load_pem_public_key(key_pem: bytes) -> PublicKey:
    """
    A specialization of `cryptography`'s `serialization.load_pem_public_key`
    with a uniform exception type (`InvalidKeyError`) and additional restrictions
    on key validity (only RSA and ECDSA keys are valid).
    """

    try:
        key = serialization.load_pem_public_key(key_pem)
    except Exception as exc:
        raise InvalidKeyError("could not load PEM-formatted public key") from exc

    if not isinstance(key, (rsa.RSAPublicKey, ec.EllipticCurvePublicKey)):
        raise UnexpectedKeyFormatError(f"invalid key format (not ECDSA or RSA): {key}")

    return key


def load_der_public_key(key_der: bytes) -> PublicKey:
    """
    The `load_pem_public_key` specialization, but DER.
    """

    try:
        key = serialization.load_der_public_key(key_der)
    except Exception as exc:
        raise InvalidKeyError("could not load DER-formatted public key") from exc

    if not isinstance(key, (rsa.RSAPublicKey, ec.EllipticCurvePublicKey)):
        raise UnexpectedKeyFormatError(f"invalid key format (not ECDSA or RSA): {key}")

    return key


def base64_encode_pem_cert(cert: Certificate) -> B64Str:
    """
    Returns a string containing a base64-encoded PEM-encoded X.509 certificate.
    """

    return B64Str(
        base64.b64encode(cert.public_bytes(serialization.Encoding.PEM)).decode()
    )


def key_id(key: PublicKey) -> KeyID:
    """
    Returns an RFC 6962-style "key ID" for the given public key.

    See: <https://www.rfc-editor.org/rfc/rfc6962#section-3.2>
    """
    public_bytes = key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    return KeyID(hashlib.sha256(public_bytes).digest())


def sha256_streaming(io: IO[bytes]) -> bytes:
    """
    Compute the SHA256 of a stream.

    This function does its own internal buffering, so an unbuffered stream
    should be supplied for optimal performance.
    """

    # NOTE: This function performs a SHA256 digest over a stream.
    # The stream's size is not checked, meaning that the stream's source
    # is implicitly trusted: if an attacker is able to truncate the stream's
    # source prematurely, then they could conceivably produce a digest
    # for a partial stream. This in turn could conceivably result
    # in a valid signature for an unintended (truncated) input.
    #
    # This is currently outside of sigstore-python's threat model: we
    # assume that the stream is trusted.
    #
    # See: https://github.com/sigstore/sigstore-python/pull/329#discussion_r1041215972

    sha256 = hashlib.sha256()
    # Per coreutils' ioblksize.h: 128KB performs optimally across a range
    # of systems in terms of minimizing syscall overhead.
    view = memoryview(bytearray(128 * 1024))

    nbytes = io.readinto(view)  # type: ignore
    while nbytes:
        sha256.update(view[:nbytes])
        nbytes = io.readinto(view)  # type: ignore

    return sha256.digest()


def read_embedded(name: str) -> bytes:
    """
    Read a resource embedded in this distribution of sigstore-python,
    returning its contents as bytes.
    """
    return resources.files("sigstore._store").joinpath(name).read_bytes()  # type: ignore
