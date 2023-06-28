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
from cryptography.x509 import Certificate, ExtensionNotFound, Version
from cryptography.x509.oid import ExtendedKeyUsageOID, ExtensionOID

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


class InvalidCertError(Error):
    """
    Raised when loading or evaluating a certificate fails.
    """


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


def read_embedded(name: str, prefix: str) -> bytes:
    """
    Read a resource embedded in this distribution of sigstore-python,
    returning its contents as bytes.
    """
    return resources.files("sigstore._store").joinpath(prefix, name).read_bytes()  # type: ignore


def cert_is_ca(cert: Certificate) -> bool:
    """
    Returns `True` if and only if the given `Certificate`
    is a CA certificate.

    This function doesn't indicate the trustworthiness of the given
    `Certificate`, only whether it has the appropriate interior state.

    This function is **not** naively invertible: users **must** use the
    dedicated `cert_is_leaf` utility function to determine whether a particular
    leaf upholds Sigstore's invariants.
    """

    # Only v3 certificates should appear in the context of Sigstore;
    # earlier versions of X.509 lack extensions and have ambiguous CA
    # behavior.
    if cert.version != Version.v3:
        raise InvalidCertError(f"invalid X.509 version: {cert.version}")

    # Valid CA certificates must have *all* of the following set:
    #
    #  * `BasicKeyUsage.digitalSignature`
    #  * `BasicKeyUsage.keyCertSign`
    #  * `BasicConstraints.ca`
    #
    # Of those, non-CAs must have *only* `BasicKeyUsage.digitalSignature` set.
    # Any other combination of states is inconsistent and invalid, meaning
    # that we won't consider the certificate a valid non-CA leaf.

    try:
        basic_constraints = cert.extensions.get_extension_for_oid(
            ExtensionOID.BASIC_CONSTRAINTS
        )

        # BasicConstraints must be marked as critical, per RFC 5280 4.2.1.9.
        if not basic_constraints.critical:
            raise InvalidCertError(
                "invalid X.509 certificate: non-critical BasicConstraints in CA"
            )

        ca = basic_constraints.value.ca  # type: ignore
    except ExtensionNotFound:
        # No BasicConstrains means that this can't possibly be a CA.
        return False

    key_cert_sign = False
    try:
        key_usage = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE)
        key_cert_sign = key_usage.value.key_cert_sign  # type: ignore
    except ExtensionNotFound:
        raise InvalidCertError("invalid X.509 certificate: missing KeyUsage")

    # If both states are set, this is a CA.
    if ca and key_cert_sign:
        return True

    if not (ca or key_cert_sign):
        return False

    # Anything else is an invalid state that should never occur.
    raise InvalidCertError(
        f"invalid certificate states: KeyUsage.keyCertSign={key_cert_sign}"
        f", BasicConstraints.ca={ca}"
    )


def cert_is_root_ca(cert: Certificate) -> bool:
    """
    Returns `True` if and only if the given `Certificate` indicates
    that it's a root CA.

    This is **not** a verification function, and it does not establish
    the trustworthiness of the given certificate.
    """

    # NOTE(ww): This function is obnoxiously long to make the different
    # states explicit.

    # Only v3 certificates should appear in the context of Sigstore;
    # earlier versions of X.509 lack extensions and have ambiguous CA
    # behavior.
    if cert.version != Version.v3:
        raise InvalidCertError(f"invalid X.509 version: {cert.version}")

    # Non-CAs can't possibly be root CAs.
    if not cert_is_ca(cert):
        return False

    # A certificate that is its own issuer and signer is considered a root CA.
    try:
        cert.verify_directly_issued_by(cert)
        return True
    except Exception:
        return False


def cert_is_leaf(cert: Certificate) -> bool:
    """
    Returns `True` if and only if the given `Certificate` is a valid
    leaf certificate for Sigstore purposes. This means that:

    * It is not a root or intermediate CA;
    * It has `KeyUsage.digitalSignature`;
    * It has `CODE_SIGNING` as an `ExtendedKeyUsage`.

    This is **not** a verification function, and it does not establish
    the trustworthiness of the given certificate.
    """

    # Only v3 certificates should appear in the context of Sigstore;
    # earlier versions of X.509 lack extensions and have ambiguous CA
    # behavior.
    if cert.version != Version.v3:
        raise InvalidCertError(f"invalid X.509 version: {cert.version}")

    # CAs are not leaves.
    if cert_is_ca(cert):
        return False

    key_usage = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE)
    digital_signature = key_usage.value.digital_signature  # type: ignore

    if not digital_signature:
        raise InvalidCertError(
            "invalid certificate for Sigstore purposes: missing digital signature usage"
        )

    # Finally, we check to make sure the leaf has an `ExtendedKeyUsages`
    # extension that includes a codesigning entitlement. Sigstore should
    # never issue a leaf that doesn't have this extended usage.
    try:
        extended_key_usage = cert.extensions.get_extension_for_oid(
            ExtensionOID.EXTENDED_KEY_USAGE
        )

        return ExtendedKeyUsageOID.CODE_SIGNING in extended_key_usage.value  # type: ignore
    except ExtensionNotFound:
        raise InvalidCertError("invalid X.509 certificate: missing ExtendedKeyUsage")
