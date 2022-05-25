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
Utilities for verifying signed certificate timestamps.
"""

import hashlib
import struct
from typing import List

import cryptography.hazmat.primitives.asymmetric.padding as padding
import cryptography.hazmat.primitives.asymmetric.rsa as rsa
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509 import Certificate, ExtendedKeyUsage, ObjectIdentifier
from cryptography.x509.certificate_transparency import (
    SignedCertificateTimestamp,
)


def _pack_digitally_signed(
    sct: SignedCertificateTimestamp,
    cert: Certificate,
    issuer_cert: Certificate,
    ctfe_key: rsa.RSAPublicKey,
) -> bytes:
    """
    The format of the digitally signed data is described in IETF's RFC 6962.

    1 SCT Version
    1 Signature Type
    8 Timestamp
    2 Entry Type
    3 Certificate Length
    X Certificate Data
    2 Extensions Length
    """

    # The digitally signed format requires the certificate in DER format.
    cert_der: bytes = cert.tbs_precertificate_bytes

    issuer_key: bytes = issuer_cert.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    # The length should then be split into three bytes.
    unused, len1, len2, len3 = struct.unpack(
        "!4B",
        struct.pack("!I", len(cert_der)),
    )
    if unused:
        raise InvalidSctError(f"Unexpectedly large certificate length: {len(cert_der)}")

    # No extensions are currently specified.
    if len(sct.extension_bytes) != 0:
        raise InvalidSctError("Unexpected trailing extension bytes")

    # NOTE(ww): This is incorrect for non-embedded SCTs, since it unconditionally
    # embeds the issuer_key_hash.

    # Assemble a format string with the certificate length baked in and then pack the digitally
    # signed data
    # fmt: off
    pattern = "!BBQh32sBBB%ssh" % len(cert_der)
    data = struct.pack(
        pattern,
        sct.version.value,                      # sct_version
        0,                                      # signature_type (certificate_timestamp(0))
        int(sct.timestamp.timestamp() * 1000),  # timestamp (milliseconds)
        sct.entry_type.value,                   # entry_type (x509_entry(0) | precert_entry(1))
        hashlib.sha256(issuer_key).digest(),    # issuer_key_hash[32]
        len1,                                   # \
        len2,                                   # | opaque TBSCertificate<1..2^24-1> OR
        len3,                                   # | opaque ASN.1Cert<1..2^24-1>
        cert_der,                               # /
        len(sct.extension_bytes),               # extensions (opaque CtExtensions<0..2^16-1>)
    )
    # fmt: on

    return data


CERTIFICATE_TRANSPARENCY_OID = ObjectIdentifier("1.3.6.1.4.1.11129.2.4.4")


def _is_preissuer(issuer: Certificate) -> bool:
    ext_key_usage = issuer.extensions.get_extension_for_class(ExtendedKeyUsage)
    return CERTIFICATE_TRANSPARENCY_OID in ext_key_usage.value


def _get_issuer_cert(chain: List[Certificate]) -> Certificate:
    issuer = chain[0]
    if _is_preissuer(issuer):
        issuer = chain[1]
    return issuer


class InvalidSctError(Exception):
    pass


def verify_sct(
    sct: SignedCertificateTimestamp,
    cert: Certificate,
    chain: List[Certificate],
    ctfe_key: rsa.RSAPublicKey,
) -> None:
    """Verify a signed certificate timestamp"""
    issuer_cert = _get_issuer_cert(chain)
    digitally_signed = _pack_digitally_signed(sct, cert, issuer_cert, ctfe_key)
    try:
        ctfe_key.verify(
            signature=sct.signature,
            data=digitally_signed,
            padding=padding.PKCS1v15(),
            algorithm=hashes.SHA256(),
        )
    except InvalidSignature as inval_sig:
        raise InvalidSctError from inval_sig
