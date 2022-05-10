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
from typing import Optional

import cryptography.hazmat.primitives.asymmetric.padding as padding
import cryptography.hazmat.primitives.asymmetric.rsa as rsa
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509 import Certificate
from cryptography.x509.certificate_transparency import (
    SignedCertificateTimestamp,
)


def _pack_digitally_signed(
    sct: SignedCertificateTimestamp,
    cert: Certificate,
    ctfe_key: rsa.RSAPublicKey,
    precert_issuer: Optional[bytes] = None,
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
    cert_der: bytes = cert.tbs_precertificate_bytes(precert_issuer)

    # The length should then be split into three bytes.
    unused, len1, len2, len3 = struct.unpack(
        "!4B",
        struct.pack("!I", len(cert_der)),
    )
    if unused:
        raise InvalidSctError(f"Unexpectedly large certificate length: {len(cert_der)}")

    # Assemble a format string with the certificate length baked in and then pack the digitally
    # signed data
    pattern = "!BBQh32sBBB%ssh" % len(cert_der)
    data = struct.pack(
        pattern,
        sct.version._value_,
        0,  # Signature Type
        int(sct.timestamp.timestamp()) * 1000,
        sct.entry_type._value_,
        hashlib.sha256(
            ctfe_key.public_bytes(
                serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        ).digest(),
        len1,
        len2,
        len3,
        cert_der,
        0,  # Extension Length
    )

    return data


class InvalidSctError(Exception):
    pass


def verify_sct(
    sct: SignedCertificateTimestamp,
    cert: Certificate,
    ctfe_key: rsa.RSAPublicKey,
    precert_issuer: Optional[bytes] = None,
) -> None:
    """Verify a signed certificate timestamp"""
    digitally_signed = _pack_digitally_signed(sct, cert, ctfe_key, precert_issuer)
    try:
        ctfe_key.verify(
            signature=sct.signature,
            data=digitally_signed,
            padding=padding.PKCS1v15(),
            algorithm=hashes.SHA256(),
        )
    except InvalidSignature as inval_sig:
        raise InvalidSctError from inval_sig
