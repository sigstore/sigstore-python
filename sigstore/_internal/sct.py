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
import logging
import struct
from typing import List, Union

import cryptography.hazmat.primitives.asymmetric.padding as padding
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509 import Certificate, ExtendedKeyUsage, ObjectIdentifier
from cryptography.x509.certificate_transparency import (
    SignedCertificateTimestamp,
)

logger = logging.getLogger(__name__)


def _pack_digitally_signed(
    sct: SignedCertificateTimestamp,
    cert: Certificate,
    issuer_key_hash: bytes,
) -> bytes:
    """
    Packs the contents of `cert` (and some pieces of `sct`) into a structured
    blob, one that forms the signature body of the "digitally-signed" struct
    for an SCT.

    The format of the digitally signed data is described in IETF's RFC 6962.
    """

    # The digitally signed format requires the certificate in DER format,
    # and with any SCTs (embedded as X.509v3 extensions) filtered out.
    cert_der: bytes = cert.tbs_precertificate_bytes

    # The length is a u24, which isn't directly supported by `struct`.
    # So we have to decompose it into 3 bytes.
    unused, len1, len2, len3 = struct.unpack(
        "!4B",
        struct.pack("!I", len(cert_der)),
    )
    if unused:
        raise InvalidSctError(f"Unexpectedly large certificate length: {len(cert_der)}")

    # No extensions are currently specified, so we treat the presence
    # of any extension bytes as suspicious.
    if len(sct.extension_bytes) != 0:
        raise InvalidSctError("Unexpected trailing extension bytes")

    # NOTE(ww): This is incorrect for non-embedded SCTs, since it unconditionally
    # embeds the issuer_key_hash.

    # Assemble a format string with the certificate length baked in and then pack the digitally
    # signed data
    # fmt: off
    pattern = "!BBQH32sBBB%ssH" % len(cert_der)
    data = struct.pack(
        pattern,
        sct.version.value,                      # sct_version
        0,                                      # signature_type (certificate_timestamp(0))
        int(sct.timestamp.timestamp() * 1000),  # timestamp (milliseconds)
        sct.entry_type.value,                   # entry_type (x509_entry(0) | precert_entry(1))
        issuer_key_hash,                        # issuer_key_hash[32]
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


def _issuer_key_hash(cert: Certificate) -> bytes:
    issuer_key: bytes = cert.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    return hashlib.sha256(issuer_key).digest()


class InvalidSctError(Exception):
    pass


def verify_sct(
    sct: SignedCertificateTimestamp,
    cert: Certificate,
    chain: List[Certificate],
    ctfe_key: Union[rsa.RSAPublicKey, ec.EllipticCurvePublicKey],
) -> None:
    """Verify a signed certificate timestamp"""

    issuer_key_hash = _issuer_key_hash(_get_issuer_cert(chain))
    digitally_signed = _pack_digitally_signed(sct, cert, issuer_key_hash)
    try:
        if isinstance(ctfe_key, rsa.RSAPublicKey):
            ctfe_key.verify(
                signature=sct.signature,
                data=digitally_signed,
                padding=padding.PKCS1v15(),
                algorithm=hashes.SHA256(),
            )
        else:
            ctfe_key.verify(
                signature=sct.signature,
                data=digitally_signed,
                signature_algorithm=ec.ECDSA(hashes.SHA256()),
            )
    except InvalidSignature as inval_sig:
        raise InvalidSctError from inval_sig
