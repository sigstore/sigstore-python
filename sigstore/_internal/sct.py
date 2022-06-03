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
from datetime import timezone
from typing import List, Optional, Tuple, Union

import cryptography.hazmat.primitives.asymmetric.padding as padding
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509 import Certificate, ExtendedKeyUsage, ObjectIdentifier
from cryptography.x509.certificate_transparency import (  # SignatureAlgorithm,
    LogEntryType,
    SignedCertificateTimestamp,
)
from cryptography.x509.oid import ExtensionOID
from pyasn1.codec.der.decoder import decode as asn1_decode
from pyasn1.codec.der.encoder import encode as asn1_encode
from pyasn1_modules import rfc5280

logger = logging.getLogger(__name__)

# HACK(#84): Replace with the import below.
# from cryptography.x509.oid import ExtendedKeyUsageOID
_CERTIFICATE_TRANSPARENCY = ObjectIdentifier("1.3.6.1.4.1.11129.2.4.4")

# HACK(#84): Remove entirely.
_HASH_ALGORITHM_SHA256 = 4
_SIG_ALGORITHM_RSA = 1
_SIG_ALGORITHM_ECDSA = 3


# HACK(#84): Remove entirely.
def _make_tbs_precertificate_bytes(cert: Certificate) -> bytes:
    if hasattr(cert, "tbs_precertificate_bytes"):
        # NOTE(ww): cryptography 38, which is unreleased, will contain this API.
        return cert.tbs_precertificate_bytes  # type: ignore[attr-defined, no-any-return]
    else:
        # Otherwise, we have to do things the hard way: we take the raw
        # DER-encoded TBSCertificate, re-decode it, and manually strip
        # out the SCT list extension.
        tbs_cert = asn1_decode(
            cert.tbs_certificate_bytes, asn1Spec=rfc5280.TBSCertificate()
        )[0]

        filtered_extensions = [
            ext
            for ext in tbs_cert["extensions"]
            if str(ext["extnID"])
            != ExtensionOID.PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS.dotted_string
        ]
        tbs_cert["extensions"].clear()
        tbs_cert["extensions"].extend(filtered_extensions)

        return asn1_encode(tbs_cert)  # type: ignore[no-any-return]


# HACK(#84): Remove entirely.
def _sct_properties(
    sct: SignedCertificateTimestamp, raw_sct: Optional[bytes]
) -> Tuple[hashes.HashAlgorithm, int, bytes]:
    if hasattr(sct, "signature"):
        return (
            sct.hash_algorithm,  # type: ignore[attr-defined]
            sct.signature_algorithm,  # type: ignore[attr-defined]
            sct.signature,  # type: ignore[attr-defined]
        )

    if not raw_sct:
        raise InvalidSctError("API misuse: missing raw SCT")

    return _raw_sct_properties(raw_sct)


# HACK(#84): Remove entirely.
def _raw_sct_properties(raw_sct: bytes) -> Tuple[hashes.HashAlgorithm, int, bytes]:
    # YOLO: A raw SCT looks like this:
    #
    #   u8     Version
    #   u8[32] LogID
    #   u64    Timestamp
    #   opaque CtExtensions<0..2^16-1>
    #   digitally-signed struct { ... }
    #
    # The last component contains the signature, in RFC5246's
    # digitally-signed format, which looks like this:
    #
    #   u8 Hash
    #   u8 Signature
    #   opaque signature<0..2^16-1>

    def _opaque16(value: bytes) -> bytes:
        # invariant: there have to be at least two bytes, for the length.
        if len(value) < 2:
            raise InvalidSctError("malformed TLS encoding in SCT (length)")

        (length,) = struct.unpack("!H", value[0:2])

        if length != len(value[2:]):
            raise InvalidSctError("malformed TLS encoding in SCT (payload)")

        return value[2:]

    # 43 = sizeof(Version) + sizeof(LogID) + sizeof(Timestamp) + sizeof(opauque CtExtensions),
    # the latter being assumed to be just two (length + zero payload).
    digitally_signed_offset = 43
    digitally_signed = raw_sct[digitally_signed_offset:]

    hash_algorithm = digitally_signed[0]
    signature_algorithm = digitally_signed[1]
    signature = _opaque16(digitally_signed[2:])

    if hash_algorithm != _HASH_ALGORITHM_SHA256:
        raise InvalidSctError(
            f"invalid hash algorithm ({hash_algorithm}, expected {_HASH_ALGORITHM_SHA256})"
        )
    return (hashes.SHA256(), signature_algorithm, signature)


# HACK(#84): Remove entirely.
def _sct_extension_bytes(sct: SignedCertificateTimestamp) -> bytes:
    if hasattr(sct, "extension_bytes"):
        return sct.extension_bytes  # type: ignore[attr-defined, no-any-return]

    # We don't actually expect any extension bytes anyways, so this is okay.
    return b""


def _pack_signed_entry(
    sct: SignedCertificateTimestamp, cert: Certificate, issuer_key_hash: Optional[bytes]
) -> bytes:
    fields = []
    if sct.entry_type == LogEntryType.X509_CERTIFICATE:
        # When dealing with a "normal" certificate, our signed entry looks like this:
        #
        # [0]: opaque ASN.1Cert<1..2^24-1>
        pack_format = "!BBB{cert_der_len}s"
        cert_der = cert.public_bytes(encoding=serialization.Encoding.DER)
    elif sct.entry_type == LogEntryType.PRE_CERTIFICATE:
        if not issuer_key_hash or len(issuer_key_hash) != 32:
            raise InvalidSctError("API misuse: issuer key hash missing")

        # When dealing with a precertificate, our signed entry looks like this:
        #
        # [0]: issuer_key_hash[32]
        # [1]: opaque TBSCertificate<1..2^24-1>
        pack_format = "!32sBBB{cert_der_len}s"

        # Precertificates must have their SCT list extension filtered out.
        cert_der = _make_tbs_precertificate_bytes(cert)
        fields.append(issuer_key_hash)
    else:
        raise InvalidSctError(f"unknown SCT log entry type: {sct.entry_type!r}")

    # The `opaque` length is a u24, which isn't directly supported by `struct`.
    # So we have to decompose it into 3 bytes.
    unused, len1, len2, len3 = struct.unpack(
        "!4B",
        struct.pack("!I", len(cert_der)),
    )
    if unused:
        raise InvalidSctError(f"Unexpectedly large certificate length: {len(cert_der)}")

    pack_format = pack_format.format(cert_der_len=len(cert_der))
    fields.extend((len1, len2, len3, cert_der))

    return struct.pack(pack_format, *fields)


def _pack_digitally_signed(
    sct: SignedCertificateTimestamp,
    cert: Certificate,
    issuer_key_hash: Optional[bytes],
) -> bytes:
    """
    Packs the contents of `cert` (and some pieces of `sct`) into a structured
    blob, one that forms the signature body of the "digitally-signed" struct
    for an SCT.

    The format of the digitally signed data is described in IETF's RFC 6962.
    """

    # No extensions are currently specified, so we treat the presence
    # of any extension bytes as suspicious.
    # HACK(#84): Replace with `sct.extension_bytes`
    if len(_sct_extension_bytes(sct)) != 0:
        raise InvalidSctError("Unexpected trailing extension bytes")

    # This constructs the "core" `signed_entry` field, which is either
    # the public bytes of the cert *or* the TBSPrecertificate (with some
    # filtering), depending on whether our SCT is for a precertificate.
    signed_entry = _pack_signed_entry(sct, cert, issuer_key_hash)

    # Assemble a format string with the certificate length baked in and then pack the digitally
    # signed data
    # fmt: off
    pattern = "!BBQH%dsH" % len(signed_entry)
    timestamp = sct.timestamp.replace(tzinfo=timezone.utc)
    data = struct.pack(
        pattern,
        sct.version.value,                  # sct_version
        0,                                  # signature_type (certificate_timestamp(0))
        int(timestamp.timestamp() * 1000),  # timestamp (milliseconds)
        sct.entry_type.value,               # entry_type (x509_entry(0) | precert_entry(1))
        signed_entry,                       # select(entry_type) -> signed_entry (see above)
        # HACK(#84): Replace with `sct.extension_bytes`
        len(_sct_extension_bytes(sct)),     # extensions (opaque CtExtensions<0..2^16-1>)
    )
    # fmt: on

    return data


def _is_preissuer(issuer: Certificate) -> bool:
    ext_key_usage = issuer.extensions.get_extension_for_class(ExtendedKeyUsage)

    # HACK(#84): Replace with the line below.
    # return ExtendedKeyUsageOID.CERTIFICATE_TRANSPARENCY in ext_key_usage.value
    return _CERTIFICATE_TRANSPARENCY in ext_key_usage.value


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
    raw_sct: Optional[bytes],
) -> None:
    """Verify a signed certificate timestamp"""

    issuer_key_hash = None
    if sct.entry_type == LogEntryType.PRE_CERTIFICATE:
        # If we're verifying an SCT for a precertificate, we need to
        # find its issuer in the chain and calculate a hash over
        # its public key information, as part of the "binding" proof
        # that ties the issuer to the final certificate.
        issuer_key_hash = _issuer_key_hash(_get_issuer_cert(chain))

    digitally_signed = _pack_digitally_signed(sct, cert, issuer_key_hash)

    hash_algorithm, signature_algorithm, signature = _sct_properties(sct, raw_sct)

    # HACK(#84): Refactor.
    if not isinstance(hash_algorithm, hashes.SHA256):
        raise InvalidSctError(
            "Found unexpected hash algorithm in SCT: only SHA256 is supported "
            f"(expected {_HASH_ALGORITHM_SHA256}, got {hash_algorithm})"
        )

    try:
        # HACK(#84): Replace with `sct.signature_algorithm`
        if signature_algorithm == _SIG_ALGORITHM_RSA and isinstance(
            ctfe_key, rsa.RSAPublicKey
        ):
            ctfe_key.verify(
                signature=signature,
                data=digitally_signed,
                padding=padding.PKCS1v15(),
                algorithm=hashes.SHA256(),
            )
        # HACK(#84): Replace with `sct.signature_algorithm`
        elif signature_algorithm == _SIG_ALGORITHM_ECDSA and isinstance(
            ctfe_key, ec.EllipticCurvePublicKey
        ):
            ctfe_key.verify(
                signature=signature,
                data=digitally_signed,
                signature_algorithm=ec.ECDSA(hashes.SHA256()),
            )
        else:
            raise InvalidSctError(
                "Found unexpected signature type in SCT: signature type of"
                f"{signature_algorithm} and CTFE key type of {type(ctfe_key)}"
            )
    except InvalidSignature as inval_sig:
        raise InvalidSctError from inval_sig
