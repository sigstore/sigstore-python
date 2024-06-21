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

import logging
import struct
from datetime import timezone
from typing import List, Optional

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509 import (
    Certificate,
    ExtendedKeyUsage,
    ExtensionNotFound,
    PrecertificateSignedCertificateTimestamps,
)
from cryptography.x509.certificate_transparency import (
    LogEntryType,
    SignedCertificateTimestamp,
)
from cryptography.x509.oid import ExtendedKeyUsageOID

from sigstore._internal.trust import CTKeyring
from sigstore._utils import (
    KeyID,
    cert_is_ca,
    key_id,
)
from sigstore.errors import VerificationError

_logger = logging.getLogger(__name__)


def _pack_signed_entry(
    sct: SignedCertificateTimestamp, cert: Certificate, issuer_key_id: Optional[bytes]
) -> bytes:
    fields = []
    if sct.entry_type == LogEntryType.X509_CERTIFICATE:
        # When dealing with a "normal" certificate, our signed entry looks like this:
        #
        # [0]: opaque ASN.1Cert<1..2^24-1>
        pack_format = "!BBB{cert_der_len}s"
        cert_der = cert.public_bytes(encoding=serialization.Encoding.DER)
    elif sct.entry_type == LogEntryType.PRE_CERTIFICATE:
        if not issuer_key_id or len(issuer_key_id) != 32:
            raise VerificationError("API misuse: issuer key ID missing")

        # When dealing with a precertificate, our signed entry looks like this:
        #
        # [0]: issuer_key_id[32]
        # [1]: opaque TBSCertificate<1..2^24-1>
        pack_format = "!32sBBB{cert_der_len}s"

        # Precertificates must have their SCT list extension filtered out.
        cert_der = cert.tbs_precertificate_bytes
        fields.append(issuer_key_id)
    else:
        raise VerificationError(f"unknown SCT log entry type: {sct.entry_type!r}")

    # The `opaque` length is a u24, which isn't directly supported by `struct`.
    # So we have to decompose it into 3 bytes.
    unused, len1, len2, len3 = struct.unpack(
        "!4B",
        struct.pack("!I", len(cert_der)),
    )
    if unused:
        raise VerificationError(
            f"Unexpectedly large certificate length: {len(cert_der)}"
        )

    pack_format = pack_format.format(cert_der_len=len(cert_der))
    fields.extend((len1, len2, len3, cert_der))

    return struct.pack(pack_format, *fields)


def _pack_digitally_signed(
    sct: SignedCertificateTimestamp,
    cert: Certificate,
    issuer_key_id: Optional[KeyID],
) -> bytes:
    """
    Packs the contents of `cert` (and some pieces of `sct`) into a structured
    blob, one that forms the signature body of the "digitally-signed" struct
    for an SCT.

    The format of the digitaly signed data is described in IETF's RFC 6962.
    """

    # No extensions are currently specified, so we treat the presence
    # of any extension bytes as suspicious.
    if len(sct.extension_bytes) != 0:
        raise VerificationError("Unexpected trailing extension bytes")

    # This constructs the "core" `signed_entry` field, which is either
    # the public bytes of the cert *or* the TBSPrecertificate (with some
    # filtering), depending on whether our SCT is for a precertificate.
    signed_entry = _pack_signed_entry(sct, cert, issuer_key_id)

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
        len(sct.extension_bytes),           # extensions (opaque CtExtensions<0..2^16-1>)
    )
    # fmt: on

    return data


def _is_preissuer(issuer: Certificate) -> bool:
    try:
        ext_key_usage = issuer.extensions.get_extension_for_class(ExtendedKeyUsage)
    # If we do not have any EKU, we certainly do not have CT Ext
    except ExtensionNotFound:
        return False

    return ExtendedKeyUsageOID.CERTIFICATE_TRANSPARENCY in ext_key_usage.value


def _get_issuer_cert(chain: List[Certificate]) -> Certificate:
    issuer = chain[0]
    if _is_preissuer(issuer):
        issuer = chain[1]
    return issuer


class UnexpectedSctCountException(Exception):
    """
    Number of percerts scts is wrong
    """

    pass


def _get_precertificate_signed_certificate_timestamps(
    certificate: Certificate,
) -> PrecertificateSignedCertificateTimestamps:
    # Try to retrieve the embedded SCTs within the cert.
    try:
        precert_scts_extension = certificate.extensions.get_extension_for_class(
            PrecertificateSignedCertificateTimestamps
        ).value
    except ExtensionNotFound:
        raise ValueError(
            "No PrecertificateSignedCertificateTimestamps found for the certificate"
        )

    if len(precert_scts_extension) != 1:
        raise UnexpectedSctCountException(
            f"Unexpected embedded SCT count in response: {len(precert_scts_extension)} != 1"
        )
    return precert_scts_extension


def _cert_is_ca(cert: Certificate) -> bool:
    _logger.debug(f"Found {cert.subject} as issuer, verifying if it is a ca")
    try:
        cert_is_ca(cert)
    except VerificationError as e:
        _logger.debug(f"Invalid {cert.subject}: failed to validate as a CA: {e}")
        return False
    return True


def verify_sct(
    sct: SignedCertificateTimestamp,
    cert: Certificate,
    chain: List[Certificate],
    ct_keyring: CTKeyring,
) -> None:
    """
    Verify a signed certificate timestamp.

    An SCT is verified by reconstructing its "digitally-signed" payload
    and verifying that the signature provided in the SCT is valid against
    one of the keys present in the CT keyring (i.e., the keys used by the CT
    log to sign SCTs).
    """

    issuer_key_id = None
    if sct.entry_type == LogEntryType.PRE_CERTIFICATE:
        # If we're verifying an SCT for a precertificate, we need to
        # find its issuer in the chain and calculate a hash over
        # its public key information, as part of the "binding" proof
        # that ties the issuer to the final certificate.
        issuer_cert = _get_issuer_cert(chain)
        issuer_pubkey = issuer_cert.public_key()

        if not _cert_is_ca(issuer_cert):
            raise VerificationError(
                f"SCT verify: Invalid issuer pubkey basicConstraint (not a CA): {issuer_pubkey}"
            )

        if not isinstance(issuer_pubkey, (rsa.RSAPublicKey, ec.EllipticCurvePublicKey)):
            raise VerificationError(
                f"SCT verify: invalid issuer pubkey format (not ECDSA or RSA): {issuer_pubkey}"
            )

        issuer_key_id = key_id(issuer_pubkey)

    digitally_signed = _pack_digitally_signed(sct, cert, issuer_key_id)

    if not isinstance(sct.signature_hash_algorithm, hashes.SHA256):
        raise VerificationError(
            "Found unexpected hash algorithm in SCT: only SHA256 is supported "
            f"(expected {hashes.SHA256}, got {sct.signature_hash_algorithm})"
        )

    try:
        _logger.debug(f"attempting to verify SCT with key ID {sct.log_id.hex()}")
        # NOTE(ww): In terms of the DER structure, the SCT's `LogID` contains a
        # singular `opaque key_id[32]`. Cryptography's APIs don't bother
        # to expose this trivial single member, so we use the `log_id`
        # attribute directly.
        ct_keyring.verify(
            key_id=KeyID(sct.log_id), signature=sct.signature, data=digitally_signed
        )
    except VerificationError as exc:
        raise VerificationError(f"SCT verify failed: {exc}")
