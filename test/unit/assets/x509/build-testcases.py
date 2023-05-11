#!/usr/bin/env python

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

# build-testcases.py: generate some bogus X.509 testcases for sigstore's
# unit tests.
#
# These testcases should already be checked-in; you can re-generate them
# (with entirely new key material) using:
#
#  python build-testcases.py
#
# ...while running from this directory.

import datetime
import os
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    load_pem_private_key,
)
from cryptography.x509.oid import NameOID


def _keypair(priv_key_file: Path):
    priv_key_bytes: bytes
    with priv_key_file.open("rb") as f:
        priv_key_bytes = f.read()
    priv_key = load_pem_private_key(priv_key_bytes, None)
    return priv_key.public_key(), priv_key


_HERE = Path(__file__).resolve().parent
_ROOT_PUBKEY, _ROOT_PRIVKEY = _keypair(_HERE / "root_privkey.pem")
_NONROOT_PUBKEY, _ = _keypair(_HERE / "nonroot_privkey.pem")

_NOT_VALID_BEFORE_DATE = datetime.datetime(2023, 1, 1)
_A_VERY_LONG_TIME = datetime.timedelta(days=365 * 1000)


def _builder() -> x509.CertificateBuilder:
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(
        x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, "sigstore-python-bogus-cert"),
            ]
        )
    )
    builder = builder.issuer_name(
        x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, "sigstore-python-bogus-cert"),
            ]
        )
    )
    builder = builder.not_valid_before(_NOT_VALID_BEFORE_DATE)
    builder = builder.not_valid_after(_NOT_VALID_BEFORE_DATE + _A_VERY_LONG_TIME)
    builder = builder.serial_number(666)
    builder = builder.add_extension(
        x509.SubjectAlternativeName([x509.DNSName("bogus.example.com")]), critical=False
    )
    return builder


def _finalize(
    builder: x509.CertificateBuilder, *, pubkey=_ROOT_PUBKEY, privkey=_ROOT_PRIVKEY
) -> x509.Certificate:
    builder = builder.public_key(pubkey)
    return builder.sign(private_key=privkey, algorithm=hashes.SHA256())


def _dump(cert: x509.Certificate, filename: Path):
    pem = cert.public_bytes(Encoding.PEM)
    if not filename.exists() or os.getenv("TESTCASE_OVERWRITE"):
        filename.write_bytes(pem)


def bogus_root() -> x509.Certificate:
    """
    A valid root CA certificate.
    """
    builder = _builder()
    builder = builder.add_extension(
        x509.BasicConstraints(ca=True, path_length=None),
        critical=True,
    )
    builder = builder.add_extension(
        x509.KeyUsage(
            digital_signature=True,
            key_cert_sign=True,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=False,
    )

    return _finalize(builder)


def bogus_root_noncritical_bc() -> x509.Certificate:
    """
    An invalid root CA certificate, due to the BasicConstraints
    extension being marked as non-critical.
    """
    builder = _builder()
    builder = builder.add_extension(
        x509.BasicConstraints(ca=True, path_length=None),
        critical=False,
    )
    builder = builder.add_extension(
        x509.KeyUsage(
            digital_signature=True,
            key_cert_sign=True,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=False,
    )

    return _finalize(builder)


def bogus_root_missing_ku() -> x509.Certificate:
    """
    An invalid root CA certificate, due to a missing
    KeyUsage extension.
    """
    builder = _builder()
    builder = builder.add_extension(
        x509.BasicConstraints(ca=True, path_length=None),
        critical=True,
    )

    return _finalize(builder)


def bogus_root_invalid_ku() -> x509.Certificate:
    """
    An invalid root CA certificate, due to inconsistent
    KeyUsage state (KU.keyCertSign <> BC.ca)
    """
    builder = _builder()
    builder = builder.add_extension(
        x509.BasicConstraints(ca=True, path_length=None),
        critical=True,
    )
    builder = builder.add_extension(
        x509.KeyUsage(
            digital_signature=True,
            key_cert_sign=False,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=False,
    )

    return _finalize(builder)


def bogus_intermediate() -> x509.Certificate:
    """
    A valid intermediate CA certificate, for Sigstore purposes.
    """

    builder = _builder()
    builder = builder.add_extension(
        x509.BasicConstraints(ca=True, path_length=1),
        critical=True,
    )
    builder = builder.add_extension(
        x509.KeyUsage(
            digital_signature=True,
            key_cert_sign=True,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=False,
    )

    return _finalize(builder, pubkey=_NONROOT_PUBKEY)


def bogus_intermediate_with_eku() -> x509.Certificate:
    """
    A valid intermediate CA certificate, for Sigstore purposes.

    This is like `bogus_intermediate`, except that it also contains a
    code signing EKU entitlement to make sure we don't treat
    that as an incorrect signal.
    """

    builder = _builder()
    builder = builder.add_extension(
        x509.BasicConstraints(ca=True, path_length=1),
        critical=True,
    )
    builder = builder.add_extension(
        x509.KeyUsage(
            digital_signature=True,
            key_cert_sign=True,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=False,
    )
    builder = builder.add_extension(
        x509.ExtendedKeyUsage(usages=[x509.OID_CODE_SIGNING]),
        critical=False,
    )

    return _finalize(builder, pubkey=_NONROOT_PUBKEY)


def bogus_leaf() -> x509.Certificate:
    """
    A valid leaf certificate, for Sigstore purposes.
    """

    builder = _builder()
    builder = builder.add_extension(
        x509.BasicConstraints(ca=False, path_length=None),
        critical=True,
    )
    builder = builder.add_extension(
        x509.KeyUsage(
            digital_signature=True,
            key_cert_sign=False,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=False,
    )
    builder = builder.add_extension(
        x509.ExtendedKeyUsage(usages=[x509.OID_CODE_SIGNING]),
        critical=False,
    )

    return _finalize(builder, pubkey=_NONROOT_PUBKEY)


def bogus_leaf_invalid_ku() -> x509.Certificate:
    """
    An invalid leaf certificate (for Sigstore purposes), due to an invalid
    KeyUsage (lacking the digitalSignature entitlement).
    """

    builder = _builder()
    builder = builder.add_extension(
        x509.BasicConstraints(ca=False, path_length=None),
        critical=True,
    )
    builder = builder.add_extension(
        x509.KeyUsage(
            digital_signature=False,
            key_cert_sign=False,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=False,
    )
    builder = builder.add_extension(
        x509.ExtendedKeyUsage(usages=[x509.OID_CODE_SIGNING]),
        critical=False,
    )

    return _finalize(builder, pubkey=_NONROOT_PUBKEY)


def bogus_leaf_invalid_eku() -> x509.Certificate:
    """
    An invalid leaf certificate (for Sigstore purposes), due to an
    invalid ExtendedKeyUsage (lacking the code signing entitlement).
    """

    builder = _builder()
    builder = builder.add_extension(
        x509.BasicConstraints(ca=False, path_length=None),
        critical=True,
    )
    builder = builder.add_extension(
        x509.KeyUsage(
            digital_signature=True,
            key_cert_sign=False,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=False,
    )
    builder = builder.add_extension(
        x509.ExtendedKeyUsage(usages=[x509.OID_SERVER_AUTH]),
        critical=False,
    )

    return _finalize(builder, pubkey=_NONROOT_PUBKEY)


def bogus_leaf_missing_eku() -> x509.Certificate:
    """
    An invalid leaf certificate (for Sigstore purposes), due to a
    missing ExtendedKeyUsage extension.
    """

    builder = _builder()
    builder = builder.add_extension(
        x509.BasicConstraints(ca=False, path_length=None),
        critical=True,
    )
    builder = builder.add_extension(
        x509.KeyUsage(
            digital_signature=True,
            key_cert_sign=False,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=False,
    )

    return _finalize(builder, pubkey=_NONROOT_PUBKEY)


# Individual testcases; see each function's docstring.
_dump(bogus_root(), _HERE / "bogus-root.pem")
_dump(bogus_root_noncritical_bc(), _HERE / "bogus-root-noncritical-bc.pem")
_dump(bogus_root_missing_ku(), _HERE / "bogus-root-missing-ku.pem")
_dump(bogus_root_invalid_ku(), _HERE / "bogus-root-invalid-ku.pem")
_dump(bogus_intermediate(), _HERE / "bogus-intermediate.pem")
_dump(bogus_intermediate_with_eku(), _HERE / "bogus-intermediate-with-eku.pem")
_dump(bogus_leaf(), _HERE / "bogus-leaf.pem")
_dump(bogus_leaf_invalid_ku(), _HERE / "bogus-leaf-invalid-ku.pem")
_dump(bogus_leaf_invalid_eku(), _HERE / "bogus-leaf-invalid-eku.pem")
_dump(bogus_leaf_missing_eku(), _HERE / "bogus-leaf-missing-eku.pem")
