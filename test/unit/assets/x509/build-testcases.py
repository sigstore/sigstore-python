#!/usr/bin/env python

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
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID


def _keypair():
    priv = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    return priv.public_key(), priv


_ROOT_PUBKEY, _ROOT_PRIVKEY = _keypair()

_A_VERY_LONG_TIME = datetime.timedelta(days=365 * 1000)

_HERE = Path(__file__).resolve().parent


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
    builder = builder.not_valid_before(datetime.datetime.today())
    builder = builder.not_valid_after(datetime.datetime.today() + _A_VERY_LONG_TIME)
    builder = builder.serial_number(x509.random_serial_number())
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


def bogus_leaf() -> x509.Certificate:
    """
    A valid leaf certificate, for Sigstore purposes.
    """

    pubkey, _ = _keypair()
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

    return _finalize(builder, pubkey=pubkey)


def bogus_leaf_invalid_ku() -> x509.Certificate:
    """
    An invalid leaf certificate (for Sigstore purposes), due to an invalid
    KeyUsage (lacking the digitalSignature entitlement).
    """

    pubkey, _ = _keypair()
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

    return _finalize(builder, pubkey=pubkey)


def bogus_leaf_invalid_eku() -> x509.Certificate:
    """
    An invalid leaf certificate (for Sigstore purposes), due to an
    invalid ExtendedKeyUsage (lacking the code signing entitlement).
    """

    pubkey, _ = _keypair()
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

    return _finalize(builder, pubkey=pubkey)


# Individual testcases; see each function's docstring.
_dump(bogus_root(), _HERE / "bogus-root.pem")
_dump(bogus_leaf(), _HERE / "bogus-leaf.pem")
_dump(bogus_leaf_invalid_ku(), _HERE / "bogus-leaf-invalid-ku.pem")
_dump(bogus_leaf_invalid_eku(), _HERE / "bogus-leaf-invalid-eku.pem")
