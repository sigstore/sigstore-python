# Copyright 2025 The Sigstore Authors
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

from datetime import datetime, timezone
from unittest.mock import Mock

import pytest
from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, padding, rsa
from sigstore_models.common.v1 import PublicKeyDetails

from sigstore._internal.key_details import _get_key_details


# The algorithms tested below are from https://github.com/sigstore/fulcio/blob/4a86d8bf45972b58051ba44d91cd96664cf74711/cmd/app/serve.go#L125-L133
@pytest.mark.parametrize(
    "mock_certificate",
    [
        # ec
        Mock(
            public_key=Mock(
                return_value=ec.generate_private_key(ec.SECP256R1()).public_key()
            )
        ),
        Mock(
            public_key=Mock(
                return_value=ec.generate_private_key(ec.SECP384R1()).public_key()
            )
        ),
        Mock(
            public_key=Mock(
                return_value=ec.generate_private_key(ec.SECP521R1()).public_key()
            )
        ),
        # ed25519
        Mock(
            public_key=Mock(
                return_value=ed25519.Ed25519PrivateKey.generate().public_key(),
                signature_algorithm_parameters=None,
            )
        ),
    ],
)
def test_get_key_details(mock_certificate):
    """
    Ensures that we return a PublicKeyDetails for supported key types and schemes.
    """
    key_details = _get_key_details(mock_certificate)
    assert isinstance(key_details, PublicKeyDetails)


@pytest.fixture(
    scope="module",
    params=[
        (2048, PublicKeyDetails.PKIX_RSA_PKCS1V15_2048_SHA256),
        (3072, PublicKeyDetails.PKIX_RSA_PKCS1V15_3072_SHA256),
        (4096, PublicKeyDetails.PKIX_RSA_PKCS1V15_4096_SHA256),
    ],
    ids=["rsa2048", "rsa3072", "rsa4096"],
)
def rsa_subject_key(request):
    key_size, key_details = request.param
    return rsa.generate_private_key(
        public_exponent=65537, key_size=key_size
    ), key_details


@pytest.mark.parametrize("issuer_algorithm", ["ecdsa", "rsa-pkcs1", "rsa-pss"])
def test_rsa_key_details_independent_of_issuer_signature(
    rsa_subject_key, issuer_algorithm
):
    """The issuer's certificate signature does not select the artifact algorithm."""
    subject_key, expected_details = rsa_subject_key
    if issuer_algorithm == "ecdsa":
        issuer_key = ec.generate_private_key(ec.SECP256R1())
        issuer_padding = None
        expected_parameters = ec.ECDSA
    else:
        issuer_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        if issuer_algorithm == "rsa-pkcs1":
            issuer_padding = padding.PKCS1v15()
            expected_parameters = padding.PKCS1v15
        else:
            issuer_padding = padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=hashes.SHA256.digest_size,
            )
            expected_parameters = padding.PSS

    issuer_name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "issuer")])
    subject_name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "signer")])
    builder = (
        x509.CertificateBuilder()
        .issuer_name(issuer_name)
        .not_valid_before(datetime(2025, 1, 1, tzinfo=timezone.utc))
        .not_valid_after(datetime(2030, 1, 1, tzinfo=timezone.utc))
    )
    issuer = (
        builder.subject_name(issuer_name)
        .public_key(issuer_key.public_key())
        .serial_number(1)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(issuer_key, hashes.SHA256(), rsa_padding=issuer_padding)
    )
    certificate = (
        builder.subject_name(subject_name)
        .public_key(subject_key.public_key())
        .serial_number(2)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(issuer_key, hashes.SHA256(), rsa_padding=issuer_padding)
    )
    certificate.verify_directly_issued_by(issuer)
    assert isinstance(certificate.signature_algorithm_parameters, expected_parameters)
    assert _get_key_details(certificate) == expected_details


def delayed_crypto_mock(mock_func, error_msg):
    # execute mock_func, mark test as skipped if cryptography does not support this algo.
    # This is done so missing support does not break the negative test collection
    try:
        data = mock_func()
        return pytest.param(data, error_msg)
    except UnsupportedAlgorithm as e:
        return pytest.param(
            None,
            error_msg,
            marks=pytest.mark.skip(reason=f"missing cryptography support: {e}"),
        )


class DummyCurve(ec.EllipticCurve):
    name = "dummycurve"

    @property
    def key_size(self):
        return 69420

    @property
    def group_order(self):
        return 69420


@pytest.mark.parametrize(
    "mock_certificate, error_msg",
    [
        # Unsupported EC curve
        delayed_crypto_mock(
            lambda: Mock(
                public_key=Mock(
                    return_value=ec.generate_private_key(DummyCurve()).public_key()
                )
            ),
            "Unsupported EC curve: dummycurve",
        ),
        # Unsupported RSA key size
        delayed_crypto_mock(
            lambda: Mock(
                public_key=Mock(
                    return_value=rsa.generate_private_key(
                        public_exponent=65537, key_size=1024
                    ).public_key()
                ),
                signature_algorithm_parameters=padding.PKCS1v15(),
            ),
            "Unsupported RSA key size: 1024",
        ),
        # Unsupported key type
        delayed_crypto_mock(
            lambda: Mock(
                public_key=Mock(
                    return_value=dsa.generate_private_key(key_size=1024).public_key()
                )
            ),
            "Unsupported public key type",
        ),
    ],
)
def test_get_key_details_unsupported(mock_certificate, error_msg):
    """
    Ensures that we raise a ValueError for unsupported key types and schemes.
    """
    with pytest.raises(ValueError, match=error_msg):
        _get_key_details(mock_certificate)
