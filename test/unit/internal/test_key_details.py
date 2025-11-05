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

from unittest.mock import Mock

import pytest
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
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
        # rsa pkcs1
        Mock(
            public_key=Mock(
                return_value=rsa.generate_private_key(
                    public_exponent=65537, key_size=2048
                ).public_key()
            ),
            signature_algorithm_parameters=padding.PKCS1v15(),
        ),
        Mock(
            public_key=Mock(
                return_value=rsa.generate_private_key(
                    public_exponent=65537, key_size=3072
                ).public_key()
            ),
            signature_algorithm_parameters=padding.PKCS1v15(),
        ),
        Mock(
            public_key=Mock(
                return_value=rsa.generate_private_key(
                    public_exponent=65537, key_size=4096
                ).public_key()
            ),
            signature_algorithm_parameters=padding.PKCS1v15(),
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
