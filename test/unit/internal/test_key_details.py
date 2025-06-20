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
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, padding, rsa
from sigstore_protobuf_specs.dev.sigstore.common import v1

from sigstore._internal.key_details import _get_key_details


@pytest.mark.parametrize(
    "mock_certificate",
    [
        # ec
        pytest.param(
            Mock(
                public_key=Mock(
                    return_value=ec.generate_private_key(ec.SECP192R1()).public_key()
                )
            ),
            marks=[pytest.mark.xfail(strict=True)],
        ),
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
        pytest.param(
            Mock(
                public_key=Mock(
                    return_value=rsa.generate_private_key(
                        public_exponent=65537, key_size=2048
                    ).public_key()
                ),
                signature_algorithm_parameters=padding.PKCS1v15(),
            ),
            marks=[pytest.mark.xfail(strict=True)],
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
        # rsa pss
        pytest.param(
            Mock(
                public_key=Mock(
                    return_value=rsa.generate_private_key(
                        public_exponent=65537, key_size=2048
                    ).public_key()
                ),
                signature_algorithm_parameters=padding.PSS(None, 0),
            ),
            marks=[pytest.mark.xfail(strict=True)],
        ),
        Mock(
            public_key=Mock(
                return_value=rsa.generate_private_key(
                    public_exponent=65537, key_size=3072
                ).public_key()
            ),
            signature_algorithm_parameters=padding.PSS(None, 0),
        ),
        Mock(
            public_key=Mock(
                return_value=rsa.generate_private_key(
                    public_exponent=65537, key_size=4096
                ).public_key()
            ),
            signature_algorithm_parameters=padding.PSS(None, 0),
        ),
        # ed25519
        Mock(
            public_key=Mock(
                return_value=ed25519.Ed25519PrivateKey.generate().public_key(),
                signature_algorithm_parameters=None,
            )
        ),
        # unsupported
        pytest.param(
            Mock(
                public_key=Mock(
                    return_value=dsa.generate_private_key(key_size=1024).public_key()
                ),
                signature_algorithm_parameters=None,
            ),
            marks=[pytest.mark.xfail(strict=True)],
        ),
    ],
)
def test_get_key_details(mock_certificate):
    """
    Ensures that we return a PublicKeyDetails for supported key types and schemes.
    """
    key_details = _get_key_details(mock_certificate)
    assert isinstance(key_details, v1.PublicKeyDetails)
