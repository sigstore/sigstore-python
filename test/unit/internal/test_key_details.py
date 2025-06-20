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

import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from sigstore_protobuf_specs.dev.sigstore.common import v1

from sigstore._internal.key_details import _get_key_details


@pytest.mark.parametrize(
    "public_key",
    [
        ec.generate_private_key(ec.SECP256R1()).public_key(),
        ec.generate_private_key(ec.SECP384R1()).public_key(),
        ec.generate_private_key(ec.SECP521R1()).public_key(),
        pytest.param(
            ec.generate_private_key(ec.SECP192R1()).public_key(),
            marks=[pytest.mark.xfail(strict=True)],
        ),
    ],
)
def test_get_key_details(public_key):
    """
    Ensures that we return a PublicKeyDetails for supported key types.
    """
    key_details = _get_key_details(public_key)
    print(key_details)
    assert isinstance(key_details, v1.PublicKeyDetails)
