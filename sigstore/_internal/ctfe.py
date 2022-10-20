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
Functionality for interacting with CT ("CTFE") signing keys.
"""

from __future__ import annotations

import fnmatch
from importlib import resources
from typing import List

import cryptography.hazmat.primitives.asymmetric.padding as padding
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from sigstore._utils import PublicKey, key_id, load_pem_public_key


class CTKeyringError(Exception):
    pass


class CTKeyring:
    """
    Represents a set of CT signing keys, each of which is a potentially
    valid signer for a Signed Certificate Timestamp (SCT).

    This structure exists to facilitate key rotation in a CT log.
    """

    def __init__(self, keys: List[PublicKey]):
        self._keyring = {}
        for key in keys:
            self._keyring[key_id(key)] = key

    @classmethod
    def staging(cls) -> CTKeyring:
        keys = []
        for resource in resources.contents("sigstore._store"):
            # All CTFE pubkeys for the staging instance share the `.staging.pub` suffix.
            if not fnmatch.fnmatch(resource, "ctfe*.staging.pub"):
                continue

            key_pem = resources.read_binary("sigstore._store", resource)
            key = load_pem_public_key(key_pem)
            keys.append(key)

        return cls(keys)

    @classmethod
    def production(cls) -> CTKeyring:
        keys = []
        for resource in resources.contents("sigstore._store"):
            # We only load resources that look like CTFE pubkeys that are *not*
            # staging instance pubkeys.
            if not fnmatch.fnmatch(resource, "ctfe*.pub") or fnmatch.fnmatch(
                resource, "ctfe*.staging.pub"
            ):
                continue

            key_pem = resources.read_binary("sigstore._store", resource)
            key = load_pem_public_key(key_pem)
            keys.append(key)

        return cls(keys)

    def verify(self, *, key_id: bytes, signature: bytes, data: bytes) -> None:
        key = self._keyring.get(key_id)
        if key is None:
            # If we don't have a key corresponding to this key ID, we can't
            # possibly verify the signature.
            raise CTKeyringError(f"no known key for key ID {key_id.hex()}")

        try:
            if isinstance(key, rsa.RSAPublicKey):
                key.verify(
                    signature=signature,
                    data=data,
                    padding=padding.PKCS1v15(),
                    algorithm=hashes.SHA256(),
                )
            elif isinstance(key, ec.EllipticCurvePublicKey):
                key.verify(
                    signature=signature,
                    data=data,
                    signature_algorithm=ec.ECDSA(hashes.SHA256()),
                )
            else:
                # Unreachable.
                raise CTKeyringError("unreachable")
        except InvalidSignature as exc:
            raise CTKeyringError("invalid signature") from exc
