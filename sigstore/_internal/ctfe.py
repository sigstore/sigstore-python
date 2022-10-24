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

from importlib import resources
from typing import List

import cryptography.hazmat.primitives.asymmetric.padding as padding
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from sigstore._utils import PublicKey, key_id, load_pem_public_key


class CTKeyringError(Exception):
    """
    Raised on failure by `CTKeyring.verify()`.
    """

    pass


class CTKeyringLookupError(CTKeyringError):
    """
    A specialization of `CTKeyringError`, indicating that the specified
    key ID wasn't found in the keyring.
    """

    pass


class CTKeyring:
    """
    Represents a set of CT signing keys, each of which is a potentially
    valid signer for a Signed Certificate Timestamp (SCT).

    This structure exists to facilitate key rotation in a CT log.
    """

    def __init__(self, keys: List[PublicKey] = []):
        self._keyring = {}
        for key in keys:
            self._keyring[key_id(key)] = key

    @classmethod
    def staging(cls) -> CTKeyring:
        """
        Returns a `CTKeyring` instance capable of verifying SCTs from
        Sigstore's staging deployment.
        """
        keyring = cls()
        keyring._add_resource("ctfe.staging.pub")
        keyring._add_resource("ctfe_2022.staging.pub")
        keyring._add_resource("ctfe_2022.2.staging.pub")

        return keyring

    @classmethod
    def production(cls) -> CTKeyring:
        """
        Returns a `CTKeyring` instance capable of verifying SCTs from
        Sigstore's production deployment.
        """
        keyring = cls()
        keyring._add_resource("ctfe.pub")
        keyring._add_resource("ctfe_2022.pub")

        return keyring

    def _add_resource(self, name: str) -> None:
        """
        Adds a key to the current keyring, as identified by its
        resource name under `sigstore._store`.
        """
        key_pem = resources.read_binary("sigstore._store", name)
        self.add(key_pem)

    def add(self, key_pem: bytes) -> None:
        """
        Adds a PEM-encoded key to the current keyring.
        """
        key = load_pem_public_key(key_pem)
        self._keyring[key_id(key)] = key

    def verify(self, *, key_id: bytes, signature: bytes, data: bytes) -> None:
        key = self._keyring.get(key_id)
        if key is None:
            # If we don't have a key corresponding to this key ID, we can't
            # possibly verify the signature.
            raise CTKeyringLookupError(f"no known key for key ID {key_id.hex()}")

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
                # NOTE(ww): Unreachable without API misuse.
                raise CTKeyringError(f"unsupported key type: {key}")
        except InvalidSignature as exc:
            raise CTKeyringError("invalid signature") from exc
