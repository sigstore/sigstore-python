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
Functionality for interacting with a generic keyring.
"""

from __future__ import annotations

from typing import List

import cryptography.hazmat.primitives.asymmetric.padding as padding
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from sigstore._utils import (
    InvalidKeyError,
    KeyID,
    UnexpectedKeyFormatError,
    key_id,
    load_der_public_key,
    load_pem_public_key,
)


class KeyringError(Exception):
    """
    Raised on failure by `Keyring.verify()`.
    """

    pass


class KeyringLookupError(KeyringError):
    """
    A specialization of `KeyringError`, indicating that the specified
    key ID wasn't found in the keyring.
    """

    pass


class KeyringSignatureError(KeyringError):
    """
    Raised when `Keyring.verify()` is passed an invalid signature.
    """


class Keyring:
    """
    Represents a set of CT signing keys, each of which is a potentially
    valid signer for a Signed Certificate Timestamp (SCT).

    This structure exists to facilitate key rotation in a CT log.
    """

    def __init__(self, keys: List[bytes] = []):
        """
        Create a new `Keyring`, with `keys` as the initial set of signing
        keys. These `keys` can be in either DER format or PEM encoded.
        """
        self._keyring = {}
        for key_bytes in keys:
            key = None

            try:
                key = load_pem_public_key(key_bytes)
            except UnexpectedKeyFormatError as e:
                raise e
            except InvalidKeyError:
                key = load_der_public_key(key_bytes)

            self._keyring[key_id(key)] = key

    def add(self, key_pem: bytes) -> None:
        """
        Adds a PEM-encoded key to the current keyring.
        """
        key = load_pem_public_key(key_pem)
        self._keyring[key_id(key)] = key

    def verify(self, *, key_id: KeyID, signature: bytes, data: bytes) -> None:
        """
        Verify that `signature` is a valid signature for `data`, using the
        key identified by `key_id`.

        Raises if `key_id` does not match a key in the `Keyring`, or if
        the signature is invalid.
        """
        key = self._keyring.get(key_id)
        if key is None:
            # If we don't have a key corresponding to this key ID, we can't
            # possibly verify the signature.
            raise KeyringLookupError(f"no known key for key ID {key_id.hex()}")

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
                raise KeyringError(f"unsupported key type: {key}")
        except InvalidSignature as exc:
            raise KeyringSignatureError("invalid signature") from exc
