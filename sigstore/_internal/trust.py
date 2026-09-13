# Copyright 2023 The Sigstore Authors
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
Client trust configuration and trust root management for sigstore-python.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import ClassVar, NewType

import cryptography.hazmat.primitives.asymmetric.padding as padding
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.x509 import (
    Certificate,
    load_der_x509_certificate,
)
from sigstore_models.common import v1 as common_v1
from sigstore_models.trustroot import v1 as trustroot_v1

from sigstore._utils import (
    KeyID,
    PublicKey,
    is_timerange_valid,
    key_id,
    load_der_public_key,
)
from sigstore.errors import Error, VerificationError

# Versions supported by this client
REKOR_VERSIONS = [1, 2]
TSA_VERSIONS = [1]
FULCIO_VERSIONS = [1]
OIDC_VERSIONS = [1]

_logger = logging.getLogger(__name__)


@dataclass(init=False)
class Key:
    """
    Represents a key in a `Keyring`.
    """

    hash_algorithm: hashes.HashAlgorithm | None
    key: PublicKey
    key_id: KeyID

    _RSA_SHA_256_DETAILS: ClassVar = {
        common_v1.PublicKeyDetails.PKCS1_RSA_PKCS1V5,
        common_v1.PublicKeyDetails.PKIX_RSA_PKCS1V15_2048_SHA256,
        common_v1.PublicKeyDetails.PKIX_RSA_PKCS1V15_3072_SHA256,
        common_v1.PublicKeyDetails.PKIX_RSA_PKCS1V15_4096_SHA256,
    }

    _EC_DETAILS_TO_HASH: ClassVar = {
        common_v1.PublicKeyDetails.PKIX_ECDSA_P256_SHA_256: hashes.SHA256(),
        common_v1.PublicKeyDetails.PKIX_ECDSA_P384_SHA_384: hashes.SHA384(),
        common_v1.PublicKeyDetails.PKIX_ECDSA_P521_SHA_512: hashes.SHA512(),
    }

    def __init__(self, public_key: common_v1.PublicKey) -> None:
        """
        Construct a key from the given Sigstore PublicKey message.
        """

        # NOTE: `raw_bytes` is marked as `optional` in the `PublicKey` message,
        # for unclear reasons.
        if not public_key.raw_bytes:
            raise VerificationError("public key is empty")

        hash_algorithm: hashes.HashAlgorithm | None
        if public_key.key_details in self._RSA_SHA_256_DETAILS:
            hash_algorithm = hashes.SHA256()
            key = load_der_public_key(public_key.raw_bytes, types=(rsa.RSAPublicKey,))
        elif public_key.key_details in self._EC_DETAILS_TO_HASH:
            hash_algorithm = self._EC_DETAILS_TO_HASH[public_key.key_details]
            key = load_der_public_key(
                public_key.raw_bytes, types=(ec.EllipticCurvePublicKey,)
            )
        elif public_key.key_details == common_v1.PublicKeyDetails.PKIX_ED25519:
            hash_algorithm = None
            key = load_der_public_key(
                public_key.raw_bytes, types=(ed25519.Ed25519PublicKey,)
            )
        else:
            raise VerificationError(f"unsupported key type: {public_key.key_details}")

        self.hash_algorithm = hash_algorithm
        self.key = key
        self.key_id = key_id(key)

    def verify(self, signature: bytes, data: bytes) -> None:
        """
        Verifies the given `data` against `signature` using the current key.
        """
        if isinstance(self.key, rsa.RSAPublicKey) and self.hash_algorithm is not None:
            self.key.verify(
                signature=signature,
                data=data,
                # TODO: Parametrize this as well, for PSS.
                padding=padding.PKCS1v15(),
                algorithm=self.hash_algorithm,
            )
        elif (
            isinstance(self.key, ec.EllipticCurvePublicKey)
            and self.hash_algorithm is not None
        ):
            self.key.verify(
                signature=signature,
                data=data,
                signature_algorithm=ec.ECDSA(self.hash_algorithm),
            )
        elif (
            isinstance(self.key, ed25519.Ed25519PublicKey)
            and self.hash_algorithm is None
        ):
            self.key.verify(
                signature=signature,
                data=data,
            )
        else:
            # Unreachable without API misuse.
            raise VerificationError(f"keyring: unsupported key: {self.key}")


class Keyring:
    """
    Represents a set of keys, each of which is a potentially valid verifier.
    """

    def __init__(self, public_keys: list[common_v1.PublicKey] = []):
        """
        Create a new `Keyring`, with `keys` as the initial set of verifying keys.
        """
        self._keyring: dict[KeyID, Key] = {}

        for public_key in public_keys:
            try:
                key = Key(public_key)
                self._keyring[key.key_id] = key
            except VerificationError as e:
                _logger.warning(f"Failed to load a trusted root key: {e}")

    def verify(self, *, key_id: KeyID, signature: bytes, data: bytes) -> None:
        """
        Verify that `signature` is a valid signature for `data`, using the
        key identified by `key_id`.

        `key_id` is an unauthenticated hint; if no key matches the given key ID,
        all keys in the keyring are tried.

        Raises if the signature is invalid, i.e. is not valid for any of the
        keys in the keyring.
        """

        key = self._keyring.get(key_id)
        candidates = [key] if key is not None else list(self._keyring.values())

        # Try to verify each candidate key. In the happy case, this will
        # be exactly one candidate.
        valid = False
        for candidate in candidates:
            try:
                candidate.verify(signature, data)
                valid = True
                break
            except InvalidSignature:
                pass

        if not valid:
            raise VerificationError("keyring: invalid signature")


class RekorKeyring(Keyring):
    """
    Rekor keys, including the trusted identities used by checkpoint signatures.

    Legacy roots retain log-ID hint lookup. For v0.2 roots, checkpoint signatures
    select keys by the exact trusted name and checkpoint ID, not by a bundle's
    log-ID hint. SET verification continues to use the ordinary keyring.
    """

    def __init__(
        self,
        logs: list[trustroot_v1.TransparencyLogInstance],
        *,
        legacy: bool,
    ) -> None:
        """Construct a keyring from log instances already filtered for validity."""
        super().__init__()
        self._legacy = legacy
        self._checkpoint_keys: dict[tuple[str, bytes], list[Key]] = {}
        for log in logs:
            try:
                key = Key(log.public_key)
            except VerificationError as exc:
                _logger.warning(f"Failed to load a trusted root key: {exc}")
                continue
            self._keyring[key.key_id] = key
            if legacy:
                continue

            # The protobuf requires log_id as the fallback only when the new
            # field is absent. A present but malformed value must not downgrade.
            checkpoint_id = (
                log.checkpoint_key_id.key_id
                if log.checkpoint_key_id is not None
                else log.log_id.key_id
            )
            if len(checkpoint_id) < 4:
                raise VerificationError(
                    "checkpoint key ID must contain at least 4 bytes"
                )
            if not log.base_url or any(
                char.isspace() or char == "+" for char in log.base_url
            ):
                raise VerificationError("invalid checkpoint key name in trusted root")

            # IDs are four-byte hints, not collision-resistant authenticators.
            # Keep every candidate; never let the last colliding key win.
            identity = (log.base_url, checkpoint_id[:4])
            self._checkpoint_keys.setdefault(identity, []).append(key)

    def verify_checkpoint_signature(
        self,
        *,
        name: str,
        signature_hash: bytes,
        signature: bytes,
        data: bytes,
        log_id: KeyID,
    ) -> bool:
        """
        Verify a known checkpoint signature; return False for an unknown signer.

        A known signer with an invalid signature raises VerificationError.
        No key from outside the matched trusted identity is tried for v0.2.
        """
        if self._legacy:
            if signature_hash != log_id[:4]:
                return False
            try:
                self.verify(key_id=log_id, signature=signature, data=data)
            except VerificationError as exc:
                raise VerificationError(
                    f"checkpoint: invalid signature: {exc}"
                ) from exc
            return True

        candidates = self._checkpoint_keys.get((name, signature_hash), [])
        if not candidates:
            return False
        for key in candidates:
            try:
                key.verify(signature, data)
                return True
            except InvalidSignature:
                pass
        raise VerificationError("checkpoint: invalid signature")


CTKeyring = NewType("CTKeyring", Keyring)


class KeyringPurpose(str, Enum):
    """
    Keyring purpose typing
    """

    SIGN = "sign"
    VERIFY = "verify"

    def __str__(self) -> str:
        """Returns the purpose string value."""
        return self.value


class CertificateAuthority:
    """
    Certificate Authority used in a Trusted Root configuration.
    """

    def __init__(self, inner: trustroot_v1.CertificateAuthority):
        """
        Construct a new `CertificateAuthority`.

        @api private
        """
        self._inner = inner
        self._certificates: list[Certificate] = []
        self._verify()

    @classmethod
    def from_json(cls, path: str) -> CertificateAuthority:
        """
        Create a CertificateAuthority directly from JSON.
        """
        inner = trustroot_v1.CertificateAuthority.from_json(Path(path).read_bytes())
        return cls(inner)

    def _verify(self) -> None:
        """
        Verify and load the certificate authority.
        """
        self._certificates = [
            load_der_x509_certificate(cert.raw_bytes)
            for cert in self._inner.cert_chain.certificates
        ]

        if not self._certificates:
            raise Error("missing a certificate in Certificate Authority")

    @property
    def validity_period_start(self) -> datetime:
        """
        Validity period start.
        """
        return self._inner.valid_for.start

    @property
    def validity_period_end(self) -> datetime | None:
        """
        Validity period end.
        """
        return self._inner.valid_for.end

    def certificates(self, *, allow_expired: bool) -> list[Certificate]:
        """
        Return a list of certificates in the authority chain.

        The certificates are returned in order from leaf to root, with any
        intermediate certificates in between.
        """
        if not is_timerange_valid(self._inner.valid_for, allow_expired=allow_expired):
            return []
        return self._certificates
