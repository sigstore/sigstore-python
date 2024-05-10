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
Trust root management for sigstore-python.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import ClassVar, Iterable, List, NewType

import cryptography.hazmat.primitives.asymmetric.padding as padding
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509 import (
    Certificate,
    load_der_x509_certificate,
)
from sigstore_protobuf_specs.dev.sigstore.common.v1 import PublicKey as _PublicKey
from sigstore_protobuf_specs.dev.sigstore.common.v1 import (
    PublicKeyDetails as _PublicKeyDetails,
)
from sigstore_protobuf_specs.dev.sigstore.common.v1 import TimeRange
from sigstore_protobuf_specs.dev.sigstore.trustroot.v1 import (
    CertificateAuthority,
    TransparencyLogInstance,
)
from sigstore_protobuf_specs.dev.sigstore.trustroot.v1 import (
    TrustedRoot as _TrustedRoot,
)

from sigstore._internal.tuf import DEFAULT_TUF_URL, STAGING_TUF_URL, TrustUpdater
from sigstore._utils import (
    KeyID,
    PublicKey,
    key_id,
    load_der_public_key,
)
from sigstore.errors import MetadataError, VerificationError


def _is_timerange_valid(period: TimeRange | None, *, allow_expired: bool) -> bool:
    """
    Given a `period`, checks that the the current time is not before `start`. If
    `allow_expired` is `False`, also checks that the current time is not after
    `end`.
    """
    now = datetime.now(timezone.utc)

    # If there was no validity period specified, the key is always valid.
    if not period:
        return True

    # Active: if the current time is before the starting period, we are not yet
    # valid.
    if now < period.start:
        return False

    # If we want Expired keys, the key is valid at this point. Otherwise, check
    # that we are within range.
    return allow_expired or (period.end is None or now <= period.end)


@dataclass(init=False)
class Key:
    """
    Represents a key in a `Keyring`.
    """

    hash_algorithm: hashes.HashAlgorithm
    key: PublicKey
    key_id: KeyID

    _RSA_SHA_256_DETAILS: ClassVar[set[_PublicKeyDetails]] = {
        _PublicKeyDetails.PKCS1_RSA_PKCS1V5,
        _PublicKeyDetails.PKIX_RSA_PKCS1V15_2048_SHA256,
        _PublicKeyDetails.PKIX_RSA_PKCS1V15_3072_SHA256,
        _PublicKeyDetails.PKIX_RSA_PKCS1V15_4096_SHA256,
    }

    _EC_DETAILS_TO_HASH: ClassVar[dict[_PublicKeyDetails, hashes.HashAlgorithm]] = {
        _PublicKeyDetails.PKIX_ECDSA_P256_SHA_256: hashes.SHA256(),
        _PublicKeyDetails.PKIX_ECDSA_P384_SHA_384: hashes.SHA384(),
        _PublicKeyDetails.PKIX_ECDSA_P521_SHA_512: hashes.SHA512(),
    }

    def __init__(self, public_key: _PublicKey) -> None:
        """
        Construct a key from the given Sigstore PublicKey message.
        """

        hash_algorithm: hashes.HashAlgorithm
        if public_key.key_details in self._RSA_SHA_256_DETAILS:
            hash_algorithm = hashes.SHA256()
            key = load_der_public_key(public_key.raw_bytes, types=(rsa.RSAPublicKey,))
        elif public_key.key_details in self._EC_DETAILS_TO_HASH:
            hash_algorithm = self._EC_DETAILS_TO_HASH[public_key.key_details]
            key = load_der_public_key(
                public_key.raw_bytes, types=(ec.EllipticCurvePublicKey,)
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
        if isinstance(self.key, rsa.RSAPublicKey):
            self.key.verify(
                signature=signature,
                data=data,
                # TODO: Parametrize this as well, for PSS.
                padding=padding.PKCS1v15(),
                algorithm=self.hash_algorithm,
            )
        elif isinstance(self.key, ec.EllipticCurvePublicKey):
            self.key.verify(
                signature=signature,
                data=data,
                signature_algorithm=ec.ECDSA(self.hash_algorithm),
            )
        else:
            # Unreachable without API misuse.
            raise VerificationError(f"keyring: unsupported key: {self.key}")


class Keyring:
    """
    Represents a set of keys, each of which is a potentially valid verifier.
    """

    def __init__(self, public_keys: List[_PublicKey] = []):
        """
        Create a new `Keyring`, with `keys` as the initial set of verifying keys.
        """
        self._keyring: dict[KeyID, Key] = {}

        for public_key in public_keys:
            key = Key(public_key)
            self._keyring[key.key_id] = key

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
        if key is not None:
            candidates = [key]
        else:
            candidates = list(self._keyring.values())

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


RekorKeyring = NewType("RekorKeyring", Keyring)
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


class TrustedRoot(_TrustedRoot):
    """Complete set of trusted entities for a Sigstore client"""

    purpose: KeyringPurpose

    @classmethod
    def from_file(
        cls,
        path: str,
        purpose: KeyringPurpose = KeyringPurpose.VERIFY,
    ) -> TrustedRoot:
        """Create a new trust root from file"""
        trusted_root: TrustedRoot = cls().from_json(Path(path).read_bytes())
        trusted_root.purpose = purpose
        return trusted_root

    @classmethod
    def from_tuf(
        cls,
        url: str,
        offline: bool = False,
        purpose: KeyringPurpose = KeyringPurpose.VERIFY,
    ) -> TrustedRoot:
        """Create a new trust root from a TUF repository.

        If `offline`, will use trust root in local TUF cache. Otherwise will
        update the trust root from remote TUF repository.
        """
        path = TrustUpdater(url, offline).get_trusted_root_path()
        return cls.from_file(path, purpose)

    @classmethod
    def production(
        cls,
        offline: bool = False,
        purpose: KeyringPurpose = KeyringPurpose.VERIFY,
    ) -> TrustedRoot:
        """Create new trust root from Sigstore production TUF repository.

        If `offline`, will use trust root in local TUF cache. Otherwise will
        update the trust root from remote TUF repository.
        """
        return cls.from_tuf(DEFAULT_TUF_URL, offline, purpose)

    @classmethod
    def staging(
        cls,
        offline: bool = False,
        purpose: KeyringPurpose = KeyringPurpose.VERIFY,
    ) -> TrustedRoot:
        """Create new trust root from Sigstore staging TUF repository.

        If `offline`, will use trust root in local TUF cache. Otherwise will
        update the trust root from remote TUF repository.
        """
        return cls.from_tuf(STAGING_TUF_URL, offline, purpose)

    @staticmethod
    def _get_tlog_keys(
        tlogs: list[TransparencyLogInstance], purpose: KeyringPurpose
    ) -> Iterable[_PublicKey]:
        """
        Yields an iterator of public keys for transparency log instances that
        are suitable for `purpose`.
        """
        allow_expired = purpose is KeyringPurpose.VERIFY
        for tlog in tlogs:
            if not _is_timerange_valid(
                tlog.public_key.valid_for, allow_expired=allow_expired
            ):
                continue

            yield tlog.public_key

    @staticmethod
    def _get_ca_keys(
        cas: list[CertificateAuthority], *, allow_expired: bool
    ) -> Iterable[bytes]:
        """Return public key contents given certificate authorities."""

        for ca in cas:
            if not _is_timerange_valid(ca.valid_for, allow_expired=allow_expired):
                continue
            for cert in ca.cert_chain.certificates:
                yield cert.raw_bytes

    def rekor_keyring(self) -> RekorKeyring:
        """Return keyring with keys for Rekor."""

        keys: list[_PublicKey] = list(self._get_tlog_keys(self.tlogs, self.purpose))
        if len(keys) != 1:
            raise MetadataError("Did not find one Rekor key in trusted root")
        return RekorKeyring(Keyring(keys))

    def ct_keyring(self) -> CTKeyring:
        """Return keyring with key for CTFE."""
        ctfes: list[_PublicKey] = list(self._get_tlog_keys(self.ctlogs, self.purpose))
        if not ctfes:
            raise MetadataError("CTFE keys not found in trusted root")
        return CTKeyring(Keyring(ctfes))

    def get_fulcio_certs(self) -> list[Certificate]:
        """Return the Fulcio certificates."""

        certs: list[Certificate]

        # Return expired certificates too: they are expired now but may have
        # been active when the certificate was used to sign.
        certs = [
            load_der_x509_certificate(c)
            for c in self._get_ca_keys(self.certificate_authorities, allow_expired=True)
        ]
        if not certs:
            raise MetadataError("Fulcio certificates not found in trusted root")
        return certs
