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

from argparse import Namespace
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Iterable, NewType, Optional

from cryptography.x509 import (
    Certificate,
    load_der_x509_certificate,
    load_pem_x509_certificates,
)
from sigstore_protobuf_specs.dev.sigstore.common.v1 import TimeRange
from sigstore_protobuf_specs.dev.sigstore.trustroot.v1 import (
    CertificateAuthority,
    TransparencyLogInstance,
)
from sigstore_protobuf_specs.dev.sigstore.trustroot.v1 import (
    TrustedRoot as _TrustedRoot,
)

from sigstore._internal.keyring import Keyring
from sigstore._internal.tuf import DEFAULT_TUF_URL, STAGING_TUF_URL, TrustUpdater
from sigstore.errors import MetadataError

RekorKeyring = NewType("RekorKeyring", Keyring)


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

    args: Optional[Namespace] = None
    purpose: KeyringPurpose

    @classmethod
    def from_file(
        cls,
        path: str,
        args: Optional[Namespace] = None,
        purpose: KeyringPurpose = KeyringPurpose.VERIFY,
    ) -> "TrustedRoot":
        """Create a new trust root from file"""
        trusted_root: TrustedRoot = cls().from_json(Path(path).read_bytes())
        trusted_root.args = args
        trusted_root.purpose = purpose
        return trusted_root

    @classmethod
    def from_tuf(
        cls,
        url: str,
        offline: bool = False,
        args: Optional[Namespace] = None,
        purpose: KeyringPurpose = KeyringPurpose.VERIFY,
    ) -> "TrustedRoot":
        """Create a new trust root from a TUF repository.

        If `offline`, will use trust root in local TUF cache. Otherwise will
        update the trust root from remote TUF repository.
        """
        path = TrustUpdater(url, offline).get_trusted_root_path()
        trusted_root = cls.from_file(path)
        trusted_root.args = args
        trusted_root.purpose = purpose
        return trusted_root

    @classmethod
    def production(
        cls,
        offline: bool = False,
        args: Optional[Namespace] = None,
        purpose: KeyringPurpose = KeyringPurpose.VERIFY,
    ) -> "TrustedRoot":
        """Create new trust root from Sigstore production TUF repository.

        If `offline`, will use trust root in local TUF cache. Otherwise will
        update the trust root from remote TUF repository.
        """
        trusted_root = cls.from_tuf(DEFAULT_TUF_URL, offline)
        trusted_root.args = args
        trusted_root.purpose = purpose
        return trusted_root

    @classmethod
    def staging(
        cls,
        offline: bool = False,
        args: Optional[Namespace] = None,
        purpose: KeyringPurpose = KeyringPurpose.VERIFY,
    ) -> "TrustedRoot":
        """Create new trust root from Sigstore staging TUF repository.

        If `offline`, will use trust root in local TUF cache. Otherwise will
        update the trust root from remote TUF repository.
        """
        trusted_root = cls.from_tuf(STAGING_TUF_URL, offline)
        trusted_root.args = args
        trusted_root.purpose = purpose
        return trusted_root

    @staticmethod
    def _get_tlog_keys(
        tlogs: list[TransparencyLogInstance], purpose: KeyringPurpose
    ) -> Iterable[bytes]:
        """Return public key contents given transparency log instances."""
        allow_expired = purpose is KeyringPurpose.VERIFY
        for key in tlogs:
            if not _is_timerange_valid(
                key.public_key.valid_for, allow_expired=allow_expired
            ):
                continue
            key_bytes = key.public_key.raw_bytes
            if key_bytes:
                yield key_bytes

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
        """Return public key contents given certificate authorities."""

        return RekorKeyring(self._get_rekor_keys())

    def get_ctfe_keys(self) -> list[bytes]:
        """Return the CTFE public keys contents."""
        # TODO: get purpose as argument
        purpose = KeyringPurpose.VERIFY
        ctfes: list[bytes] = list(self._get_tlog_keys(self.ctlogs, purpose))
        if not ctfes:
            raise MetadataError("CTFE keys not found in trusted root")
        return ctfes

    def _get_rekor_keys(self) -> Keyring:
        """Return the rekor public key content."""
        keys: list[bytes]
        if self.args and self.args.rekor_root_pubkey:
            keys = self.args.rekor_root_pubkey.read()
        else:
            keys = list(self._get_tlog_keys(self.tlogs, self.purpose))
        if len(keys) != 1:
            raise MetadataError("Did not find one Rekor key in trusted root")
        return Keyring(keys)

    def get_fulcio_certs(self) -> list[Certificate]:
        """Return the Fulcio certificates."""

        certs: list[Certificate]

        # Return expired certificates too: they are expired now but may have
        # been active when the certificate was used to sign.

        if self.args:
            try:
                certs = load_pem_x509_certificates(self.args.certificate_chain.read())
            except ValueError as error:
                self.args._parser.error(f"Invalid certificate chain: {error}")
                raise ValueError("unreachable")
        else:
            certs = [
                load_der_x509_certificate(c)
                for c in self._get_ca_keys(
                    self.certificate_authorities, allow_expired=True
                )
            ]
        if not certs:
            raise MetadataError("Fulcio certificates not found in trusted root")
        return certs
