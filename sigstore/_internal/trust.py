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
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timezone
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
from sigstore_protobuf_specs.dev.sigstore.common.v1 import PublicKey as _PublicKey
from sigstore_protobuf_specs.dev.sigstore.common.v1 import (
    PublicKeyDetails as _PublicKeyDetails,
)
from sigstore_protobuf_specs.dev.sigstore.common.v1 import TimeRange
from sigstore_protobuf_specs.dev.sigstore.trustroot.v1 import (
    CertificateAuthority as _CertificateAuthority,
)
from sigstore_protobuf_specs.dev.sigstore.trustroot.v1 import (
    ClientTrustConfig as _ClientTrustConfig,
)
from sigstore_protobuf_specs.dev.sigstore.trustroot.v1 import (
    Service,
    ServiceConfiguration,
    ServiceSelector,
    TransparencyLogInstance,
)
from sigstore_protobuf_specs.dev.sigstore.trustroot.v1 import (
    SigningConfig as _SigningConfig,
)
from sigstore_protobuf_specs.dev.sigstore.trustroot.v1 import (
    TrustedRoot as _TrustedRoot,
)

from sigstore._internal.fulcio.client import FulcioClient
from sigstore._internal.rekor.client import RekorClient
from sigstore._internal.timestamp import TimestampAuthorityClient
from sigstore._internal.tuf import DEFAULT_TUF_URL, STAGING_TUF_URL, TrustUpdater
from sigstore._utils import (
    KeyID,
    PublicKey,
    key_id,
    load_der_public_key,
    read_embedded,
)
from sigstore.errors import Error, MetadataError, TUFError, VerificationError

# Versions supported by this client
REKOR_VERSIONS = [1]
TSA_VERSIONS = [1]
FULCIO_VERSIONS = [1]
OIDC_VERSIONS = [1]

_logger = logging.getLogger(__name__)


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

    hash_algorithm: hashes.HashAlgorithm | None
    key: PublicKey
    key_id: KeyID

    _RSA_SHA_256_DETAILS: ClassVar = {
        _PublicKeyDetails.PKCS1_RSA_PKCS1V5,
        _PublicKeyDetails.PKIX_RSA_PKCS1V15_2048_SHA256,
        _PublicKeyDetails.PKIX_RSA_PKCS1V15_3072_SHA256,
        _PublicKeyDetails.PKIX_RSA_PKCS1V15_4096_SHA256,
    }

    _EC_DETAILS_TO_HASH: ClassVar = {
        _PublicKeyDetails.PKIX_ECDSA_P256_SHA_256: hashes.SHA256(),
        _PublicKeyDetails.PKIX_ECDSA_P384_SHA_384: hashes.SHA384(),
        _PublicKeyDetails.PKIX_ECDSA_P521_SHA_512: hashes.SHA512(),
    }

    def __init__(self, public_key: _PublicKey) -> None:
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
        elif public_key.key_details == _PublicKeyDetails.PKIX_ED25519:
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

    def __init__(self, public_keys: list[_PublicKey] = []):
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


class CertificateAuthority:
    """
    Certificate Authority used in a Trusted Root configuration.
    """

    def __init__(self, inner: _CertificateAuthority):
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
        inner = _CertificateAuthority().from_json(Path(path).read_bytes())
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
        if not _is_timerange_valid(self._inner.valid_for, allow_expired=allow_expired):
            return []
        return self._certificates


class SigningConfig:
    """
    Signing configuration for a Sigstore instance.
    """

    class SigningConfigType(str, Enum):
        """
        Known Sigstore signing config media types.
        """

        SIGNING_CONFIG_0_2 = "application/vnd.dev.sigstore.signingconfig.v0.2+json"

        def __str__(self) -> str:
            """Returns the variant's string value."""
            return self.value

    def __init__(self, inner: _SigningConfig):
        """
        Construct a new `SigningConfig`.

        @api private
        """
        self._inner = inner

        # must have a recognized media type.
        try:
            SigningConfig.SigningConfigType(self._inner.media_type)
        except ValueError:
            raise Error(f"unsupported signing config format: {self._inner.media_type}")

        # Create lists of service protos that are valid, selected by the service
        # configuration & supported by this client
        self._tlogs = self._get_valid_services(
            self._inner.rekor_tlog_urls, REKOR_VERSIONS, self._inner.rekor_tlog_config
        )
        if not self._tlogs:
            raise Error("No valid Rekor transparency log found in signing config")

        self._tsas = self._get_valid_services(
            self._inner.tsa_urls, TSA_VERSIONS, self._inner.tsa_config
        )

        self._fulcios = self._get_valid_services(
            self._inner.ca_urls, FULCIO_VERSIONS, None
        )
        if not self._fulcios:
            raise Error("No valid Fulcio CA found in signing config")

        self._oidcs = self._get_valid_services(
            self._inner.oidc_urls, OIDC_VERSIONS, None
        )

    @classmethod
    def from_file(
        cls,
        path: str,
    ) -> SigningConfig:
        """Create a new signing config from file"""
        inner = _SigningConfig().from_json(Path(path).read_bytes())
        return cls(inner)

    @staticmethod
    def _get_valid_services(
        services: list[Service],
        supported_versions: list[int],
        config: ServiceConfiguration | None,
    ) -> list[Service]:
        """Return supported services, taking SigningConfig restrictions into account"""

        # split services by operator, only include valid services
        services_by_operator: dict[str, list[Service]] = defaultdict(list)
        for service in services:
            if service.major_api_version not in supported_versions:
                continue

            if not _is_timerange_valid(service.valid_for, allow_expired=False):
                continue

            services_by_operator[service.operator].append(service)

        # build a list of services but make sure we only include one service per operator
        # and use the highest version available for that operator
        result: list[Service] = []
        for op_services in services_by_operator.values():
            op_services.sort(key=lambda s: s.major_api_version)
            result.append(op_services[-1])

        # Depending on ServiceSelector, prune the result list
        if not config or config.selector == ServiceSelector.ALL:
            return result

        if config.selector == ServiceSelector.UNDEFINED:
            raise ValueError("Undefined is not a valid signing config ServiceSelector")

        # handle EXACT and ANY selectors
        count = config.count if config.selector == ServiceSelector.EXACT else 1
        if len(result) < count:
            raise ValueError(
                f"Expected {count} services in signing config, found {len(result)}"
            )

        return result[:count]

    def get_tlogs(self) -> list[RekorClient]:
        """
        Returns the rekor transparency log clients to sign with.
        """
        return [RekorClient(tlog.url) for tlog in self._tlogs]

    def get_fulcio(self) -> FulcioClient:
        """
        Returns a Fulcio client to get a signing certificate from
        """
        return FulcioClient(self._fulcios[0].url)

    def get_oidc_url(self) -> str:
        """
        Returns url for the OIDC provider that client should use to interactively
        authenticate.
        """
        if not self._oidcs:
            raise Error("No valid OIDC provider found in signing config")
        return self._oidcs[0].url

    def get_tsas(self) -> list[TimestampAuthorityClient]:
        """
        Returns timestamp authority clients for urls configured in signing config.
        """
        return [TimestampAuthorityClient(s.url) for s in self._tsas]


class TrustedRoot:
    """
    The cryptographic root(s) of trust for a Sigstore instance.
    """

    class TrustedRootType(str, Enum):
        """
        Known Sigstore trusted root media types.
        """

        TRUSTED_ROOT_0_1 = "application/vnd.dev.sigstore.trustedroot+json;version=0.1"

        def __str__(self) -> str:
            """Returns the variant's string value."""
            return self.value

    def __init__(self, inner: _TrustedRoot):
        """
        Construct a new `TrustedRoot`.

        @api private
        """
        self._inner = inner
        self._verify()

    def _verify(self) -> None:
        """
        Performs various feats of heroism to ensure that the trusted root
        is well-formed.
        """

        # The trusted root must have a recognized media type.
        try:
            TrustedRoot.TrustedRootType(self._inner.media_type)
        except ValueError:
            raise Error(f"unsupported trusted root format: {self._inner.media_type}")

    @classmethod
    def from_file(
        cls,
        path: str,
    ) -> TrustedRoot:
        """Create a new trust root from file"""
        inner = _TrustedRoot().from_json(Path(path).read_bytes())
        return cls(inner)

    def _get_tlog_keys(
        self, tlogs: list[TransparencyLogInstance], purpose: KeyringPurpose
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

    def rekor_keyring(self, purpose: KeyringPurpose) -> RekorKeyring:
        """Return keyring with keys for Rekor."""

        keys: list[_PublicKey] = list(self._get_tlog_keys(self._inner.tlogs, purpose))
        if len(keys) == 0:
            raise MetadataError("Did not find any Rekor keys in trusted root")
        return RekorKeyring(Keyring(keys))

    def ct_keyring(self, purpose: KeyringPurpose) -> CTKeyring:
        """Return keyring with key for CTFE."""
        ctfes: list[_PublicKey] = list(self._get_tlog_keys(self._inner.ctlogs, purpose))
        if not ctfes:
            raise MetadataError("CTFE keys not found in trusted root")
        return CTKeyring(Keyring(ctfes))

    def get_fulcio_certs(self) -> list[Certificate]:
        """Return the Fulcio certificates."""

        certs: list[Certificate] = []

        # Return expired certificates too: they are expired now but may have
        # been active when the certificate was used to sign.
        for authority in self._inner.certificate_authorities:
            certificate_authority = CertificateAuthority(authority)
            certs.extend(certificate_authority.certificates(allow_expired=True))

        if not certs:
            raise MetadataError("Fulcio certificates not found in trusted root")
        return certs

    def get_timestamp_authorities(self) -> list[CertificateAuthority]:
        """
        Return the TSA present in the trusted root.

        This list may be empty and in this case, no timestamp verification can be
        performed.
        """
        certificate_authorities: list[CertificateAuthority] = [
            CertificateAuthority(cert_chain)
            for cert_chain in self._inner.timestamp_authorities
        ]
        return certificate_authorities


class ClientTrustConfig:
    """
    Represents a Sigstore client's trust configuration, including a root of trust.
    """

    class ClientTrustConfigType(str, Enum):
        """
        Known Sigstore client trust config media types.
        """

        CONFIG_0_1 = "application/vnd.dev.sigstore.clienttrustconfig.v0.1+json"

        def __str__(self) -> str:
            """Returns the variant's string value."""
            return self.value

    @classmethod
    def from_json(cls, raw: str) -> ClientTrustConfig:
        """
        Deserialize the given client trust config.
        """
        inner = _ClientTrustConfig().from_json(raw)
        return cls(inner)

    @classmethod
    def production(
        cls,
        offline: bool = False,
    ) -> ClientTrustConfig:
        """Create new trust config from Sigstore production TUF repository.

        If `offline`, will use data in local TUF cache. Otherwise will
        update the data from remote TUF repository.
        """
        return cls.from_tuf(DEFAULT_TUF_URL, offline)

    @classmethod
    def staging(
        cls,
        offline: bool = False,
    ) -> ClientTrustConfig:
        """Create new trust config from Sigstore staging TUF repository.

        If `offline`, will use data in local TUF cache. Otherwise will
        update the data from remote TUF repository.
        """
        return cls.from_tuf(STAGING_TUF_URL, offline)

    @classmethod
    def from_tuf(
        cls,
        url: str,
        offline: bool = False,
    ) -> ClientTrustConfig:
        """Create a new trust config from a TUF repository.

        If `offline`, will use data in local TUF cache. Otherwise will
        update the trust config from remote TUF repository.
        """
        updater = TrustUpdater(url, offline)

        tr_path = updater.get_trusted_root_path()
        inner_tr = _TrustedRoot().from_json(Path(tr_path).read_bytes())

        try:
            sc_path = updater.get_signing_config_path()
            inner_sc = _SigningConfig().from_json(Path(sc_path).read_bytes())
        except TUFError as e:
            # TUF repo may not have signing config yet: hard code values for prod:
            # https://github.com/sigstore/sigstore-python/issues/1388
            if url == DEFAULT_TUF_URL:
                embedded = read_embedded("signing_config.v0.2.json", url)
                inner_sc = _SigningConfig().from_json(embedded)
            else:
                raise e

        return cls(
            _ClientTrustConfig(
                ClientTrustConfig.ClientTrustConfigType.CONFIG_0_1,
                inner_tr,
                inner_sc,
            )
        )

    def __init__(self, inner: _ClientTrustConfig) -> None:
        """
        @api private
        """
        self._inner = inner
        self._verify()

    def _verify(self) -> None:
        """
        Performs various feats of heroism to ensure that the client trust config
        is well-formed.
        """

        # The client trust config must have a recognized media type.
        try:
            ClientTrustConfig.ClientTrustConfigType(self._inner.media_type)
        except ValueError:
            raise Error(
                f"unsupported client trust config format: {self._inner.media_type}"
            )

    @property
    def trusted_root(self) -> TrustedRoot:
        """
        Return the interior root of trust, as a `TrustedRoot`.
        """
        return TrustedRoot(self._inner.trusted_root)

    @property
    def signing_config(self) -> SigningConfig:
        """
        Return the interior root of trust, as a `SigningConfig`.
        """
        return SigningConfig(self._inner.signing_config)
