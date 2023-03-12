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
TUF functionality for `sigstore-python`.
"""

from __future__ import annotations

import logging
import os
from datetime import datetime, timezone
from enum import Enum, auto
from functools import lru_cache
from pathlib import Path
from typing import Optional
from urllib import parse

import appdirs
from cryptography.x509 import (
    Certificate,
    load_der_x509_certificate,
    load_pem_x509_certificate,
)
from sigstore_protobuf_specs.dev.sigstore.common.v1 import TimeRange
from sigstore_protobuf_specs.dev.sigstore.trustroot.v1 import TrustedRoot
from tuf.api import exceptions as TUFExceptions
from tuf.ngclient import RequestsFetcher, Updater

from sigstore._errors import MetadataError, TUFError
from sigstore._utils import read_embedded

logger = logging.getLogger(__name__)

DEFAULT_TUF_URL = "https://sigstore-tuf-root.storage.googleapis.com/"
STAGING_TUF_URL = "https://tuf-root-staging.storage.googleapis.com/"


@lru_cache()
def _get_fetcher() -> RequestsFetcher:
    # NOTE: We poke into the underlying fetcher here to set a more reasonable timeout.
    # The default timeout is 4 seconds, which can cause spurious timeout errors on
    # CI systems like GitHub Actions (where traffic may be delayed/deprioritized due
    # to network load).
    fetcher = RequestsFetcher()
    fetcher.socket_timeout = 30

    return fetcher


def _get_dirs(url: str) -> tuple[Path, Path]:
    """
    Given a TUF repository URL, return suitable local metadata and cache directories.

    These directories are not guaranteed to already exist.
    """

    builder = appdirs.AppDirs("sigstore-python", "sigstore")
    repo_base = parse.quote(url, safe="")

    tuf_data_dir = Path(builder.user_data_dir) / "tuf"
    tuf_cache_dir = Path(builder.user_cache_dir) / "tuf"

    return (tuf_data_dir / repo_base), (tuf_cache_dir / repo_base)


class KeyUsage(Enum):
    Rekor = auto()
    Fulcio = auto()
    CTFE = auto()

    def __str__(self) -> str:
        return self.name


class KeyStatus(Enum):
    Active = auto()
    Expired = auto()

    def __str__(self) -> str:
        return self.name


def _timerange_valid_for_status(period: TimeRange | None, status: KeyStatus) -> bool:
    now = datetime.now(timezone.utc)

    # If there was no validity period specified, the key is always valid.
    if not period:
        return True

    # Active: if the current time is before the starting period, we are not yet valid
    if now < period.start:
        return False

    # If we want Expired keys, we don't care. Otherwise, check that we are within range.
    return status == KeyStatus.Expired or (period.end is not None and now < period.end)


class TrustUpdater:
    """Internal trust root (certificates and keys) downloader.

    TrustUpdater discovers the currently valid certificates and keys and
    securely downloads them from the remote TUF repository at 'url'.

    TrustUpdater expects to find an initial root.json in either the local
    metadata directory for this URL, or (as special case for the sigstore.dev
    production and staging instances) in the application resources.
    """

    def __init__(self, url: str) -> None:
        """
        Create a new `TrustUpdater`, pulling from the given `url`.

        The URL is expected to match one of `sigstore-python`'s known TUF
        roots, i.e. for the production or staging Sigstore TUF repos.
        """
        self._repo_url = url
        self._updater: Updater | None = None
        self._trusted_root: TrustedRoot | None = None

        self._metadata_dir, self._targets_dir = _get_dirs(url)

        # Initialize metadata dir
        tuf_root = self._metadata_dir / "root.json"
        if not tuf_root.exists():
            if self._repo_url == DEFAULT_TUF_URL:
                fname = "root.json"
            elif self._repo_url == STAGING_TUF_URL:
                fname = "staging-root.json"
            else:
                raise Exception(f"TUF root not found in {tuf_root}")

            self._metadata_dir.mkdir(parents=True, exist_ok=True)
            root_json = read_embedded(fname)
            with tuf_root.open("wb") as io:
                io.write(root_json)

        # Initialize targets cache dir
        # NOTE: Could prime the cache here with any embedded certs/keys
        self._targets_dir.mkdir(parents=True, exist_ok=True)

        logger.debug(f"TUF metadata: {self._metadata_dir}")
        logger.debug(f"TUF targets cache: {self._targets_dir}")

    @classmethod
    def production(cls) -> TrustUpdater:
        """
        Returns a `TrustUpdater` for the Sigstore production instances.
        """
        return cls(DEFAULT_TUF_URL)

    @classmethod
    def staging(cls) -> TrustUpdater:
        """
        Returns a `TrustUpdater` for the Sigstore staging instances.
        """
        return cls(STAGING_TUF_URL)

    def _setup(self) -> Updater:
        """Initialize and update the toplevel TUF metadata"""
        updater = Updater(
            metadata_dir=str(self._metadata_dir),
            metadata_base_url=self._repo_url,
            target_base_url=parse.urljoin(f"{self._repo_url}/", "targets/"),
            target_dir=str(self._targets_dir),
            fetcher=_get_fetcher(),
        )

        # NOTE: we would like to avoid refresh if the toplevel metadata is valid.
        # https://github.com/theupdateframework/python-tuf/issues/2225
        try:
            updater.refresh()
        except Exception as e:
            raise TUFError("Failed to refresh TUF metadata") from e

        return updater

    def _get_trusted_root(self) -> Optional[TrustedRoot]:
        if not self._updater:
            self._updater = self._setup()

        root_info = self._updater.get_targetinfo("trusted_root.json")
        if root_info is None:
            return None
        path = self._updater.find_cached_target(root_info)
        if path is None:
            try:
                path = self._updater.download_target(root_info)
            except (
                TUFExceptions.DownloadError,
                TUFExceptions.RepositoryError,
            ) as e:
                raise TUFError("Failed to download trusted key bundle") from e

        return TrustedRoot().from_json(Path(path).read_bytes())

    def _get(self, usage: KeyUsage, statuses: list[KeyStatus]) -> list[bytes]:
        """Return all targets with given usage and any of the statuses"""
        if not self._updater:
            self._updater = self._setup()

        data = []

        targets = self._updater._trusted_set.targets.signed.targets
        for target_info in targets.values():
            custom = target_info.unrecognized_fields.get("custom", {}).get("sigstore")
            if (
                custom
                and custom.get("status") in [str(x) for x in statuses]
                and custom.get("usage") == str(usage)
            ):
                path = self._updater.find_cached_target(target_info)
                if path is None:
                    try:
                        path = self._updater.download_target(target_info)
                    except (
                        TUFExceptions.DownloadError,
                        TUFExceptions.RepositoryError,
                    ) as e:
                        raise TUFError(f"Failed to download keys for {usage}") from e
                with open(path, "rb") as f:
                    target_contents = f.read()
                    base_name = os.path.basename(path)
                    logger.info(
                        f"TUF cache target {usage} {statuses}: {base_name} sha256 {target_info.hashes.get('sha256')}"
                    )
                    logger.debug(
                        f"TUF cache target {base_name}:\n"
                        f"{target_contents.decode('utf-8')}"
                    )
                    data.append(target_contents)

        return data

    def get_ctfe_keys(self) -> list[bytes]:
        """Return the active CTFE public keys contents.

        May download files from the remote repository.
        """

        self._trusted_root = self._get_trusted_root()
        if self._trusted_root:
            keys = []
            for key in self._trusted_root.ctlogs:
                if not _timerange_valid_for_status(
                    key.public_key.valid_for, KeyStatus.Active
                ):
                    continue
                key_bytes = key.public_key.raw_bytes
                if key_bytes:
                    keys.append(key_bytes)

            return keys

        ctfes = self._get(KeyUsage.CTFE, [KeyStatus.Active])
        if not ctfes:
            raise MetadataError("CTFE keys not found in TUF metadata")
        return ctfes

    def get_rekor_keys(self) -> list[bytes]:
        """Return the rekor public key content.

        May download files from the remote repository.
        """
        self._trusted_root = self._get_trusted_root()
        if self._trusted_root:
            keys = []
            for key in self._trusted_root.tlogs:
                if not _timerange_valid_for_status(
                    key.public_key.valid_for, KeyStatus.Active
                ):
                    continue
                key_bytes = key.public_key.raw_bytes
                if key_bytes:
                    keys.append(key_bytes)

            return keys

        keys = self._get(KeyUsage.Rekor, [KeyStatus.Active])
        if len(keys) != 1:
            raise MetadataError("Did not find one active Rekor key in TUF metadata")
        return keys

    def get_fulcio_certs(self) -> list[Certificate]:
        """Return the Fulcio certificates.

        May download files from the remote repository.
        """
        self._trusted_root = self._get_trusted_root()
        if self._trusted_root:
            keys = []
            for ca in self._trusted_root.certificate_authorities:
                if not _timerange_valid_for_status(ca.valid_for, KeyStatus.Expired):
                    continue
                keys.extend(
                    [
                        load_der_x509_certificate(cert.raw_bytes)
                        for cert in ca.cert_chain.certificates
                    ]
                )

            return keys

        # Return expired certificates too: they are expired now but may have
        # been active when the certificate was used to sign.
        certs = self._get(KeyUsage.Fulcio, [KeyStatus.Active, KeyStatus.Expired])
        if not certs:
            raise MetadataError("Fulcio certificates not found in TUF metadata")
        return [load_pem_x509_certificate(c) for c in certs]
