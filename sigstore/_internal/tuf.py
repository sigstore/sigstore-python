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
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from typing import Iterable
from urllib import parse

import appdirs
from cryptography.x509 import Certificate, load_der_x509_certificate
from sigstore_protobuf_specs.dev.sigstore.common.v1 import TimeRange
from sigstore_protobuf_specs.dev.sigstore.trustroot.v1 import (
    CertificateAuthority,
    TransparencyLogInstance,
    TrustedRoot,
)
from tuf.api import exceptions as TUFExceptions
from tuf.ngclient import RequestsFetcher, Updater

from sigstore._utils import read_embedded
from sigstore.errors import MetadataError, RootError, TUFError

logger = logging.getLogger(__name__)

DEFAULT_TUF_URL = "https://tuf-repo-cdn.sigstore.dev"
STAGING_TUF_URL = "https://tuf-repo-cdn.sigstage.dev"


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
        self._metadata_dir, self._targets_dir = _get_dirs(url)

        rsrc_prefix: str
        if self._repo_url == DEFAULT_TUF_URL:
            rsrc_prefix = "prod"
        elif self._repo_url == STAGING_TUF_URL:
            rsrc_prefix = "staging"
        else:
            raise RootError

        # Initialize metadata dir
        self._metadata_dir.mkdir(parents=True, exist_ok=True)
        tuf_root = self._metadata_dir / "root.json"

        if not tuf_root.exists():
            try:
                root_json = read_embedded("root.json", rsrc_prefix)
            except FileNotFoundError as e:
                raise RootError from e

            tuf_root.write_bytes(root_json)

        # Initialize targets cache dir
        self._targets_dir.mkdir(parents=True, exist_ok=True)
        trusted_root_target = self._targets_dir / "trusted_root.json"

        if not trusted_root_target.exists():
            try:
                trusted_root_json = read_embedded("trusted_root.json", rsrc_prefix)
            except FileNotFoundError as e:
                raise RootError from e

            trusted_root_target.write_bytes(trusted_root_json)

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

    @lru_cache()
    def _updater(self) -> Updater:
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

    @lru_cache()
    def _get_trusted_root(self) -> TrustedRoot:
        root_info = self._updater().get_targetinfo("trusted_root.json")
        if root_info is None:
            raise TUFError("Unsupported TUF configuration: no trusted root")
        path = self._updater().find_cached_target(root_info)
        if path is None:
            try:
                path = self._updater().download_target(root_info)
            except (
                TUFExceptions.DownloadError,
                TUFExceptions.RepositoryError,
            ) as e:
                raise TUFError("Failed to download trusted key bundle") from e

        logger.debug("Found trusted root")
        return TrustedRoot().from_json(Path(path).read_bytes())

    def _get_tlog_keys(self, tlogs: list[TransparencyLogInstance]) -> Iterable[bytes]:
        """Return public key contents given transparency log instances."""

        for key in tlogs:
            if not _is_timerange_valid(key.public_key.valid_for, allow_expired=False):
                continue
            key_bytes = key.public_key.raw_bytes
            if key_bytes:
                yield key_bytes

    def _get_ca_keys(
        self, cas: list[CertificateAuthority], *, allow_expired: bool
    ) -> Iterable[bytes]:
        """Return public key contents given certificate authorities."""

        for ca in cas:
            if not _is_timerange_valid(ca.valid_for, allow_expired=allow_expired):
                continue
            for cert in ca.cert_chain.certificates:
                yield cert.raw_bytes

    def get_ctfe_keys(self) -> list[bytes]:
        """Return the active CTFE public keys contents.

        May download files from the remote repository.
        """
        ctfes: list[bytes]

        trusted_root = self._get_trusted_root()
        ctfes = list(self._get_tlog_keys(trusted_root.ctlogs))

        if not ctfes:
            raise MetadataError("CTFE keys not found in TUF metadata")
        return ctfes

    def get_rekor_keys(self) -> list[bytes]:
        """Return the rekor public key content.

        May download files from the remote repository.
        """
        keys: list[bytes]

        trusted_root = self._get_trusted_root()
        keys = list(self._get_tlog_keys(trusted_root.tlogs))

        if len(keys) != 1:
            raise MetadataError("Did not find one active Rekor key in TUF metadata")
        return keys

    def get_fulcio_certs(self) -> list[Certificate]:
        """Return the Fulcio certificates.

        May download files from the remote repository.
        """
        certs: list[Certificate]

        trusted_root = self._get_trusted_root()
        # Return expired certificates too: they are expired now but may have
        # been active when the certificate was used to sign.
        certs = [
            load_der_x509_certificate(c)
            for c in self._get_ca_keys(
                trusted_root.certificate_authorities, allow_expired=True
            )
        ]

        if not certs:
            raise MetadataError("Fulcio certificates not found in TUF metadata")
        return certs
