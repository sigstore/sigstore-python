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
from pathlib import Path
from urllib import parse

import appdirs
from cryptography.x509 import Certificate, load_pem_x509_certificate
from tuf.ngclient import Updater

from sigstore._utils import read_embedded

logger = logging.getLogger(__name__)

DEFAULT_TUF_URL = "https://sigstore-tuf-root.storage.googleapis.com/"
STAGING_TUF_URL = "https://tuf-root-staging.storage.googleapis.com/"

# for tests to override
_fetcher = None


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
            fetcher=_fetcher,
        )

        # NOTE: we would like to avoid refresh if the toplevel metadata is valid.
        # https://github.com/theupdateframework/python-tuf/issues/2225
        updater.refresh()
        return updater

    def _get(self, usage: str, statuses: list[str]) -> list[bytes]:
        """Return all targets with given usage and any of the statuses"""
        if not self._updater:
            self._updater = self._setup()

        data = []

        # NOTE: _updater has been fully initialized at this point, but mypy can't see that.
        targets = self._updater._trusted_set.targets.signed.targets  # type: ignore[union-attr]
        for target_info in targets.values():
            custom = target_info.unrecognized_fields["custom"]["sigstore"]
            if custom["status"] in statuses and custom["usage"] == usage:
                path = self._updater.find_cached_target(target_info)
                if path is None:
                    path = self._updater.download_target(target_info)
                with open(path, "rb") as f:
                    data.append(f.read())

        return data

    def get_ctfe_keys(self) -> list[bytes]:
        """Return the active CTFE public keys contents.

        May download files from the remote repository.
        """
        ctfes = self._get("CTFE", ["Active"])
        if not ctfes:
            raise Exception("CTFE keys not found in TUF metadata")
        return ctfes

    def get_rekor_key(self) -> bytes:
        """Return the rekor public key content.

        May download files from the remote repository.
        """
        keys = self._get("Rekor", ["Active"])
        if len(keys) != 1:
            raise Exception("Did not find one active Rekor key in TUF metadata")
        return keys[0]

    def get_fulcio_certs(self) -> list[Certificate]:
        """Return the Fulcio certificates.

        May download files from the remote repository.
        """
        # Return expired certificates too: they are expired now but may have
        # been active when the certificate was used to sign.
        certs = self._get("Fulcio", ["Active", "Expired"])
        if not certs:
            raise Exception("Fulcio certificates not found in TUF metadata")
        return [load_pem_x509_certificate(c) for c in certs]
