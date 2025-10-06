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
from functools import lru_cache
from pathlib import Path
from urllib import parse

import platformdirs
from tuf.api import exceptions as TUFExceptions
from tuf.ngclient import Updater, UpdaterConfig  # type: ignore[attr-defined]

from sigstore import __version__
from sigstore._utils import read_embedded
from sigstore.errors import TUFError

_logger = logging.getLogger(__name__)

DEFAULT_TUF_URL = "https://tuf-repo-cdn.sigstore.dev"
STAGING_TUF_URL = "https://tuf-repo-cdn.sigstage.dev"


def _get_dirs(url: str) -> tuple[Path, Path]:
    """
    Given a TUF repository URL, return suitable local metadata and cache directories.

    These directories are not guaranteed to already exist.
    """

    app_name = "sigstore-python"
    app_author = "sigstore"

    repo_base = parse.quote(url, safe="")

    tuf_data_dir = Path(platformdirs.user_data_dir(app_name, app_author)) / "tuf"
    tuf_cache_dir = Path(platformdirs.user_cache_dir(app_name, app_author)) / "tuf"

    return (tuf_data_dir / repo_base), (tuf_cache_dir / repo_base)


class TrustUpdater:
    """Internal trust root (certificates and keys) downloader.

    TrustUpdater discovers the currently valid certificates and keys and
    securely downloads them from the remote TUF repository at 'url'.

    TrustUpdater expects to find an initial root.json in either the local
    metadata directory for this URL, or (as special case for the sigstore.dev
    production and staging instances) in the application resources.
    """

    def __init__(
        self, url: str, offline: bool = False, bootstrap_root: Path | None = None
    ) -> None:
        """
        Create a new `TrustUpdater`, pulling from the given `url`.

        TrustUpdater expects that either embedded data contains
        a root.json for this url or that `bootstrap_root` is provided as argument.

        If not `offline`, TrustUpdater will update the TUF metadata from
        the remote repository.
        """
        # not canonicalization, just handling trailing slash as common mistake:
        url = url.rstrip("/")

        self._metadata_dir, self._targets_dir = _get_dirs(url)

        # Populate targets cache so we don't have to download these versions
        self._targets_dir.mkdir(parents=True, exist_ok=True)

        for artifact in ["trusted_root.json", "signing_config.v0.2.json"]:
            artifact_path = self._targets_dir / artifact
            if not artifact_path.exists():
                try:
                    data = read_embedded(artifact, url)
                    artifact_path.write_bytes(data)
                except FileNotFoundError:
                    pass  # this is ok: we only have embedded data for specific repos

        _logger.debug(f"TUF metadata: {self._metadata_dir}")
        _logger.debug(f"TUF targets cache: {self._targets_dir}")

        self._updater: Updater | None = None
        if offline:
            _logger.warning(
                "TUF repository is loaded in offline mode; updates will not be performed"
            )
        else:
            # Initialize and update the toplevel TUF metadata
            try:
                root_json: bytes | None = read_embedded("root.json", url)
            except FileNotFoundError:
                # We do not have embedded root metadata for this URL: we can still
                # initialize _if_ given bootstrap root (i.e. during "sigstore trust-instance")
                # or local metadata exists already (after "sigstore trust-instance")
                root_json = bootstrap_root.read_bytes() if bootstrap_root else None

            try:
                self._updater = Updater(
                    metadata_dir=str(self._metadata_dir),
                    metadata_base_url=url,
                    target_base_url=parse.urljoin(f"{url}/", "targets/"),
                    target_dir=str(self._targets_dir),
                    config=UpdaterConfig(
                        app_user_agent=f"sigstore-python/{__version__}"
                    ),
                    bootstrap=root_json,
                )
                self._updater.refresh()
            except Exception as e:
                raise TUFError("Failed to refresh TUF metadata") from e

    @lru_cache()
    def get_trusted_root_path(self) -> str:
        """Return local path to currently valid trusted root file"""
        if not self._updater:
            _logger.debug("Using unverified trusted root from cache")
            return str(self._targets_dir / "trusted_root.json")

        root_info = self._updater.get_targetinfo("trusted_root.json")
        if root_info is None:
            raise TUFError("Unsupported TUF configuration: no trusted root")
        path = self._updater.find_cached_target(root_info)
        if path is None:
            try:
                path = self._updater.download_target(root_info)
            except (
                TUFExceptions.DownloadError,
                TUFExceptions.RepositoryError,
            ) as e:
                raise TUFError("Failed to download trusted key bundle") from e

        _logger.debug("Found and verified trusted root")
        return path

    @lru_cache()
    def get_signing_config_path(self) -> str:
        """Return local path to currently valid signing config file"""
        if not self._updater:
            _logger.debug("Using unverified signing config from cache")
            return str(self._targets_dir / "signing_config.v0.2.json")

        root_info = self._updater.get_targetinfo("signing_config.v0.2.json")
        if root_info is None:
            raise TUFError("Unsupported TUF configuration: no signing config")
        path = self._updater.find_cached_target(root_info)
        if path is None:
            try:
                path = self._updater.download_target(root_info)
            except (
                TUFExceptions.DownloadError,
                TUFExceptions.RepositoryError,
            ) as e:
                raise TUFError("Failed to download signing config") from e

        _logger.debug("Found and verified signing config")
        return path
