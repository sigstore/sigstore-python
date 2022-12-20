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

import logging
import shutil
from importlib import resources
from pathlib import Path
from typing import List, Optional, Tuple
from urllib import parse

from tuf.ngclient import Updater

logger = logging.getLogger(__name__)

DEFAULT_TUF_URL = "https://sigstore-tuf-root.storage.googleapis.com/"
STAGING_TUF_URL = "https://tuf-root-staging.storage.googleapis.com/"


def _get_dirs(url: str) -> Tuple[Path, Path]:
    """Return metadata dir and target cache dir for URL"""
    # NOTE: this is not great for windows: should maybe depend on appdirs?
    # TODO: there should be URL normalization if URLs come from user
    dir = parse.quote(url, safe="")
    md_dir = Path.home() / ".local" / "share" / "sigstore-python" / "tuf" / dir
    targets_dir = Path.home() / ".cache" / "sigstore-python" / "tuf" / dir
    return md_dir, targets_dir


class TrustUpdater:
    def __init__(self, url: str) -> None:
        self._repo_url = url
        self._updater: Optional[Updater] = None

        self._metadata_dir, self._targets_dir = _get_dirs(url)

        # intialize metadata dir
        tuf_root = self._metadata_dir / "root.json"
        if not tuf_root.exists():
            if self._repo_url == DEFAULT_TUF_URL:
                fname = "root.json"
            elif self._repo_url == STAGING_TUF_URL:
                fname = "staging-root.json"
            else:
                raise Exception(f"TUF root not found in {tuf_root}")

            self._metadata_dir.mkdir(parents=True, exist_ok=True)
            with resources.path("sigstore._store", fname) as res:
                shutil.copy2(res, tuf_root)

        # intialize targets cache dir
        # TODO: Pre-populate with any targets we ship with sources
        self._targets_dir.mkdir(parents=True, exist_ok=True)

        logger.debug("TUF metadata: %s", self._metadata_dir)
        logger.debug("TUF targets cache: %s", self._targets_dir)

    @classmethod
    def production(cls) -> "TrustUpdater":
        return cls(DEFAULT_TUF_URL)

    @classmethod
    def staging(cls) -> "TrustUpdater":
        return cls(STAGING_TUF_URL)

    def _setup(self) -> "Updater":
        """Initialize and update the toplevel TUF metadata"""
        updater = Updater(
            metadata_dir=str(self._metadata_dir),
            metadata_base_url=f"{self._repo_url}",
            target_base_url=f"{self._repo_url}targets/",
            target_dir=str(self._targets_dir),
        )

        # NOTE: we would like to avoid refresh if the toplevel metadata is valid.
        # https://github.com/theupdateframework/python-tuf/issues/2225
        updater.refresh()
        return updater

    def get_ctfe_keys(self) -> List[bytes]:
        """Return the active CTFE public keys contents"""
        if not self._updater:
            self._updater = self._setup()

        ctfes = []
        assert self._updater._trusted_set.targets
        targets = self._updater._trusted_set.targets.signed.targets
        for target_info in targets.values():
            custom = target_info.unrecognized_fields["custom"]["sigstore"]
            if custom["status"] == "Active" and custom["usage"] == "CTFE":
                path = self._updater.find_cached_target(target_info)
                if path is None:
                    path = self._updater.download_target(target_info)
                with open(path, "rb") as f:
                    ctfes.append(f.read())

        if not ctfes:
            raise Exception("CTFE keys not found in TUF metadata")

        return ctfes

    def get_rekor_key(self) -> bytes:
        """Return the rekor public key content"""
        if not self._updater:
            self._updater = self._setup()

        assert self._updater._trusted_set.targets
        targets = self._updater._trusted_set.targets.signed.targets
        for target, target_info in targets.items():
            custom = target_info.unrecognized_fields["custom"]["sigstore"]
            if custom["status"] == "Active" and custom["usage"] == "Rekor":
                path = self._updater.find_cached_target(target_info)
                if path is None:
                    path = self._updater.download_target(target_info)
                with open(path, "rb") as f:
                    return f.read()

        raise Exception("Rekor key not found in TUF metadata")

    def get_fulcio_certs(self) -> List[bytes]:
        """Return the active Fulcio certificate contents"""
        if not self._updater:
            self._updater = self._setup()

        certs = []
        assert self._updater._trusted_set.targets
        targets = self._updater._trusted_set.targets.signed.targets
        for target_info in targets.values():
            custom = target_info.unrecognized_fields["custom"]["sigstore"]
            if custom["status"] == "Active" and custom["usage"] == "Fulcio":
                path = self._updater.find_cached_target(target_info)
                if path is None:
                    path = self._updater.download_target(target_info)
                with open(path, "rb") as f:
                    certs.append(f.read())

        if not certs:
            raise Exception("Fulcio certificates not found in TUF metadata")

        return certs
