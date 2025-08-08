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
Client trust configuration for sigstore-python.
"""

from __future__ import annotations

import logging
from enum import Enum
from pathlib import Path

from sigstore_protobuf_specs.dev.sigstore.trustroot.v1 import (
    ClientTrustConfig as _ClientTrustConfig,
)
from sigstore_protobuf_specs.dev.sigstore.trustroot.v1 import (
    SigningConfig as _SigningConfig,
)
from sigstore_protobuf_specs.dev.sigstore.trustroot.v1 import (
    TrustedRoot as _TrustedRoot,
)

from sigstore._internal.trust import SigningConfig, TrustedRoot
from sigstore._internal.tuf import DEFAULT_TUF_URL, STAGING_TUF_URL, TrustUpdater
from sigstore._utils import (
    read_embedded,
)
from sigstore.errors import Error, TUFError

_logger = logging.getLogger(__name__)


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
