# Copyright 2026 The Sigstore Authors
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
Client implementation for interacting with Rekor v2 identity transparency logs
(`serve-identity`).
"""

from __future__ import annotations

import base64
import logging

import urllib3
from sigstore_models.rekor.v2.identity import (
    IdentityRequestV001,
    OidcCredential,
    PublicKeyCredential,
)

from sigstore._internal import DEFAULT_RETRIES, USER_AGENT
from sigstore._internal.c2sp.checkpoint import SignedCheckpoint
from sigstore._internal.c2sp.proof import TLogProof
from sigstore._internal.rekor import (
    DEFAULT_REKOR_TIMEOUT,
    RekorClientError,
)
from sigstore.errors import VerificationError
from sigstore.oidc import IdentityToken

_logger = logging.getLogger(__name__)


class IdentityRekorClient:
    """
    The internal Rekor client for the v2 identity transparency log API
    (`serve-identity`).
    """

    def __init__(self, base_url: str) -> None:
        """
        Create a new `IdentityRekorClient` from the given base URL.
        """
        # SigningConfig identifies the serve-identity API with majorApiVersion == 3,
        # while the HTTP endpoint path in rekor-tiles remains /api/v2/log/entries.
        self.url = f"{base_url.rstrip('/')}/api/v2"
        self._http = urllib3.PoolManager(
            headers={
                "Content-Type": "application/json",
                "Accept": "text/plain",
                "User-Agent": USER_AGENT,
            },
            retries=DEFAULT_RETRIES,
            timeout=DEFAULT_REKOR_TIMEOUT,
            maxsize=32,
        )

    def _create_entry(self, request: IdentityRequestV001) -> TLogProof:
        """
        Submit an `IdentityRequestV001` to the identity transparency log and
        return the parsed `TLogProof`.

        `_create_entry()` can be called from multiple threads.
        """
        try:
            resp = self._http.request(
                "POST",
                f"{self.url}/log/entries",
                json=request.to_dict(),
                redirect=False,
            )
        except urllib3.exceptions.HTTPError as http_error:
            raise RekorClientError.from_http_error(http_error) from http_error

        if not (200 <= resp.status < 300):
            raise RekorClientError.from_response(resp)

        try:
            proof = TLogProof.from_bytes(resp.data)
            SignedCheckpoint.from_bytes(proof.checkpoint)
            proof.decode_extra_claims()
        except VerificationError as exc:
            raise RekorClientError(
                f"Invalid tlog-proof response from Rekor: {exc}"
            ) from exc

        _logger.debug(f"Transparency log entry created with index: {proof.index}")
        return proof

    def create_oidc_entry(
        self,
        digest: bytes,
        token: IdentityToken,
    ) -> TLogProof:
        """
        Construct and submit an OIDC `IdentityRequestV001` for `digest` and `token`.

        Can be called from multiple threads.
        """
        if len(digest) != 32:
            raise ValueError(
                f"IdentityRequestV001 digest must be 32 bytes, got {len(digest)}"
            )
        token_str = str(token)
        if not token_str:
            raise ValueError("OidcCredential token must not be empty")

        request = IdentityRequestV001(
            message=base64.b64encode(digest),
            oidc=OidcCredential(token=token_str),
        )
        return self._create_entry(request)

    def create_public_key_entry(
        self,
        digest: bytes,
        public_key_spki: bytes,
        signature: bytes,
        *,
        context: bytes | None = None,
    ) -> TLogProof:
        """
        Construct and submit a public-key `IdentityRequestV001` for `digest`,
        `public_key_spki` (SPKI DER bytes), `signature`, and optional 32-byte `context`.

        Can be called from multiple threads.
        """
        if len(digest) != 32:
            raise ValueError(
                f"IdentityRequestV001 digest must be 32 bytes, got {len(digest)}"
            )
        if not public_key_spki:
            raise ValueError("PublicKeyCredential public_key_spki must not be empty")
        if not signature:
            raise ValueError("PublicKeyCredential signature must not be empty")
        if context is not None and len(context) != 32:
            raise ValueError(
                f"PublicKeyCredential context must be 32 bytes, got {len(context)}"
            )

        request = IdentityRequestV001(
            message=base64.b64encode(digest),
            public_key=PublicKeyCredential(
                public_key=base64.b64encode(public_key_spki),
                signature=base64.b64encode(signature),
                context=base64.b64encode(context) if context is not None else None,
            ),
        )
        return self._create_entry(request)
