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
Ambient OIDC credential detection for sigstore.
"""

import logging
import os
from typing import Callable, List, Optional

import requests
from pydantic import BaseModel

from sigstore._internal.oidc import IdentityError

logger = logging.getLogger(__name__)


class AmbientCredentialError(IdentityError):
    """
    Raised when an ambient credential should be present, but
    can't be retrieved (e.g. network failure).
    """

    pass


def detect_credential() -> Optional[str]:
    """
    Try each ambient credential detector, returning the first one to succeed
    or `None` if all fail.

    Raises `AmbientCredentialError` if any detector fails internally (i.e.
    detects a credential, but cannot retrieve it).
    """
    detectors: List[Callable[..., Optional[str]]] = [detect_github]
    for detector in detectors:
        credential = detector()
        if credential is not None:
            return credential
    return None


class _GitHubTokenPayload(BaseModel):
    """
    A trivial model for GitHub's OIDC token endpoint payload.

    This exists solely to provide nice error handling.
    """

    value: str


def detect_github() -> Optional[str]:
    logger.debug("GitHub: looking for OIDC credentials")
    if not os.getenv("GITHUB_ACTIONS"):
        logger.debug("GitHub: environment doesn't look like a GH action; giving up")
        return None

    # If we're running on a GitHub Action, we need to issue a GET request
    # to a special URL with a special bearer token. Both are stored in
    # the environment and are only present if the workflow has sufficient permissions.
    req_token = os.getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
    req_url = os.getenv("ACTIONS_ID_TOKEN_REQUEST_URL")
    if not req_token or not req_url:
        raise AmbientCredentialError(
            "GitHub: missing or insufficient OIDC token permissions?"
        )

    resp = requests.get(
        req_url,
        params={"audience": "sigstore"},
        headers={"Authorization": f"bearer {req_token}"},
    )
    try:
        resp.raise_for_status()
    except requests.HTTPError as http_error:
        raise AmbientCredentialError(
            f"GitHub: OIDC token request failed (code={resp.status_code})"
        ) from http_error

    try:
        body = resp.json()
        return _GitHubTokenPayload(**body).value
    except Exception as e:
        raise AmbientCredentialError("GitHub: malformed or incomplete JSON") from e
