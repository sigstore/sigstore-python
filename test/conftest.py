# Copyright 2024 The Sigstore Authors
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

import os

import pytest
from id import (
    AmbientCredentialError,
    GitHubOidcPermissionCredentialError,
    detect_credential,
)

from sigstore.oidc import _DEFAULT_AUDIENCE


def _has_oidc_id():
    # If there are tokens manually defined for us in the environment, use them.
    if os.getenv("SIGSTORE_IDENTITY_TOKEN_production") or os.getenv(
        "SIGSTORE_IDENTITY_TOKEN_staging"
    ):
        return True

    try:
        token = detect_credential(_DEFAULT_AUDIENCE)
        if token is None:
            return False
    except GitHubOidcPermissionCredentialError:
        # On GitHub Actions, forks do not have access to OIDC identities.
        # We differentiate this case from other GitHub credential errors,
        # since it's a case where we want to skip (i.e. return False).
        if os.getenv("GITHUB_EVENT_NAME") == "pull_request":
            return False
        return True
    except AmbientCredentialError:
        # If ambient credential detection raises, then we *are* in an ambient
        # environment but one that's been configured incorrectly. We
        # pass this through, so that the CI fails appropriately rather than
        # silently skipping the faulty tests.
        return True

    return True


def pytest_addoption(parser):
    parser.addoption(
        "--skip-online",
        action="store_true",
        help="skip tests that require network connectivity",
    )
    parser.addoption(
        "--skip-staging",
        action="store_true",
        help="skip tests that require Sigstore staging infrastructure",
    )


def pytest_runtest_setup(item):
    # Do we need a network connection?
    online = False
    for mark in ["online", "staging", "production"]:
        if mark in item.keywords:
            online = True

    if online and item.config.getoption("--skip-online"):
        pytest.skip(
            "skipping test that requires network connectivity due to `--skip-online` flag"
        )
    elif "ambient_oidc" in item.keywords and not _has_oidc_id():
        pytest.skip("skipping test that requires an ambient OIDC credential")

    if "staging" in item.keywords and item.config.getoption("--skip-staging"):
        pytest.skip(
            "skipping test that requires staging infrastructure due to `--skip-staging` flag"
        )


def pytest_configure(config):
    config.addinivalue_line(
        "markers", "staging: mark test as requiring Sigstore staging infrastructure"
    )
    config.addinivalue_line(
        "markers",
        "production: mark test as requiring Sigstore production infrastructure",
    )
    config.addinivalue_line(
        "markers",
        "online: mark test as requiring network connectivity (but not a specific Sigstore infrastructure)",
    )
    config.addinivalue_line(
        "markers", "ambient_oidc: mark test as requiring an ambient OIDC identity"
    )
