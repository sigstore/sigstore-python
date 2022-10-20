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

import os
from pathlib import Path
from typing import Tuple

import pytest

from sigstore._internal.oidc.ambient import (
    AmbientCredentialError,
    GitHubOidcPermissionCredentialError,
    detect_credential,
)

_ASSETS = (Path(__file__).parent / "assets").resolve()
assert _ASSETS.is_dir()


def _is_ambient_env():
    try:
        token = detect_credential()
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


def pytest_runtest_setup(item):
    if "online" in item.keywords and item.config.getoption("--skip-online"):
        pytest.skip(
            "skipping test that requires network connectivity due to `--skip-online` flag"
        )
    elif "ambient_oidc" in item.keywords and not _is_ambient_env():
        pytest.skip("skipping test that requires an ambient OIDC credential")


def pytest_configure(config):
    config.addinivalue_line(
        "markers", "online: mark test as requiring network connectivity"
    )
    config.addinivalue_line(
        "markers", "ambient_oidc: mark test as requiring an ambient OIDC identity"
    )


@pytest.fixture
def signed_asset():
    def _signed_asset(name: str) -> Tuple[bytes, bytes, bytes]:
        file = _ASSETS / name
        cert = _ASSETS / f"{name}.crt"
        sig = _ASSETS / f"{name}.sig"

        return (file.read_bytes(), cert.read_bytes(), sig.read_bytes())

    return _signed_asset
