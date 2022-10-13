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

from pathlib import Path
from typing import Tuple

import pytest

_ASSETS = (Path(__file__).parent / "assets").resolve()
assert _ASSETS.is_dir()


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


def pytest_configure(config):
    config.addinivalue_line(
        "markers", "online: mark test as requiring network connectivity"
    )


@pytest.fixture
def asset():
    def _asset(name: str) -> Path:
        return _ASSETS / name

    return _asset


@pytest.fixture
def signed_asset():
    def _signed_asset(name: str) -> Tuple[bytes, bytes, bytes]:
        file = _ASSETS / name
        cert = _ASSETS / f"{name}.crt"
        sig = _ASSETS / f"{name}.sig"
        bundle = _ASSETS / f"{name}.rekor"

        bundle_bytes = None
        if bundle.is_file():
            bundle_bytes = bundle.read_bytes()

        return (
            file.read_bytes(),
            cert.read_bytes().rstrip(),
            sig.read_bytes().rstrip(),
            bundle_bytes,
        )

    return _signed_asset
