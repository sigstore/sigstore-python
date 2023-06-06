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

import base64
import os
import re
from collections import defaultdict
from io import BytesIO
from pathlib import Path
from typing import Iterator
from urllib.parse import urlparse

import jwt
import pytest
from cryptography.x509 import Certificate, load_pem_x509_certificate
from id import (
    AmbientCredentialError,
    GitHubOidcPermissionCredentialError,
    detect_credential,
)
from sigstore_protobuf_specs.dev.sigstore.bundle.v1 import Bundle
from tuf.api.exceptions import DownloadHTTPError
from tuf.ngclient import FetcherInterface

from sigstore._internal import tuf
from sigstore.oidc import _DEFAULT_AUDIENCE, IdentityToken
from sigstore.sign import SigningContext
from sigstore.verify import VerificationMaterials
from sigstore.verify.policy import VerificationSuccess

_ASSETS = (Path(__file__).parent / "assets").resolve()
assert _ASSETS.is_dir()

_TUF_ASSETS = (_ASSETS / "staging-tuf").resolve()
assert _TUF_ASSETS.is_dir()


def _has_oidc_id():
    # If there are tokens manually defined for us in the environment, use them.
    if os.getenv("SIGSTORE_IDENTITY_TOKEN_production") is not None:
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


def pytest_runtest_setup(item):
    if "online" in item.keywords and item.config.getoption("--skip-online"):
        pytest.skip(
            "skipping test that requires network connectivity due to `--skip-online` flag"
        )
    elif "ambient_oidc" in item.keywords and not _has_oidc_id():
        pytest.skip("skipping test that requires an ambient OIDC credential")


def pytest_configure(config):
    config.addinivalue_line(
        "markers", "online: mark test as requiring network connectivity"
    )
    config.addinivalue_line(
        "markers", "ambient_oidc: mark test as requiring an ambient OIDC identity"
    )


@pytest.fixture
def asset():
    def _asset(name: str) -> Path:
        return _ASSETS / name

    return _asset


@pytest.fixture
def x509_testcase():
    def _x509_testcase(name: str) -> Certificate:
        pem = (_ASSETS / "x509" / name).read_bytes()
        return load_pem_x509_certificate(pem)

    return _x509_testcase


@pytest.fixture
def tuf_asset():
    SHA256_TARGET_PATTERN = re.compile(r"[0-9a-f]{64}\.")

    class TUFAsset:
        def asset(self, name: str):
            return (_TUF_ASSETS / name).read_bytes()

        def target(self, name: str):
            # Since TUF contains both sha256 and sha512 prefixed targets, filter
            # out the sha512 ones.
            matches = filter(
                lambda path: SHA256_TARGET_PATTERN.match(path.name) is not None,
                (_TUF_ASSETS / "targets").glob(f"*.{name}"),
            )

            try:
                path = next(matches)
            except StopIteration as e:
                raise Exception(f"Unable to match {name} in targets/") from e

            if next(matches, None) is None:
                return path.read_bytes()
            return None

    return TUFAsset()


@pytest.fixture
def signing_materials():
    def _signing_materials(name: str, offline: bool = False) -> VerificationMaterials:
        file = _ASSETS / name
        cert = _ASSETS / f"{name}.crt"
        sig = _ASSETS / f"{name}.sig"

        with file.open(mode="rb", buffering=0) as io:
            materials = VerificationMaterials(
                input_=io,
                cert_pem=cert.read_text(),
                signature=base64.b64decode(sig.read_text()),
                offline=offline,
                rekor_entry=None,
            )

        return materials

    return _signing_materials


@pytest.fixture
def signing_bundle():
    def _signing_bundle(name: str, *, offline: bool = False) -> VerificationMaterials:
        file = _ASSETS / name
        bundle = _ASSETS / f"{name}.sigstore"
        bundle = Bundle().from_json(bundle.read_bytes())

        with file.open(mode="rb", buffering=0) as io:
            materials = VerificationMaterials.from_bundle(
                input_=io, bundle=bundle, offline=offline
            )

        return materials

    return _signing_bundle


@pytest.fixture
def null_policy():
    class NullPolicy:
        def verify(self, cert):
            return VerificationSuccess()

    return NullPolicy()


@pytest.fixture
def mock_staging_tuf(monkeypatch, tuf_dirs):
    """Mock that prevents tuf module from making requests: it returns staging
    assets from a local directory instead

    Return a tuple of dicts with the requested files and counts"""

    success = defaultdict(int)
    failure = defaultdict(int)

    class MockFetcher(FetcherInterface):
        def _fetch(self, url: str) -> Iterator[bytes]:
            filepath = _TUF_ASSETS / urlparse(url).path.lstrip("/")
            filename = filepath.name
            if filepath.is_file():
                success[filename] += 1
                return BytesIO(filepath.read_bytes())

            failure[filename] += 1
            raise DownloadHTTPError("File not found", 404)

    monkeypatch.setattr(tuf, "_get_fetcher", lambda: MockFetcher())

    return success, failure


@pytest.fixture
def tuf_dirs(monkeypatch, tmp_path):
    # Patch _get_dirs as well, to avoid polluting the user's actual cache
    # with test assets.
    data_dir = tmp_path / "data" / "tuf"
    cache_dir = tmp_path / "cache" / "tuf"
    monkeypatch.setattr(tuf, "_get_dirs", lambda u: (data_dir, cache_dir))

    return (data_dir, cache_dir)


@pytest.fixture(
    params=[
        ("production", SigningContext.production),
        ("staging", SigningContext.staging),
    ],
    ids=["production", "staging"],
)
def id_config(request):
    env, signer = request.param
    # Detect env variable for local interactive tests.
    token = os.getenv(f"SIGSTORE_IDENTITY_TOKEN_{env}")
    if not token:
        # If the variable is not defined, try getting an ambient token.
        token = detect_credential(_DEFAULT_AUDIENCE)

    return signer, IdentityToken(token)


@pytest.fixture
def dummy_jwt():
    def _dummy_jwt(claims: dict):
        return jwt.encode(claims, key="definitely not secure")

    return _dummy_jwt
