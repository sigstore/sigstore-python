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

from __future__ import annotations

import base64
import datetime
import os
import re
from collections import defaultdict
from collections.abc import Iterator
from io import BytesIO
from pathlib import Path
from typing import Callable
from urllib.parse import urlparse

import jwt
import pytest
from cryptography.x509 import Certificate, load_pem_x509_certificate
from id import (
    detect_credential,
)
from tuf.api.exceptions import DownloadHTTPError
from tuf.ngclient import FetcherInterface, updater

from sigstore._internal import tuf
from sigstore._internal.rekor import _hashedrekord_from_parts
from sigstore._internal.rekor.client import RekorClient
from sigstore._utils import sha256_digest
from sigstore.models import Bundle, ClientTrustConfig
from sigstore.oidc import IdentityToken
from sigstore.sign import SigningContext
from sigstore.verify.verifier import Verifier

_TUF_ASSETS = (Path(__file__).parent.parent / "assets" / "staging-tuf").resolve()
assert _TUF_ASSETS.is_dir()

TEST_CLIENT_ID = "sigstore"


@pytest.fixture
def x509_testcase(asset):
    def _x509_testcase(name: str) -> Certificate:
        pem = asset(f"x509/{name}").read_bytes()
        return load_pem_x509_certificate(pem)

    return _x509_testcase


@pytest.fixture
def tuf_asset():
    SHA256_TARGET_PATTERN = re.compile(r"[0-9a-f]{64}\.")

    class TUFAsset:
        def asset(self, name: str):
            return (_TUF_ASSETS / name).read_bytes()

        def target(self, name: str):
            path = self.target_path(name)
            return path.read_bytes() if path else None

        def target_path(self, name: str) -> Path:
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
                return path
            return None

    return TUFAsset()


@pytest.fixture
def signing_materials(asset) -> Callable[[str, RekorClient], tuple[Path, Bundle]]:
    # NOTE: Unlike `signing_bundle`, `signing_materials` requires a
    # Rekor client to retrieve its entry with.
    def _signing_materials(name: str, client: RekorClient) -> tuple[Path, Bundle]:
        file = asset(name)
        cert_path = asset(f"{name}.crt")
        sig_path = asset(f"{name}.sig")

        cert = load_pem_x509_certificate(cert_path.read_bytes())
        sig = base64.b64decode(sig_path.read_text())
        with file.open(mode="rb") as io:
            hashed = sha256_digest(io)

        entry = client.log.entries.retrieve.post(
            _hashedrekord_from_parts(cert, sig, hashed)
        )

        bundle = Bundle.from_parts(cert, sig, entry)

        return (file, bundle)

    return _signing_materials


@pytest.fixture
def signing_bundle(asset) -> Callable[[str], tuple[Path, Bundle]]:
    def _signing_bundle(name: str) -> tuple[Path, Bundle]:
        file = asset(name)
        bundle_path = asset(f"{name}.sigstore")
        if not bundle_path.is_file():
            bundle_path = asset(f"{name}.sigstore.json")
        bundle = Bundle.from_json(bundle_path.read_bytes())

        return (file, bundle)

    return _signing_bundle


@pytest.fixture
def null_policy():
    class NullPolicy:
        def verify(self, cert):
            return

    return NullPolicy()


@pytest.fixture
def mock_staging_tuf(monkeypatch, tuf_dirs):
    """Mock that prevents python-tuf from making requests: it returns staging
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

    monkeypatch.setattr(updater, "Urllib3Fetcher", lambda app_user_agent: MockFetcher())

    # Using the staging TUF assets is a nice way to test but staging tuf assets expire in
    # 3 days so faking now() becomes necessary. This correctly affects checks in
    # _internal/trust.py as well
    class mydatetime(datetime.datetime):
        @classmethod
        def now(cls, tz=None):
            return datetime.datetime(2025, 5, 6, 0, 0, 0, 0, datetime.timezone.utc)

    monkeypatch.setattr(datetime, "datetime", mydatetime)

    return success, failure


@pytest.fixture
def tuf_dirs(monkeypatch, tmp_path):
    # Patch _get_dirs as well, to avoid polluting the user's actual cache
    # with test assets.
    data_dir = tmp_path / "data" / "tuf"
    cache_dir = tmp_path / "cache" / "tuf"
    monkeypatch.setattr(tuf, "_get_dirs", lambda u: (data_dir, cache_dir))

    return (data_dir, cache_dir)


@pytest.fixture
def sign_ctx_and_ident_for_env(
    pytestconfig,
    env: str,
) -> tuple[type[SigningContext], type[IdentityToken]]:
    """
    Returns a SigningContext and IdentityToken for the given environment.
    The SigningContext is behind a callable so that it may be lazily evaluated.
    """
    if env == "staging":

        def ctx_cls():
            return SigningContext.from_trust_config(ClientTrustConfig.staging())

    elif env == "production":

        def ctx_cls():
            return SigningContext.from_trust_config(ClientTrustConfig.production())

    else:
        raise ValueError(f"Unknown env {env}")

    token = os.getenv(f"SIGSTORE_IDENTITY_TOKEN_{env}")
    if not token:
        # If the variable is not defined, try getting an ambient token.
        token = detect_credential(TEST_CLIENT_ID)

    return ctx_cls, IdentityToken(token)


@pytest.fixture
def staging() -> tuple[type[SigningContext], type[Verifier], IdentityToken]:
    """
    Returns a SigningContext, Verifier, and IdentityToken for the staging environment.
    The SigningContext and Verifier are both behind callables so that they may be lazily evaluated.
    """

    def signer():
        return SigningContext.from_trust_config(ClientTrustConfig.staging())

    verifier = Verifier.staging

    # Detect env variable for local interactive tests.
    token = os.getenv("SIGSTORE_IDENTITY_TOKEN_staging")
    if not token:
        # If the variable is not defined, try getting an ambient token.
        token = detect_credential(TEST_CLIENT_ID)

    return signer, verifier, IdentityToken(token)


@pytest.fixture
def dummy_jwt():
    def _dummy_jwt(claims: dict):
        return jwt.encode(claims, key="definitely not secure")

    return _dummy_jwt


@pytest.fixture
def tsa_url():
    """Return the URL of the TSA"""
    return os.getenv("TEST_SIGSTORE_TIMESTAMP_AUTHORITY_URL")
