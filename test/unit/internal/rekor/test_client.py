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

import json
import unittest.mock
from collections.abc import Callable
from typing import Any

import pytest
import urllib3

from sigstore._internal import DEFAULT_RETRIES
from sigstore._internal.rekor import (
    DEFAULT_REKOR_TIMEOUT,
    EntryRequestBody,
    RekorClientError,
)
from sigstore._internal.rekor.client import RekorClient
from sigstore._internal.rekor.client_v2 import RekorV2Client
from sigstore.models import TransparencyLogEntry


def _mock_make_request(
    monkeypatch: pytest.MonkeyPatch,
    handler: Callable[[str, str], urllib3.HTTPResponse],
) -> list[tuple[str, str]]:
    """
    Patch urllib3.HTTPConnectionPool._make_request so that PoolManager.request()
    and HTTPConnectionPool.urlopen() execute the real urllib3.Retry loop without
    opening any sockets.
    """
    requests_seen: list[tuple[str, str]] = []

    def _fake_make_request(
        self: urllib3.HTTPConnectionPool,
        conn: Any,
        method: str,
        url: str,
        body: Any = None,
        headers: Any = None,
        retries: urllib3.Retry | None = None,
        **kwargs: Any,
    ) -> urllib3.HTTPResponse:
        requests_seen.append((method, url))
        resp = handler(method, url)
        resp.retries = retries
        return resp

    monkeypatch.setattr(urllib3.HTTPConnectionPool, "_make_request", _fake_make_request)
    return requests_seen


def test_default_rekor_retries_configuration():
    """Verify the shared urllib3.Retry and Timeout configuration for Rekor clients."""
    for client in (RekorClient("http://fake"), RekorV2Client("http://fake")):
        retries = client._http.connection_pool_kw["retries"]
        assert retries is DEFAULT_RETRIES
        assert retries.connect == 2
        assert retries.read == 1
        assert retries.status == 2
        assert retries.allowed_methods == frozenset(["GET", "POST"])
        assert retries.status_forcelist == frozenset([408, 429, 500, 502, 503, 504])
        assert retries.respect_retry_after_header is True
        assert retries.raise_on_status is False
        assert retries.backoff_factor == 1.0
        assert retries.backoff_jitter == 0.5

        timeout = client._http.connection_pool_kw["timeout"]
        assert timeout is DEFAULT_REKOR_TIMEOUT
        assert timeout.connect_timeout == 5
        assert timeout.read_timeout == 60
        assert client._http.connection_pool_kw["maxsize"] == 32


def test_rekor_v1_post_retries_on_503_and_handles_409_conflict(monkeypatch):
    """
    Simulate Rekor returning 503 first while creating the entry, followed by a
    retry that receives 409 Conflict with a Location header, and fetches the
    entry via GET.
    """
    monkeypatch.setattr("urllib3.util.retry.time.sleep", lambda _: None)

    expected_uuid = "24296fb24b8ad77a1234567890abcdef"
    sentinel_entry = unittest.mock.MagicMock(spec=TransparencyLogEntry)
    monkeypatch.setattr(
        TransparencyLogEntry,
        "_from_v1_response",
        lambda data: sentinel_entry if expected_uuid in data else None,
    )

    responses = iter(
        [
            urllib3.HTTPResponse(body=b"Service Unavailable", status=503),
            urllib3.HTTPResponse(
                body=json.dumps(
                    {
                        "code": 409,
                        "message": f"an equivalent entry already exists in the transparency log with UUID {expected_uuid}",
                    }
                ).encode(),
                headers={
                    "Content-Type": "application/json",
                    "Location": f"/api/v1/log/entries/{expected_uuid}",
                },
                status=409,
            ),
            urllib3.HTTPResponse(
                body=json.dumps({expected_uuid: {"logIndex": 1}}).encode(),
                headers={"Content-Type": "application/json"},
                status=200,
            ),
        ]
    )

    requests_seen = _mock_make_request(monkeypatch, lambda _m, _u: next(responses))

    client = RekorClient("http://fake")
    entry = client.create_entry(EntryRequestBody({"kind": "hashedrekord"}))

    assert entry is sentinel_entry
    assert requests_seen == [
        ("POST", "/api/v1/log/entries"),
        ("POST", "/api/v1/log/entries"),
        ("GET", f"/api/v1/log/entries/{expected_uuid}"),
    ]


@pytest.mark.parametrize("client_cls", [RekorClient, RekorV2Client])
def test_rekor_post_503_exhausts_retries_after_three_attempts(monkeypatch, client_cls):
    """
    Verify that persistent 503 responses are retried twice (3 attempts total)
    before failing with RekorClientError.
    """
    slept: list[float] = []
    monkeypatch.setattr("urllib3.util.retry.time.sleep", lambda s: slept.append(s))

    requests_seen = _mock_make_request(
        monkeypatch,
        lambda _m, _u: urllib3.HTTPResponse(body=b"Service Unavailable", status=503),
    )

    client = client_cls("http://fake")
    with pytest.raises(RekorClientError, match="Rekor returned an error with HTTP 503"):
        client.create_entry(EntryRequestBody({"kind": "hashedrekord"}))

    assert len(requests_seen) == 3
    assert len(slept) == 1
    assert 2.0 <= slept[0] <= 2.5


@pytest.mark.parametrize("headers", [{}, {"Location": "/"}, {"Location": "/not-hex!"}])
def test_rekor_v1_post_409_without_valid_location_raises(monkeypatch, headers):
    """Verify that a 409 response without a valid hex UUID Location header raises RekorClientError."""
    client = RekorClient("http://fake")
    resp = urllib3.HTTPResponse(
        body=json.dumps({"code": 409, "message": "conflict"}).encode(),
        headers={"Content-Type": "application/json", **headers},
        status=409,
    )
    _mock_make_request(monkeypatch, lambda _m, _u: resp)
    with pytest.raises(RekorClientError, match="409: conflict"):
        client.create_entry(EntryRequestBody({}))


def test_rekor_retry_after_header_respected(monkeypatch):
    """Verify that Retry-After header is respected on 429/503 responses."""
    slept: list[float] = []
    monkeypatch.setattr("urllib3.util.retry.time.sleep", lambda s: slept.append(s))

    sentinel_entry = unittest.mock.MagicMock(spec=TransparencyLogEntry)
    monkeypatch.setattr(
        TransparencyLogEntry,
        "_from_v1_response",
        lambda _: sentinel_entry,
    )

    responses = iter(
        [
            urllib3.HTTPResponse(headers={"Retry-After": "3"}, status=429),
            urllib3.HTTPResponse(
                body=json.dumps({"uuid": {}}).encode(),
                headers={"Content-Type": "application/json"},
                status=201,
            ),
        ]
    )

    requests_seen = _mock_make_request(monkeypatch, lambda _m, _u: next(responses))

    client = RekorClient("http://fake")
    entry = client.create_entry(EntryRequestBody({}))

    assert entry is sentinel_entry
    assert len(requests_seen) == 2
    assert slept == [3.0]


def test_rekor_client_error_formatting():
    """Verify RekorClientError formatting for JSON error, unknown HTTP error, and transport error."""
    json_resp = urllib3.HTTPResponse(
        body=json.dumps({"code": 400, "message": "bad request"}).encode(),
        status=400,
    )
    err1 = RekorClientError.from_response(json_resp)
    assert str(err1) == "400: bad request"

    text_resp = urllib3.HTTPResponse(
        body=b"Bad Gateway",
        status=502,
    )
    err2 = RekorClientError.from_response(text_resp)
    assert str(err2) == "Rekor returned an error with HTTP 502"

    conn_err = urllib3.exceptions.MaxRetryError(
        None,  # type: ignore[arg-type]
        "http://fake",
        reason=urllib3.exceptions.ConnectTimeoutError(None, "http://fake", "timed out"),
    )
    err3 = RekorClientError.from_http_error(conn_err)
    assert "Unexpected Rekor error:" in str(err3)
