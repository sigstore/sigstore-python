# Copyright 2025 The Sigstore Authors
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

import hashlib
import json
from unittest.mock import Mock

import pytest
import requests

from sigstore import dsse
from sigstore._internal.rekor import EntryRequestBody, RekorClientError
from sigstore._internal.rekor.client_v2 import RekorV2Client
from sigstore.models import Bundle, TransparencyLogEntry


def test_rekor_v2_create_entry_timeout(monkeypatch, asset):
    bundle_bytes = asset("staging-rekor-v2.txt.sigstore.json").read_bytes()
    entry = json.loads(bundle_bytes)["verificationMaterial"]["tlogEntries"][0]
    response = Mock(spec=requests.Response)
    response.json.return_value = entry
    post = Mock(return_value=response)
    client = RekorV2Client("https://rekor.example.com")
    monkeypatch.setattr(client._session, "post", post)
    payload = EntryRequestBody({})

    result = client.create_entry(payload)

    post.assert_called_once_with(
        "https://rekor.example.com/api/v2/log/entries", json=payload, timeout=60
    )
    assert result == Bundle.from_json(bundle_bytes).log_entry


@pytest.mark.parametrize("error_type", [requests.ConnectTimeout, requests.ReadTimeout])
def test_rekor_v2_create_entry_timeout_propagates(monkeypatch, error_type):
    error = error_type("Rekor request timed out")
    post = Mock(side_effect=error)
    client = RekorV2Client("https://rekor.example.com")
    monkeypatch.setattr(client._session, "post", post)

    with pytest.raises(error_type) as exc:
        client.create_entry(EntryRequestBody({}))

    assert exc.value is error
    assert post.call_count == 1


def test_rekor_v2_create_entry_http_error(monkeypatch):
    response = requests.Response()
    response.status_code = 503
    response._content = b"Service unavailable"
    post = Mock(return_value=response)
    client = RekorV2Client("https://rekor.example.com")
    monkeypatch.setattr(client._session, "post", post)

    with pytest.raises(
        RekorClientError, match="Rekor returned an unknown error with HTTP 503"
    ):
        client.create_entry(EntryRequestBody({}))


@pytest.mark.staging
@pytest.mark.ambient_oidc
def test_rekor_v2_create_entry_dsse(staging):
    # This is not a real unit test: it requires not only staging rekor but also TUF
    # fulcio and oidc -- maybe useful only until we have real integration tests in place
    sign_ctx_cls, _, identity = staging
    sign_ctx = sign_ctx_cls()

    stmt = (
        dsse.StatementBuilder()
        .subjects(
            [
                dsse.Subject(
                    name="null", digest={"sha256": hashlib.sha256(b"").hexdigest()}
                )
            ]
        )
        .predicate_type("https://cosign.sigstore.dev/attestation/v1")
        .predicate(
            {
                "Data": "",
                "Timestamp": "2023-12-07T00:37:58Z",
            }
        )
    ).build()

    with sign_ctx.signer(identity) as signer:
        bundle = signer.sign_dsse(stmt)

    assert isinstance(bundle.log_entry, TransparencyLogEntry)


@pytest.mark.staging
@pytest.mark.ambient_oidc
def test_rekor_v2_create_entry_hashed_rekord(staging):
    # This is not a real unit test: it requires not only staging rekor but also TUF
    # fulcio and oidc -- maybe useful only until we have real integration tests in place
    sign_ctx_cls, _, identity = staging
    sign_ctx = sign_ctx_cls()

    with sign_ctx.signer(identity) as signer:
        bundle = signer.sign_artifact(b"")

    assert isinstance(bundle.log_entry, TransparencyLogEntry)
