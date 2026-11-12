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

import base64
import unittest.mock

import pytest
import urllib3
from sigstore_models.rekor.v2.identity import IdentityRequestV001, OidcCredential

from sigstore._internal import DEFAULT_RETRIES, USER_AGENT
from sigstore._internal.c2sp.proof import TLogProof, encode_extra_claims
from sigstore._internal.rekor import DEFAULT_REKOR_TIMEOUT, RekorClientError
from sigstore._internal.rekor.client_identity import IdentityRekorClient
from sigstore.oidc import IdentityToken

SAMPLE_CHECKPOINT = (
    b"rekor.sigstore.dev\n"
    b"1\n"
    b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n"
    b"\n"
    b"\xe2\x80\x94 rekor.sigstore.dev AAAAbbbbcccc\n"
)


def _sample_tlog_proof() -> TLogProof:
    extra = encode_extra_claims(
        {
            "identity": "alice@example.com",
            "issuer": "https://accounts.example.com",
        }
    )
    return TLogProof(
        index=0,
        hashes=[],
        checkpoint=SAMPLE_CHECKPOINT,
        extra_data=extra,
    )


def test_identity_rekor_client_init_and_pool_config():
    client = IdentityRekorClient("https://global-pqc.rekor.sigstage.dev/")
    assert client.url == "https://global-pqc.rekor.sigstage.dev/api/v2"
    headers = client._http.headers
    assert headers["Content-Type"] == "application/json"
    assert headers["Accept"] == "text/plain"
    assert headers["User-Agent"] == USER_AGENT
    assert client._http.connection_pool_kw["retries"] is DEFAULT_RETRIES
    assert client._http.connection_pool_kw["timeout"] is DEFAULT_REKOR_TIMEOUT
    assert client._http.connection_pool_kw["maxsize"] == 32


def test_create_oidc_entry_success():
    client = IdentityRekorClient("https://global-pqc.rekor.sigstage.dev")
    digest = b"\x11" * 32
    expected_proof = _sample_tlog_proof()

    mock_resp = urllib3.HTTPResponse(body=expected_proof.to_bytes(), status=201)

    token = unittest.mock.MagicMock(spec=IdentityToken)
    token.__str__.return_value = "header.payload.sig"

    with unittest.mock.patch.object(
        client._http, "request", return_value=mock_resp
    ) as mock_req:
        result = client.create_oidc_entry(digest, token)

    assert result == expected_proof
    mock_req.assert_called_once_with(
        "POST",
        "https://global-pqc.rekor.sigstage.dev/api/v2/log/entries",
        json={
            "message": base64.b64encode(digest).decode(),
            "oidc": {"token": "header.payload.sig"},
        },
    )


def test_create_public_key_entry_with_and_without_context():
    client = IdentityRekorClient("https://global-pqc.rekor.sigstage.dev")
    digest = b"\x22" * 32
    spki = b"spki-der-key"
    sig = b"mldsa-signature"
    ctx = b"\x33" * 32
    expected_proof = _sample_tlog_proof()

    mock_resp = urllib3.HTTPResponse(body=expected_proof.to_bytes(), status=201)

    with unittest.mock.patch.object(
        client._http, "request", return_value=mock_resp
    ) as mock_req:
        result_ctx = client.create_public_key_entry(digest, spki, sig, context=ctx)
        assert result_ctx == expected_proof
        mock_req.assert_called_once_with(
            "POST",
            "https://global-pqc.rekor.sigstage.dev/api/v2/log/entries",
            json={
                "message": base64.b64encode(digest).decode(),
                "publicKey": {
                    "publicKey": base64.b64encode(spki).decode(),
                    "signature": base64.b64encode(sig).decode(),
                    "context": base64.b64encode(ctx).decode(),
                },
            },
        )

        mock_req.reset_mock()
        result_no_ctx = client.create_public_key_entry(digest, spki, sig)
        assert result_no_ctx == expected_proof
        mock_req.assert_called_once_with(
            "POST",
            "https://global-pqc.rekor.sigstage.dev/api/v2/log/entries",
            json={
                "message": base64.b64encode(digest).decode(),
                "publicKey": {
                    "publicKey": base64.b64encode(spki).decode(),
                    "signature": base64.b64encode(sig).decode(),
                },
            },
        )


def test_create_entry_invalid_digest_or_context_length():
    client = IdentityRekorClient("https://global-pqc.rekor.sigstage.dev")
    token = unittest.mock.MagicMock(spec=IdentityToken)
    with pytest.raises(ValueError, match="IdentityRequestV001 digest must be 32 bytes"):
        client.create_oidc_entry(b"short", token)

    with pytest.raises(ValueError, match="IdentityRequestV001 digest must be 32 bytes"):
        client.create_public_key_entry(b"short", b"spki", b"sig")

    with pytest.raises(
        ValueError, match="PublicKeyCredential context must be 32 bytes"
    ):
        client.create_public_key_entry(b"\x22" * 32, b"spki", b"sig", context=b"short")


def test_create_entry_invalid_tlog_proof_response():
    client = IdentityRekorClient("https://global-pqc.rekor.sigstage.dev")
    mock_resp = urllib3.HTTPResponse(body=b"not a valid c2sp tlog proof", status=201)

    req = IdentityRequestV001(
        message=base64.b64encode(b"\x11" * 32),
        oidc=OidcCredential(token="tok"),
    )

    with (
        unittest.mock.patch.object(client._http, "request", return_value=mock_resp),
        pytest.raises(RekorClientError, match="Invalid tlog-proof response from Rekor"),
    ):
        client._create_entry(req)


def test_create_entry_http_409_duplicate_entry():
    client = IdentityRekorClient("https://global-pqc.rekor.sigstage.dev")
    mock_resp = urllib3.HTTPResponse(
        body=b'{"code":6,"message":"already exists"}',
        headers={"x-log-index": "42"},
        status=409,
    )

    req = IdentityRequestV001(
        message=base64.b64encode(b"\x11" * 32),
        oidc=OidcCredential(token="tok"),
    )

    with (
        unittest.mock.patch.object(client._http, "request", return_value=mock_resp),
        pytest.raises(
            RekorClientError,
            match="Duplicate entry already exists at log index 42",
        ),
    ):
        client._create_entry(req)


def test_create_entry_http_405_and_transport_errors():
    client = IdentityRekorClient("https://global-pqc.rekor.sigstage.dev")
    mock_resp = urllib3.HTTPResponse(
        body=b"This log has been frozen, please switch to the latest log.\n",
        status=405,
    )

    req = IdentityRequestV001(
        message=base64.b64encode(b"\x11" * 32),
        oidc=OidcCredential(token="tok"),
    )

    with (
        unittest.mock.patch.object(client._http, "request", return_value=mock_resp),
        pytest.raises(
            RekorClientError,
            match="Rekor returned an error with HTTP 405",
        ),
    ):
        client._create_entry(req)

    with (
        unittest.mock.patch.object(
            client._http,
            "request",
            side_effect=urllib3.exceptions.ConnectTimeoutError(
                None, "https://global-pqc.rekor.sigstage.dev", "timed out"
            ),
        ),
        pytest.raises(RekorClientError, match="Unexpected Rekor error:"),
    ):
        client._create_entry(req)
