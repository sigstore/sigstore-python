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

import unittest.mock

import pytest
import urllib3

from sigstore._internal.fulcio.client import (
    DEFAULT_FULCIO_TIMEOUT,
    FulcioClient,
    FulcioClientError,
)


def _client_with_mock_http():
    client = FulcioClient("http://fake")
    assert client._http.connection_pool_kw["timeout"] is DEFAULT_FULCIO_TIMEOUT
    http = unittest.mock.MagicMock(spec=urllib3.PoolManager)
    client._http = http
    return client, http


def test_signing_cert_post_handles_error():
    client, http = _client_with_mock_http()

    request = unittest.mock.MagicMock()
    request.public_bytes.return_value = b"csr"
    http.request.return_value = urllib3.HTTPResponse(
        body=b'{"message": "bad csr"}', status=400
    )

    with pytest.raises(FulcioClientError, match="bad csr"):
        client.signing_cert.post(request, "token")


def test_trust_bundle_get():
    client, http = _client_with_mock_http()
    http.request.return_value = urllib3.HTTPResponse(body=b'{"chains": []}', status=200)

    resp = client.trust_bundle.get()

    assert resp.trust_bundle == []
