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
import requests

from sigstore._internal.fulcio.client import (
    DEFAULT_FULCIO_TIMEOUT,
    FulcioClient,
    FulcioClientError,
)


def _client_with_mock_session():
    client = FulcioClient("http://fake")
    session = unittest.mock.MagicMock()
    client.session = session
    return client, session


def test_signing_cert_post_passes_timeout():
    client, session = _client_with_mock_session()

    request = unittest.mock.MagicMock()
    request.public_bytes.return_value = b"csr"
    response = session.post.return_value
    response.raise_for_status.side_effect = requests.HTTPError

    with pytest.raises(FulcioClientError):
        client.signing_cert.post(request, "token")

    assert session.post.call_args.kwargs["timeout"] == DEFAULT_FULCIO_TIMEOUT


def test_signing_cert_timeout_is_wrapped():
    client, session = _client_with_mock_session()

    request = unittest.mock.MagicMock()
    request.public_bytes.return_value = b"csr"
    session.post.side_effect = requests.Timeout("timed out")

    with pytest.raises(FulcioClientError) as error:
        client.signing_cert.post(request, "token")

    assert isinstance(error.value.__cause__, requests.Timeout)
    assert session.post.call_args.kwargs["timeout"] == DEFAULT_FULCIO_TIMEOUT


def test_trust_bundle_get_passes_timeout():
    client, session = _client_with_mock_session()
    session.get.return_value.json.return_value = {"chains": []}

    client.trust_bundle.get()

    assert session.get.call_args.kwargs["timeout"] == DEFAULT_FULCIO_TIMEOUT


def test_trust_bundle_timeout_is_wrapped():
    client, session = _client_with_mock_session()
    session.get.side_effect = requests.Timeout("timed out")

    with pytest.raises(FulcioClientError) as error:
        client.trust_bundle.get()

    assert isinstance(error.value.__cause__, requests.Timeout)
    assert session.get.call_args.kwargs["timeout"] == DEFAULT_FULCIO_TIMEOUT
