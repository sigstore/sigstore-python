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

import unittest.mock

import pytest

from sigstore._internal.rekor import DEFAULT_REKOR_TIMEOUT, EntryRequestBody
from sigstore._internal.rekor.client import RekorClient


def _client_with_mock_session():
    client = RekorClient("http://fake")
    session = unittest.mock.MagicMock()
    client._thread_local.session = session
    return client, session


def test_log_get_passes_timeout():
    client, session = _client_with_mock_session()

    # Hide exceptions: the mocked response is not a valid API response, and we
    # only care about how the request itself was made.
    try:
        client.log.get()
    except Exception:
        pass

    assert session.get.call_args.kwargs["timeout"] == DEFAULT_REKOR_TIMEOUT


@pytest.mark.parametrize(
    "kwargs", [{"uuid": "deadbeef"}, {"log_index": 1}], ids=["uuid", "log_index"]
)
def test_entries_get_passes_timeout(kwargs):
    client, session = _client_with_mock_session()

    try:
        client.log.entries.get(**kwargs)
    except Exception:
        pass

    assert session.get.call_args.kwargs["timeout"] == DEFAULT_REKOR_TIMEOUT


def test_entries_post_passes_timeout():
    client, session = _client_with_mock_session()

    try:
        client.create_entry(EntryRequestBody({}))
    except Exception:
        pass

    assert session.post.call_args.kwargs["timeout"] == DEFAULT_REKOR_TIMEOUT


def test_entries_retrieve_post_passes_timeout():
    client, session = _client_with_mock_session()

    try:
        client.log.entries.retrieve.post(unittest.mock.MagicMock())
    except Exception:
        pass

    assert session.post.call_args.kwargs["timeout"] == DEFAULT_REKOR_TIMEOUT
