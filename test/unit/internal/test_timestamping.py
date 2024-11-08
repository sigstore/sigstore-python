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
import pytest
import requests

from sigstore._internal.timestamping import TimestampAuthorityClient, TimestampError


@pytest.mark.timestamp_authority
class TestTimestampAuthorityClient:
    def test_sign_request(self, tsa_url: str):
        tsa = TimestampAuthorityClient(tsa_url)
        response = tsa.timestamps(b"hello")
        assert response

    def test_sign_request_invalid_url(self):
        tsa = TimestampAuthorityClient("http://fake-url")
        with pytest.raises(TimestampError, match="Invalid network"):
            tsa.timestamps(b"hello")

    def test_sign_request_invalid_request(self, tsa_url):
        tsa = TimestampAuthorityClient(tsa_url)
        with pytest.raises(TimestampError, match="Invalid Request"):
            tsa.timestamps(b"")  # empty value here

    def test_invalid_response(self, tsa_url, monkeypatch):
        monkeypatch.setattr(requests.Response, "content", b"invalid-response")

        tsa = TimestampAuthorityClient(tsa_url)
        with pytest.raises(TimestampError, match="Invalid response"):
            tsa.timestamps(b"hello")
