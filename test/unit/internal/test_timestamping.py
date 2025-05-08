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

from sigstore._internal.timestamp import TimestampAuthorityClient, TimestampError
from sigstore._utils import sha256_digest
from cryptography.hazmat.primitives.hashes import SHA256


@pytest.mark.timestamp_authority
class TestTimestampAuthorityClient:
    def test_sign_request(self, tsa_url: str):
        tsa = TimestampAuthorityClient(tsa_url)
        response = tsa.request_timestamp(b"hello")
        assert response
        assert (
            response.tst_info.message_imprint.message == sha256_digest(b"hello").digest
        )
        assert (
            response.tst_info.message_imprint.hash_algorithm.dotted_string
            == "2.16.840.1.101.3.4.2.1"
        )  # SHA256 OID

    def test_sign_request_invalid_url(self):
        tsa = TimestampAuthorityClient("http://fake-url")
        with pytest.raises(TimestampError, match="error while sending"):
            tsa.request_timestamp(b"hello")

    def test_sign_request_invalid_request(self, tsa_url):
        tsa = TimestampAuthorityClient(tsa_url)
        with pytest.raises(TimestampError, match="invalid request"):
            tsa.request_timestamp(b"")  # empty value here

    def test_invalid_response(self, tsa_url, monkeypatch):
        monkeypatch.setattr(requests.Response, "content", b"invalid-response")

        tsa = TimestampAuthorityClient(tsa_url)
        with pytest.raises(TimestampError, match="invalid response"):
            tsa.request_timestamp(b"hello")
