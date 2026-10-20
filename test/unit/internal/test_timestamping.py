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
import pretend
import pytest
import requests

from sigstore._internal.timestamp import TimestampAuthorityClient, TimestampError
from sigstore._utils import sha256_digest


class TestTimestampAuthorityClient:
    @pytest.mark.timestamp_authority
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

    @pytest.mark.timestamp_authority
    def test_sign_request_invalid_url(self):
        tsa = TimestampAuthorityClient("http://fake-url")
        with pytest.raises(TimestampError, match="error while sending"):
            tsa.request_timestamp(b"hello")

    @pytest.mark.timestamp_authority
    def test_sign_request_invalid_request(self, tsa_url):
        tsa = TimestampAuthorityClient(tsa_url)
        with pytest.raises(TimestampError, match="invalid request"):
            tsa.request_timestamp(b"")  # empty value here

    @pytest.mark.timestamp_authority
    def test_invalid_response(self, tsa_url, monkeypatch):
        monkeypatch.setattr(requests.Response, "content", b"invalid-response")

        tsa = TimestampAuthorityClient(tsa_url)
        with pytest.raises(TimestampError, match="invalid response"):
            tsa.request_timestamp(b"hello")

    def test_non_granted_response(self, monkeypatch):
        # DER-encoded TimeStampResp with PKIStatus = 2 (REJECTION) and no TimeStampToken:
        rejection_der = bytes.fromhex("30053003020102")
        response = pretend.stub(
            raise_for_status=lambda: None,
            content=rejection_der,
        )
        tsa = TimestampAuthorityClient("http://fake-url")
        monkeypatch.setattr(tsa._session, "post", lambda *a, **kw: response)

        with pytest.raises(
            TimestampError, match="invalid response: PKIStatus is REJECTION"
        ):
            tsa.request_timestamp(b"hello")
