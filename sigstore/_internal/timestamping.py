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

"""
Timestamp Authority Client for `sigstore-python`
"""

import requests
from rfc3161_client import (
    TimestampRequestBuilder,
    TimeStampResponse,
    decode_timestamp_response,
)

from sigstore._internal import USER_AGENT


class TimestampError(Exception):
    """
    A generic error in the TimestampAuthority client.
    """

    pass


class TimestampAuthorityClient:
    """Internal client to deal with a Timestamp Authority"""

    def __init__(self, url: str) -> None:
        """
        Create a new `TimestampAuthorityClient` from the given URL
        """
        self.url = url
        self.session = requests.Session()
        self.session.headers.update(
            {
                "Content-Type": "application/timestamp-query",
                "User-Agent": USER_AGENT,
            }
        )
        self.timeout: int = 30

    def __del__(self) -> None:
        """
        Terminates the underlying network session.
        """
        self.session.close()

    def timestamps(self, signature: bytes) -> TimeStampResponse:
        """
        Timestamp the signature using the configured Timestamp Authority.

        This method generates a RFC3161 Timestamp request, and then send it to a TSA.
        The received response is then decoded to ensure it's valid but is *not* verified.

        Raises a TimestampError on failure.
        """
        # Build the timestamp request
        try:
            timestamp_request = (
                TimestampRequestBuilder().data(signature).nonce(nonce=True).build()
            )
        except ValueError as error:
            msg = f"Invalid Request: {error}"
            raise TimestampError(msg)

        # Request a signature of the request
        try:
            response = self.session.post(
                self.url,
                data=timestamp_request.as_bytes(),
                timeout=self.timeout,
            )
            response.raise_for_status()
        except requests.RequestException as error:
            msg = f"Invalid network: {error}"
            raise TimestampError(msg)

        # Check that we can parse the response but does not *verify* it
        try:
            timestamp_response = decode_timestamp_response(response.content)
        except ValueError as e:
            msg = f"Invalid response: {e}"
            raise TimestampError(msg)

        return timestamp_response
