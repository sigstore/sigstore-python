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
HTTP client utilities for sigstore-python using urllib3.
"""

from __future__ import annotations

import json
from typing import Any

import urllib3

from sigstore import __version__ as sigstore_version

# Global PoolManager for all HTTP requests
_pool_manager: urllib3.PoolManager | None = None

# User-Agent header for all requests
USER_AGENT = f"sigstore-python/{sigstore_version} (urllib3/{urllib3.__version__})"  # type: ignore[attr-defined]


def _get_pool_manager() -> urllib3.PoolManager:
    """
    Get or create the global PoolManager instance.

    Returns:
        The global urllib3.PoolManager instance.
    """
    global _pool_manager
    if _pool_manager is None:
        _pool_manager = urllib3.PoolManager(
            headers={"User-Agent": USER_AGENT},
            timeout=urllib3.Timeout(connect=30.0, read=30.0),
        )
    return _pool_manager


class HTTPError(Exception):
    """
    Represents an HTTP error response.
    """

    def __init__(self, status: int, reason: str, body: str | None = None):
        """
        Create a new HTTPError.

        Args:
            status: HTTP status code
            reason: HTTP status reason phrase
            body: Optional response body
        """
        self.status = status
        self.reason = reason
        self.body = body
        super().__init__(f"HTTP {status}: {reason}")


class HTTPResponse:
    """
    Wrapper around urllib3 HTTPResponse for easier usage.
    """

    def __init__(self, response: urllib3.BaseHTTPResponse):  # type: ignore[type-arg]
        """
        Create a new HTTPResponse.

        Args:
            response: The underlying urllib3.HTTPResponse
        """
        self._response = response
        self.status_code = response.status
        self.reason = response.reason
        self._data = response.data

    def raise_for_status(self) -> None:
        """
        Raise an HTTPError if the response status indicates an error.

        Raises:
            HTTPError: If status code is 4xx or 5xx
        """
        if 400 <= self.status_code < 600:
            raise HTTPError(self.status_code, self.reason or "", self.text)

    @property
    def text(self) -> str:
        """
        Get the response body as text.

        Returns:
            The response body decoded as UTF-8
        """
        return self._data.decode("utf-8")

    def json(self) -> Any:
        """
        Parse the response body as JSON.

        Returns:
            The parsed JSON data
        """
        return json.loads(self.text)


def request(
    method: str,
    url: str,
    *,
    headers: dict[str, str] | None = None,
    json_data: Any | None = None,
    data: bytes | None = None,
    params: dict[str, Any] | None = None,
    timeout: float | None = None,
) -> HTTPResponse:
    """
    Make an HTTP request using the global PoolManager.

    Args:
        method: HTTP method (GET, POST, etc.)
        url: URL to request
        headers: Optional additional headers
        json_data: Optional JSON data to send (will be serialized)
        data: Optional raw bytes to send
        params: Optional query parameters
        timeout: Optional timeout in seconds

    Returns:
        HTTPResponse object

    Raises:
        urllib3.exceptions.HTTPError: On connection errors
        HTTPError: On HTTP error status codes (if raise_for_status is called)
    """
    pool = _get_pool_manager()

    # Build request headers
    request_headers = {}
    if json_data is not None:
        request_headers["Content-Type"] = "application/json"
        data = json.dumps(json_data).encode("utf-8")
    if headers:
        request_headers.update(headers)

    # Build fields for query parameters
    fields = None
    if params:
        fields = params

    # Create timeout object if specified
    timeout_obj = None
    if timeout is not None:
        timeout_obj = urllib3.Timeout(connect=timeout, read=timeout)

    response = pool.request(
        method,
        url,
        headers=request_headers,
        body=data,
        fields=fields if method.upper() == "GET" else None,
        timeout=timeout_obj,
    )

    return HTTPResponse(response)


def get(url: str, **kwargs: Any) -> HTTPResponse:
    """
    Make a GET request.

    Args:
        url: URL to request
        **kwargs: Additional arguments to pass to request()

    Returns:
        HTTPResponse object
    """
    return request("GET", url, **kwargs)


def post(url: str, **kwargs: Any) -> HTTPResponse:
    """
    Make a POST request.

    Args:
        url: URL to request
        **kwargs: Additional arguments to pass to request()

    Returns:
        HTTPResponse object
    """
    return request("POST", url, **kwargs)
