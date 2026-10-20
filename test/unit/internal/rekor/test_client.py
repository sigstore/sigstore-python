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

import pytest
import requests

from sigstore._internal.rekor import RekorClientError


@pytest.mark.parametrize(
    "body, expected",
    [
        (b'{"code": 400, "message": "bad request"}', "400: bad request"),
        (b"not JSON", "Rekor returned an unknown error with HTTP 400"),
        (b"{}", "Rekor returned an unknown error with HTTP 400"),
    ],
)
def test_rekor_client_error(body, expected):
    response = requests.Response()
    response.status_code = 400
    response._content = body

    error = RekorClientError(requests.HTTPError(response=response))

    assert str(error) == expected
