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

import gc
import warnings
from types import SimpleNamespace

from sigstore._internal.oidc.oauth import _OAuthFlow


def test_oauth_flow_closes_redirect_server_socket():
    issuer = SimpleNamespace(
        oidc_config=SimpleNamespace(authorization_endpoint="https://example.com/auth")
    )

    with warnings.catch_warnings(record=True) as warnings_seen:
        warnings.simplefilter("always", ResourceWarning)
        flow = _OAuthFlow("sigstore", "", issuer)
        with flow as server:
            assert server.server_port

        del server
        del flow
        gc.collect()

    resource_warnings = [
        warning for warning in warnings_seen if warning.category is ResourceWarning
    ]
    assert not resource_warnings
