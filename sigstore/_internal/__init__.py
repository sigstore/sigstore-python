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
sigstore-python's internal APIs.

Everything in these APIs is considered internal and unstable, and is not
subject to any stability guarantees.
"""

import urllib3

from sigstore import __version__ as sigstore_version

USER_AGENT = f"sigstore-python/{sigstore_version}"

# Connection and HTTP status errors are retried twice; read timeouts are retried once.
# POST is also retried since all service endpoints (Fulcio, TSA, OIDC, and Rekor with
# 409 handling) are safe to retry on transient 5xx/429/408 errors.
# backoff + Jitter are defined mostly for Rekor and TSA that may be called in parallel
# from multiple threads.
DEFAULT_RETRIES = urllib3.Retry(
    connect=2,
    read=1,
    status=2,
    allowed_methods=frozenset(["GET", "POST"]),
    status_forcelist=frozenset([408, 429, 500, 502, 503, 504]),
    backoff_factor=1.0,
    backoff_jitter=0.5,
    respect_retry_after_header=True,
    raise_on_status=False,
)
