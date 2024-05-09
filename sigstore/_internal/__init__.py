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

from requests import __version__ as requests_version

from sigstore import __version__ as sigstore_version

USER_AGENT = f"sigstore-python/{sigstore_version} (python-requests/{requests_version})"
