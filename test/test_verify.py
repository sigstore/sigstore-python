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

import sigstore


@pytest.mark.xfail
def test_verify():
    filename = pretend.stub()
    certificate_path = pretend.stub()
    signature_path = pretend.stub()
    assert (
        sigstore.verify(filename, certificate_path, signature_path)
        == "Nothing here yet"
    )
