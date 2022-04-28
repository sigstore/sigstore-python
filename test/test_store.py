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

from importlib import resources


def test_store_reads_fulcio_root_cert():
    fulcio_crt = resources.read_text("sigstore._store", "fulcio.crt.pem")

    assert fulcio_crt.startswith("-----BEGIN CERTIFICATE-----")
    assert fulcio_crt.endswith("-----END CERTIFICATE-----")


def test_store_reads_ctfe_pub():
    ctfe_pub = resources.read_text("sigstore._store", "ctfe.pub")

    assert ctfe_pub.startswith("-----BEGIN PUBLIC KEY-----")
    assert ctfe_pub.endswith("-----END PUBLIC KEY-----")
