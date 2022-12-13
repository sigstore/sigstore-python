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

from sigstore._utils import read_embedded


def test_store_reads_fulcio_root_cert():
    fulcio_crt = read_embedded("fulcio.crt.pem").strip()
    lines = fulcio_crt.split(b"\n")

    assert lines[0].startswith(b"-----BEGIN CERTIFICATE-----")
    assert lines[-1].startswith(b"-----END CERTIFICATE-----")


def test_store_reads_ctfe_pub():
    ctfe_pub = read_embedded("ctfe.pub").strip()
    lines = ctfe_pub.split(b"\n")

    assert lines[0].startswith(b"-----BEGIN PUBLIC KEY-----")
    assert lines[-1].startswith(b"-----END PUBLIC KEY-----")
