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

import datetime
import struct

import pretend
import pytest
from cryptography.x509.certificate_transparency import LogEntryType

from sigstore._internal import sct


@pytest.mark.parametrize(
    "precert_bytes_len",
    [
        3,
        255,
        1024,
        16777215,
    ],
)
def test_pack_digitally_signed(precert_bytes_len):
    precert_bytes = b"x" * precert_bytes_len

    mock_sct = pretend.stub(
        version=pretend.stub(value=0),
        timestamp=datetime.datetime.fromtimestamp(
            1234 / 1000.0, tz=datetime.timezone.utc
        ),
        entry_type=LogEntryType.PRE_CERTIFICATE,
        extension_bytes=b"",
    )
    cert = pretend.stub(tbs_precertificate_bytes=precert_bytes)
    issuer_key_hash = b"iamapublickeyshatwofivesixdigest"

    _, l1, l2, l3 = struct.unpack("!4c", struct.pack("!I", len(precert_bytes)))

    data = sct._pack_digitally_signed(mock_sct, cert, issuer_key_hash)
    assert data == (
        b"\x00"  # version
        b"\x00"  # signature type
        b"\x00\x00\x00\x00\x00\x00\x04\xd2"  # timestamp
        b"\x00\x01"  # entry type
        b"iamapublickeyshatwofivesixdigest"  # issuer key hash
        + l1
        + l2
        + l3  # tbs cert length
        + precert_bytes  # tbs cert
        + b"\x00\x00"  # extensions length
        + b""  # extensions
    )
