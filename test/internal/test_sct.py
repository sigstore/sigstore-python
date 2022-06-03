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
import hashlib
import struct

import pretend
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.certificate_transparency import LogEntryType

from sigstore._internal import sct


@pytest.mark.parametrize(
    "precert_bytes",
    [
        b"tbs",
        # b"x" * 255,
        # b"x" * 1024,
        # b"x" * 16777215,
    ],
)
def test_pack_digitally_signed(precert_bytes):
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


def test_issuer_key_hash():
    # Taken from certificate-transparency-go:
    # https://github.com/google/certificate-transparency-go/blob/88227ce0/trillian/ctfe/testonly/certificates.go#L213-L231
    precert_pem = b"""-----BEGIN CERTIFICATE-----
MIIC3zCCAkigAwIBAgIBBzANBgkqhkiG9w0BAQUFADBVMQswCQYDVQQGEwJHQjEk
MCIGA1UEChMbQ2VydGlmaWNhdGUgVHJhbnNwYXJlbmN5IENBMQ4wDAYDVQQIEwVX
YWxlczEQMA4GA1UEBxMHRXJ3IFdlbjAeFw0xMjA2MDEwMDAwMDBaFw0yMjA2MDEw
MDAwMDBaMFIxCzAJBgNVBAYTAkdCMSEwHwYDVQQKExhDZXJ0aWZpY2F0ZSBUcmFu
c3BhcmVuY3kxDjAMBgNVBAgTBVdhbGVzMRAwDgYDVQQHEwdFcncgV2VuMIGfMA0G
CSqGSIb3DQEBAQUAA4GNADCBiQKBgQC+75jnwmh3rjhfdTJaDB0ym+3xj6r015a/
BH634c4VyVui+A7kWL19uG+KSyUhkaeb1wDDjpwDibRc1NyaEgqyHgy0HNDnKAWk
EM2cW9tdSSdyba8XEPYBhzd+olsaHjnu0LiBGdwVTcaPfajjDK8VijPmyVCfSgWw
FAn/Xdh+tQIDAQABo4HBMIG+MB0GA1UdDgQWBBQgMVQa8lwF/9hli2hDeU9ekDb3
tDB9BgNVHSMEdjB0gBRfnYgNyHPmVNT4DdjmsMEktEfDVaFZpFcwVTELMAkGA1UE
BhMCR0IxJDAiBgNVBAoTG0NlcnRpZmljYXRlIFRyYW5zcGFyZW5jeSBDQTEOMAwG
A1UECBMFV2FsZXMxEDAOBgNVBAcTB0VydyBXZW6CAQAwCQYDVR0TBAIwADATBgor
BgEEAdZ5AgQDAQH/BAIFADANBgkqhkiG9w0BAQUFAAOBgQACocOeAVr1Tf8CPDNg
h1//NDdVLx8JAb3CVDFfM3K3I/sV+87MTfRxoM5NjFRlXYSHl/soHj36u0YtLGhL
BW/qe2O0cP8WbjLURgY1s9K8bagkmyYw5x/DTwjyPdTuIo+PdPY9eGMR3QpYEUBf
kGzKLC0+6/yBmWTr2M98CIY/vg==
    -----END CERTIFICATE-----"""

    precert = x509.load_pem_x509_certificate(precert_pem)

    public_key = precert.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    assert sct._issuer_key_hash(precert) == hashlib.sha256(public_key).digest()
    assert (
        hashlib.sha256(public_key).hexdigest()
        == "086c0ea25b60e3c44a994d0d5f40b81a0d44f21d63df19315e6ddfbe47373817"
    )
