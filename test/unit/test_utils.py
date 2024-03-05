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


import hashlib
import io

import pretend
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from sigstore import _utils as utils


def test_key_id():
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

    key_id = utils.key_id(precert.public_key())
    assert key_id == hashlib.sha256(public_key).digest()
    assert (
        hashlib.sha256(public_key).hexdigest()
        == "086c0ea25b60e3c44a994d0d5f40b81a0d44f21d63df19315e6ddfbe47373817"
    )


@pytest.mark.parametrize(
    "size", [0, 1, 2, 4, 8, 32, 128, 1024, 128 * 1024, 1024 * 1024, 128 * 1024 * 1024]
)
def test_sha256_streaming(size):
    buf = b"x" * size

    expected_digest = hashlib.sha256(buf).digest()
    actual_digest = utils._sha256_streaming(io.BytesIO(buf))

    assert expected_digest == actual_digest


def test_load_pem_public_key_format():
    keybytes = b"-----BEGIN PUBLIC KEY-----\n" b"bleh\n" b"-----END PUBLIC KEY-----"
    with pytest.raises(
        utils.InvalidKeyError, match="could not load PEM-formatted public key"
    ):
        utils.load_pem_public_key([keybytes])


def test_load_pem_public_key_serialization(monkeypatch):
    from cryptography.hazmat.primitives import serialization

    monkeypatch.setattr(serialization, "load_pem_public_key", lambda a: a)

    keybytes = (
        b"-----BEGIN PUBLIC KEY-----\n"
        b"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEbfwR+RJudXscgRBRpKX1XFDy3Pyu\n"
        b"dDxz/SfnRi1fT8ekpfBd2O1uoz7jr3Z8nKzxA69EUQ+eFCFI3zeubPWU7w==\n"
        b"-----END PUBLIC KEY-----"
    )

    with pytest.raises(
        utils.InvalidKeyError, match="invalid key format (not ECDSA or RSA)*"
    ):
        utils.load_pem_public_key([keybytes])


@pytest.mark.parametrize(
    ("testcase", "valid"),
    [
        ("bogus-root.pem", True),
        ("bogus-intermediate.pem", True),
        ("bogus-leaf.pem", False),
    ],
)
def test_cert_is_ca(x509_testcase, testcase, valid):
    cert = x509_testcase(testcase)

    assert utils.cert_is_ca(cert) is valid


@pytest.mark.parametrize(
    "testcase",
    [
        "bogus-root-noncritical-bc.pem",
        "bogus-root-invalid-ku.pem",
        "bogus-root-missing-ku.pem",
    ],
)
def test_cert_is_ca_invalid_states(x509_testcase, testcase):
    cert = x509_testcase(testcase)

    with pytest.raises(utils.InvalidCertError):
        utils.cert_is_ca(cert)


@pytest.mark.parametrize(
    ("testcase", "valid"),
    [
        ("bogus-root.pem", True),
        ("bogus-intermediate.pem", False),
        ("bogus-leaf.pem", False),
        ("bogus-leaf-invalid-ku.pem", False),
    ],
)
def test_cert_is_root_ca(x509_testcase, testcase, valid):
    cert = x509_testcase(testcase)

    assert utils.cert_is_root_ca(cert) is valid


@pytest.mark.parametrize(
    ("testcase", "valid"),
    (
        ["bogus-root.pem", False],
        ["bogus-intermediate.pem", False],
        ["bogus-intermediate-with-eku.pem", False],
        ["bogus-leaf.pem", True],
        ["bogus-leaf-invalid-eku.pem", False],
    ),
)
def test_cert_is_leaf(x509_testcase, testcase, valid):
    cert = x509_testcase(testcase)

    assert utils.cert_is_leaf(cert) is valid


@pytest.mark.parametrize(
    "testcase",
    [
        "bogus-root-invalid-ku.pem",
        "bogus-root-missing-ku.pem",
        "bogus-leaf-invalid-ku.pem",
        "bogus-leaf-missing-eku.pem",
    ],
)
def test_cert_is_leaf_invalid_states(x509_testcase, testcase):
    cert = x509_testcase(testcase)

    with pytest.raises(utils.InvalidCertError):
        utils.cert_is_leaf(cert)


@pytest.mark.parametrize(
    "helper", [utils.cert_is_leaf, utils.cert_is_ca, utils.cert_is_root_ca]
)
def test_cert_is_leaf_invalid_version(helper):
    cert = pretend.stub(version=x509.Version.v1)

    with pytest.raises(utils.InvalidCertError):
        helper(cert)


class TestKnownBundleTypes:
    def test_str(self):
        for type_ in utils.BundleType:
            assert str(type_) == type_.value
            assert type_ in utils.BundleType
