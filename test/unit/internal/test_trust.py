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


import os
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.x509 import load_pem_x509_certificate
from sigstore_protobuf_specs.dev.sigstore.common.v1 import TimeRange

from sigstore._internal.trust import (
    CertificateAuthority,
    ClientTrustConfig,
    KeyringPurpose,
    SigningConfig,
    TrustedRoot,
    _is_timerange_valid,
)
from sigstore._utils import load_pem_public_key
from sigstore.errors import Error


class TestCertificateAuthority:
    def test_good(self, asset):
        path = asset("trusted_root/certificate_authority.json")
        authority = CertificateAuthority.from_json(path)

        assert len(authority.certificates(allow_expired=True)) == 3
        assert authority.validity_period_start < authority.validity_period_end

    def test_missing_root(self, asset):
        path = asset("trusted_root/certificate_authority.empty.json")
        with pytest.raises(Error, match="missing a certificate"):
            CertificateAuthority.from_json(path)


class TestSigningcconfig:
    def test_good(self, asset):
        path = asset("signing_config/signingconfig.v2.json")
        signing_config = SigningConfig.from_file(path)

        assert (
            signing_config._inner.media_type
            == SigningConfig.SigningConfigType.SIGNING_CONFIG_0_2.value
        )
        assert signing_config.get_fulcio_url() == "https://fulcio.example.com"
        assert signing_config.get_oidc_url() == "https://oauth2.example.com/auth"
        assert signing_config.get_tlog_urls() == ["https://rekor.example.com"]
        assert signing_config.get_tsa_urls() == [
            "https://timestamp.example.com/api/v1/timestamp"
        ]


class TestTrustedRoot:
    @pytest.mark.parametrize(
        "file",
        [
            "trusted_root/trustedroot.v1.json",
            "trusted_root/trustedroot.v1.local_tlog_ed25519_rekor-tiles.json",
        ],
    )
    def test_good(self, asset, file):
        """
        Ensures that the trusted_roots are well-formed and that the embedded keys are supported.
        """
        path = asset(file)
        root = TrustedRoot.from_file(path)

        assert (
            root._inner.media_type == TrustedRoot.TrustedRootType.TRUSTED_ROOT_0_1.value
        )
        assert len(root._inner.tlogs) == 1
        assert len(root._inner.certificate_authorities) == 2
        assert len(root._inner.ctlogs) == 2
        assert len(root._inner.timestamp_authorities) == 1
        assert root.rekor_keyring(KeyringPurpose.VERIFY) is not None
        assert root.ct_keyring(KeyringPurpose.VERIFY) is not None
        assert root.get_fulcio_certs() is not None
        assert root.get_timestamp_authorities() is not None

    def test_bad_media_type(self, asset):
        path = asset("trusted_root/trustedroot.badtype.json")

        with pytest.raises(
            Error, match="unsupported trusted root format: bad-media-type"
        ):
            TrustedRoot.from_file(path)


# TODO(ww): Move these into appropriate class-scoped tests.


def test_trust_root_tuf_caches_and_requests(mock_staging_tuf, tuf_dirs):
    # start with empty target cache, empty local metadata dir
    data_dir, cache_dir = tuf_dirs

    # keep track of requests the TrustUpdater invoked by TrustedRoot makes
    reqs, fail_reqs = mock_staging_tuf

    trust_config = ClientTrustConfig.staging()
    # metadata was "downloaded" from staging
    expected = [
        "root.json",
        "root_history",
        "snapshot.json",
        "targets.json",
        "timestamp.json",
    ]
    assert sorted(os.listdir(data_dir)) == expected

    # Expect requests of top-level metadata (and 404 for the next root version)
    # Don't expect trusted_root.json request as it's cached already
    expected_requests = {
        "timestamp.json": 1,
        "13.snapshot.json": 1,
        "13.targets.json": 1,
    }
    expected_fail_reqs = {"12.root.json": 1}
    assert reqs == expected_requests
    assert fail_reqs == expected_fail_reqs

    trust_config.trusted_root.ct_keyring(KeyringPurpose.VERIFY)
    trust_config.trusted_root.rekor_keyring(KeyringPurpose.VERIFY)

    # no new requests
    assert reqs == expected_requests
    assert fail_reqs == expected_fail_reqs

    # New trust root (and TrustUpdater instance), same cache dirs
    trust_config = ClientTrustConfig.staging()

    # Expect new timestamp and root requests
    expected_requests["timestamp.json"] += 1
    expected_fail_reqs["12.root.json"] += 1
    assert reqs == expected_requests
    assert fail_reqs == expected_fail_reqs

    trust_config.trusted_root.ct_keyring(purpose=KeyringPurpose.VERIFY)
    trust_config.trusted_root.rekor_keyring(purpose=KeyringPurpose.VERIFY)
    # Expect no requests
    assert reqs == expected_requests
    assert fail_reqs == expected_fail_reqs


def test_trust_root_tuf_offline(mock_staging_tuf, tuf_dirs):
    # start with empty target cache, empty local metadata dir
    data_dir, cache_dir = tuf_dirs

    # keep track of requests the TrustUpdater invoked by TrustedRoot makes
    reqs, fail_reqs = mock_staging_tuf

    trust_config = ClientTrustConfig.staging(offline=True)

    # local TUF metadata is not initialized, nothing is downloaded
    assert not os.path.exists(data_dir)
    assert reqs == {}
    assert fail_reqs == {}

    trust_config.trusted_root.ct_keyring(purpose=KeyringPurpose.VERIFY)
    trust_config.trusted_root.rekor_keyring(purpose=KeyringPurpose.VERIFY)

    # Still no requests
    assert reqs == {}
    assert fail_reqs == {}


def test_is_timerange_valid():
    def range_from(offset_lower=0, offset_upper=0):
        base = datetime.now(timezone.utc)
        return TimeRange(
            base + timedelta(minutes=offset_lower),
            base + timedelta(minutes=offset_upper),
        )

    # Test None should always be valid
    assert _is_timerange_valid(None, allow_expired=False)
    assert _is_timerange_valid(None, allow_expired=True)

    # Test lower bound conditions
    assert _is_timerange_valid(
        range_from(-1, 1), allow_expired=False
    )  # Valid: 1 ago, 1 from now
    assert not _is_timerange_valid(
        range_from(1, 1), allow_expired=False
    )  # Invalid: 1 from now, 1 from now

    # Test upper bound conditions
    assert not _is_timerange_valid(
        range_from(-1, -1), allow_expired=False
    )  # Invalid: 1 ago, 1 ago
    assert _is_timerange_valid(
        range_from(-1, -1), allow_expired=True
    )  # Valid: 1 ago, 1 ago


def test_trust_root_bundled_get(monkeypatch, mock_staging_tuf, tuf_asset):
    def get_public_bytes(keys):
        return [
            k.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
            for k in keys
        ]

    def _pem_keys(keys):
        return get_public_bytes([load_pem_public_key(k) for k in keys])

    ctfe_keys = _pem_keys(
        [
            tuf_asset.target("ctfe_2022_2.pub"),
        ]
    )
    rekor_keys = _pem_keys([tuf_asset.target("rekor.pub")])
    fulcio_certs = [
        load_pem_x509_certificate(c)
        for c in [
            tuf_asset.target("fulcio_intermediate.crt.pem"),
            tuf_asset.target("fulcio.crt.pem"),
        ]
    ]

    # Assert that trust root from TUF contains the expected keys/certs
    trust_root = ClientTrustConfig.staging().trusted_root
    assert ctfe_keys[0] in get_public_bytes(
        [
            k.key
            for k in trust_root.ct_keyring(
                purpose=KeyringPurpose.VERIFY
            )._keyring.values()
        ]
    )
    assert (
        get_public_bytes(
            [
                k.key
                for k in trust_root.rekor_keyring(
                    purpose=KeyringPurpose.VERIFY
                )._keyring.values()
            ]
        )
        == rekor_keys
    )
    assert trust_root.get_fulcio_certs() == fulcio_certs

    # Assert that trust root from offline TUF contains the expected keys/certs
    trust_root = ClientTrustConfig.staging(offline=True).trusted_root
    assert ctfe_keys[0] in get_public_bytes(
        [
            k.key
            for k in trust_root.ct_keyring(
                purpose=KeyringPurpose.VERIFY
            )._keyring.values()
        ]
    )
    assert (
        get_public_bytes(
            [
                k.key
                for k in trust_root.rekor_keyring(
                    purpose=KeyringPurpose.VERIFY
                )._keyring.values()
            ]
        )
        == rekor_keys
    )
    assert trust_root.get_fulcio_certs() == fulcio_certs

    # Assert that trust root from file contains the expected keys/certs
    path = tuf_asset.target_path("trusted_root.json")
    trust_root = TrustedRoot.from_file(path)
    assert ctfe_keys[0] in get_public_bytes(
        [
            k.key
            for k in trust_root.ct_keyring(
                purpose=KeyringPurpose.VERIFY
            )._keyring.values()
        ]
    )
    assert (
        get_public_bytes(
            [
                k.key
                for k in trust_root.rekor_keyring(
                    purpose=KeyringPurpose.VERIFY
                )._keyring.values()
            ]
        )
        == rekor_keys
    )
    assert trust_root.get_fulcio_certs() == fulcio_certs


def test_trust_root_tuf_instance_error():
    # Expect file not found since embedded root.json is not found and
    # no local metadata is found
    with pytest.raises(FileNotFoundError):
        ClientTrustConfig.from_tuf("foo.bar")


def test_trust_root_tuf_ctfe_keys_error(monkeypatch):
    trust_root = ClientTrustConfig.staging(offline=True).trusted_root
    monkeypatch.setattr(trust_root._inner, "ctlogs", [])
    with pytest.raises(Exception, match="CTFE keys not found in trusted root"):
        trust_root.ct_keyring(purpose=KeyringPurpose.VERIFY)


def test_trust_root_fulcio_certs_error(tuf_asset, monkeypatch):
    trust_root = ClientTrustConfig.staging(offline=True).trusted_root
    monkeypatch.setattr(trust_root._inner, "certificate_authorities", [])
    with pytest.raises(
        Exception, match="Fulcio certificates not found in trusted root"
    ):
        trust_root.get_fulcio_certs()


class TestClientTrustConfig:
    def test_good(self, asset):
        path = asset("trust_config/config.v1.json")
        config = ClientTrustConfig.from_json(path.read_text())

        assert isinstance(config.signing_config, SigningConfig)
        assert isinstance(config.trusted_root, TrustedRoot)

    def test_bad_media_type(self, asset):
        path = asset("trust_config/config.badtype.json")

        with pytest.raises(
            Error, match="unsupported client trust config format: bad-media-type"
        ):
            ClientTrustConfig.from_json(path.read_text())
