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
import pretend
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.x509 import load_pem_x509_certificate
from sigstore_protobuf_specs.dev.sigstore.common.v1 import TimeRange

from sigstore._internal.tuf import TrustUpdater, _is_timerange_valid
from sigstore._utils import load_der_public_key, load_pem_public_key
from sigstore.errors import RootError


def test_updater_staging_caches_and_requests(mock_staging_tuf, tuf_dirs):
    # start with empty target cache, empty local metadata dir
    data_dir, cache_dir = tuf_dirs

    # keep track of successful and failed requests TrustUpdater makes
    reqs, fail_reqs = mock_staging_tuf

    updater = TrustUpdater.staging()
    # Expect root.json bootstrapped from _store
    assert sorted(os.listdir(data_dir)) == ["root.json"]
    # Expect no requests happened
    assert reqs == {}
    assert fail_reqs == {}

    updater.get_ctfe_keys()
    # Expect local metadata to now contain all top-level metadata files
    expected = ["root.json", "snapshot.json", "targets.json", "timestamp.json"]
    assert sorted(os.listdir(data_dir)) == expected
    # Expect requests of top-level metadata, and the ctfe targets
    expected_requests = {
        "2.root.json": 1,
        "2.snapshot.json": 1,
        "2.targets.json": 1,
        "timestamp.json": 1,
        # trusted_root.json should not be requested, as it is cached locally
    }
    expected_fail_reqs = {"3.root.json": 1}

    assert reqs == expected_requests
    # Expect 404 from the next root version
    assert fail_reqs == expected_fail_reqs

    updater.get_rekor_keys()
    # Expect no requests, as the `get_ctfe_keys` should have populated the bundled trust root
    assert reqs == expected_requests
    assert fail_reqs == expected_fail_reqs

    # New Updater instance, same cache dirs
    updater = TrustUpdater.staging()
    # Expect no requests happened
    assert reqs == expected_requests
    assert fail_reqs == expected_fail_reqs

    updater.get_ctfe_keys()
    # Expect new timestamp and root requests
    expected_requests["timestamp.json"] += 1
    expected_fail_reqs["3.root.json"] += 1
    assert reqs == expected_requests
    assert fail_reqs == expected_fail_reqs

    updater.get_rekor_keys()
    # Expect no requests
    assert reqs == expected_requests
    assert fail_reqs == expected_fail_reqs


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


def test_bundled_get(monkeypatch, mock_staging_tuf, tuf_asset):
    # We don't strictly need to re-encode these keys as they are already DER,
    # but by doing so we are also validating the keys structurally.
    def _der_keys(keys):
        return [
            load_der_public_key(k).public_bytes(
                Encoding.DER, PublicFormat.SubjectPublicKeyInfo
            )
            for k in keys
        ]

    def _pem_keys(keys):
        return [
            load_pem_public_key(k).public_bytes(
                Encoding.DER, PublicFormat.SubjectPublicKeyInfo
            )
            for k in keys
        ]

    updater = TrustUpdater.staging()

    assert _der_keys(updater.get_ctfe_keys()) == _pem_keys(
        [
            tuf_asset.target("ctfe.pub"),
            tuf_asset.target("ctfe_2022.pub"),
            tuf_asset.target("ctfe_2022_2.pub"),
        ]
    )
    assert _der_keys(updater.get_rekor_keys()) == _pem_keys(
        [tuf_asset.target("rekor.pub")]
    )
    assert updater.get_fulcio_certs() == [
        load_pem_x509_certificate(c)
        for c in [
            tuf_asset.target("fulcio.crt.pem"),
            tuf_asset.target("fulcio_intermediate.crt.pem"),
        ]
    ]


def test_updater_instance_error():
    with pytest.raises(RootError):
        TrustUpdater("foo.bar")


def test_updater_ctfe_keys_error(monkeypatch):
    updater = TrustUpdater.staging()
    trusted_root = pretend.stub(ctlogs=[])
    monkeypatch.setattr(updater, "_get_trusted_root", lambda: trusted_root)
    with pytest.raises(Exception, match="CTFE keys not found in TUF metadata"):
        updater.get_ctfe_keys()


def test_updater_fulcio_certs_error(tuf_asset, monkeypatch):
    updater = TrustUpdater.staging()
    trusted_root = pretend.stub(certificate_authorities=[])
    monkeypatch.setattr(updater, "_get_trusted_root", lambda: trusted_root)
    with pytest.raises(
        Exception, match="Fulcio certificates not found in TUF metadata"
    ):
        updater.get_fulcio_certs()
