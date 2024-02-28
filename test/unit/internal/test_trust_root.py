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

from sigstore._internal.trustroot import TrustedRoot, _is_timerange_valid
from sigstore._utils import load_der_public_key, load_pem_public_key
from sigstore.errors import RootError


def test_trust_root_tuf_caches_and_requests(mock_staging_tuf, tuf_dirs):
    # start with empty target cache, empty local metadata dir
    data_dir, cache_dir = tuf_dirs

    # keep track of requests the TrustUpdater invoked by TrustedRoot makes
    reqs, fail_reqs = mock_staging_tuf

    trust_root = TrustedRoot.staging()
    # metadata was "downloaded" from staging
    expected = ["root.json", "snapshot.json", "targets.json", "timestamp.json"]
    assert sorted(os.listdir(data_dir)) == expected

    # Expect requests of top-level metadata (and 404 for the next root version)
    # Don't expect trusted_root.json request as it's cached already
    expected_requests = {
        "timestamp.json": 1,
        "4.snapshot.json": 1,
        "4.targets.json": 1,
    }
    expected_fail_reqs = {"5.root.json": 1}
    assert reqs == expected_requests
    assert fail_reqs == expected_fail_reqs

    trust_root.get_ctfe_keys()
    trust_root.get_rekor_keys()

    # no new requests
    assert reqs == expected_requests
    assert fail_reqs == expected_fail_reqs

    # New trust root (and TrustUpdater instance), same cache dirs
    trust_root = TrustedRoot.staging()

    # Expect new timestamp and root requests
    expected_requests["timestamp.json"] += 1
    expected_fail_reqs["5.root.json"] += 1
    assert reqs == expected_requests
    assert fail_reqs == expected_fail_reqs

    trust_root.get_ctfe_keys()
    trust_root.get_rekor_keys()
    # Expect no requests
    assert reqs == expected_requests
    assert fail_reqs == expected_fail_reqs


def test_trust_root_tuf_offline(mock_staging_tuf, tuf_dirs):
    # start with empty target cache, empty local metadata dir
    data_dir, cache_dir = tuf_dirs

    # keep track of requests the TrustUpdater invoked by TrustedRoot makes
    reqs, fail_reqs = mock_staging_tuf

    trust_root = TrustedRoot.staging(offline=True)

    # Only the embedded root is in local TUF metadata, nothing is downloaded
    expected = ["root.json"]
    assert sorted(os.listdir(data_dir)) == expected
    assert reqs == {}
    assert fail_reqs == {}

    trust_root.get_ctfe_keys()
    trust_root.get_rekor_keys()

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

    ctfe_keys = _pem_keys(
        [
            tuf_asset.target("ctfe.pub"),
            tuf_asset.target("ctfe_2022.pub"),
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
    trust_root = TrustedRoot.staging()
    assert _der_keys(trust_root.get_ctfe_keys()) == ctfe_keys
    assert _der_keys(trust_root.get_rekor_keys()) == rekor_keys
    assert trust_root.get_fulcio_certs() == fulcio_certs

    # Assert that trust root from offline TUF contains the expected keys/certs
    trust_root = TrustedRoot.staging(offline=True)
    assert _der_keys(trust_root.get_ctfe_keys()) == ctfe_keys
    assert _der_keys(trust_root.get_rekor_keys()) == rekor_keys
    assert trust_root.get_fulcio_certs() == fulcio_certs

    # Assert that trust root from file contains the expected keys/certs
    path = tuf_asset.target_path("trusted_root.json")
    trust_root = TrustedRoot.from_file(path)
    assert _der_keys(trust_root.get_ctfe_keys()) == ctfe_keys
    assert _der_keys(trust_root.get_rekor_keys()) == rekor_keys
    assert trust_root.get_fulcio_certs() == fulcio_certs


def test_trust_root_tuf_instance_error():
    with pytest.raises(RootError):
        TrustedRoot.from_tuf("foo.bar")


def test_trust_root_tuf_ctfe_keys_error(monkeypatch):
    trust_root = TrustedRoot.staging(offline=True)
    monkeypatch.setattr(trust_root, "ctlogs", [])
    with pytest.raises(Exception, match="Active CTFE keys not found in trusted root"):
        trust_root.get_ctfe_keys()


def test_trust_root_fulcio_certs_error(tuf_asset, monkeypatch):
    trust_root = TrustedRoot.staging(offline=True)
    monkeypatch.setattr(trust_root, "certificate_authorities", [])
    with pytest.raises(
        Exception, match="Fulcio certificates not found in trusted root"
    ):
        trust_root.get_fulcio_certs()
