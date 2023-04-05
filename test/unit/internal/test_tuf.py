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
from sigstore_protobuf_specs.dev.sigstore.common.v1 import TimeRange

from sigstore._internal.tuf import TrustUpdater, _is_timerange_valid


def test_updater_staging_caches_and_requests(mock_staging_tuf, tuf_dirs):
    def consistent_targets_match(consistent_targets, targets):
        for t in consistent_targets:
            if os.path.basename(t) not in targets:
                return False
        return True

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
        "ctfe.pub": 1,
        "ctfe_2022.pub": 1,
        "ctfe_2022_2.pub": 1,
        "2.root.json": 1,
        "2.snapshot.json": 1,
        "2.targets.json": 1,
        "2.timestamp.json": 1,
        "timestamp.json": 1,
        "6494317303d0e04509a30b239bf8290057164fba67072b6f89ddf1032273a78b.trusted_root.json": 1,
    }
    expected_fail_reqs = {"3.root.json": 1}
    assert consistent_targets_match(reqs, expected_requests)
    # Expect 404 from the next root version
    assert consistent_targets_match(fail_reqs, expected_fail_reqs)

    updater.get_rekor_keys()
    # Expect request of the rekor key but nothing else
    expected_requests["rekor.pub"] = 1
    assert consistent_targets_match(reqs, expected_requests)
    assert consistent_targets_match(fail_reqs, expected_fail_reqs)

    updater.get_rekor_keys()
    # Expect no requests
    assert consistent_targets_match(reqs, expected_requests)
    assert consistent_targets_match(fail_reqs, expected_fail_reqs)

    # New Updater instance, same cache dirs
    updater = TrustUpdater.staging()
    # Expect no requests happened
    assert consistent_targets_match(reqs, expected_requests)
    assert consistent_targets_match(fail_reqs, expected_fail_reqs)

    updater.get_ctfe_keys()
    # Expect new timestamp and root requests
    expected_requests["timestamp.json"] += 1
    expected_fail_reqs["3.root.json"] += 1
    assert consistent_targets_match(reqs, expected_requests)
    assert consistent_targets_match(fail_reqs, expected_fail_reqs)

    updater.get_rekor_keys()
    # Expect no requests
    assert consistent_targets_match(reqs, expected_requests)
    assert consistent_targets_match(fail_reqs, expected_fail_reqs)


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


@pytest.mark.skip
def test_updater_staging_get(mock_staging_tuf, tuf_asset):
    """Test that one of the get-methods returns the expected content"""
    updater = TrustUpdater.staging()
    with open(
        tuf_asset(
            "targets/1d80b8f72505a43e65e6e125247cd508f61b459dc457c1d1bcb78d96e1760959.rekor.pub"
        ),
        "rb",
    ) as f:
        assert updater.get_rekor_keys() == [f.read()]


def test_updater_instance_error():
    with pytest.raises(Exception, match="TUF root not found in"):
        TrustUpdater("foo.bar")


def test_updater_ctfe_keys_error(monkeypatch):
    updater = TrustUpdater.staging()
    # getter returns no keys.
    monkeypatch.setattr(updater, "_get", lambda usage, statuses: [])
    monkeypatch.setattr(updater, "_get_trusted_root", lambda: None)
    with pytest.raises(Exception, match="CTFE keys not found in TUF metadata"):
        updater.get_ctfe_keys()


@pytest.mark.skip
def test_updater_rekor_keys_error(tuf_asset, monkeypatch):
    updater = TrustUpdater.staging()
    with open(
        tuf_asset(
            "targets/1d80b8f72505a43e65e6e125247cd508f61b459dc457c1d1bcb78d96e1760959.rekor.pub"
        ),
        "rb",
    ) as f:
        rekor_key = f.read()
        # getter returns duplicate copy of `rekor_key`.
        monkeypatch.setattr(
            updater,
            "_get",
            lambda usage, statuses: [rekor_key, rekor_key],
        )
    monkeypatch.setattr(updater, "_get_trusted_root", lambda: None)

    with pytest.raises(
        Exception, match="Did not find one active Rekor key in TUF metadata"
    ):
        updater.get_rekor_keys()


def test_updater_fulcio_certs_error(tuf_asset, monkeypatch):
    updater = TrustUpdater.staging()
    # getter returns no fulcio certs.
    monkeypatch.setattr(updater, "_get", lambda usage, statuses: [])
    monkeypatch.setattr(updater, "_get_trusted_root", lambda: None)
    with pytest.raises(
        Exception, match="Fulcio certificates not found in TUF metadata"
    ):
        updater.get_fulcio_certs()
