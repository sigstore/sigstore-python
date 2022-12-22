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

from sigstore._internal.tuf import STAGING_TUF_URL, TrustUpdater, _get_dirs


def test_updater_staging_caches_and_requests(mock_staging_tuf, temp_home):
    # start with empty target cache, empty local metadata dir
    data_dir, cache_dir = _get_dirs(STAGING_TUF_URL)

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
        "snapshot.json": 1,
        "targets.json": 1,
        "timestamp.json": 1,
    }
    expected_fail_reqs = {"2.root.json": 1}
    assert reqs == expected_requests
    # Expect 404 from the next root version
    assert fail_reqs == expected_fail_reqs

    updater.get_rekor_key()
    # Expect request of the rekor key but nothing else
    expected_requests["rekor.pub"] = 1
    assert reqs == expected_requests
    assert fail_reqs == expected_fail_reqs

    updater.get_rekor_key()
    # Expect no requests
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
    expected_fail_reqs["2.root.json"] += 1
    assert reqs == expected_requests
    assert fail_reqs == expected_fail_reqs

    updater.get_rekor_key()
    # Expect no requests
    assert reqs == expected_requests
    assert fail_reqs == expected_fail_reqs


def test_updater_staging_get(mock_staging_tuf, temp_home, tuf_asset):
    """Test that one of the get-methods returns the expected content"""
    updater = TrustUpdater.staging()
    with open(tuf_asset("rekor.pub"), "rb") as f:
        assert updater.get_rekor_key() == f.read()
