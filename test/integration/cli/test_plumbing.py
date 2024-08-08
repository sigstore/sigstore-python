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


import pytest
from sigstore_protobuf_specs.dev.sigstore.common.v1 import HashAlgorithm

from sigstore.hashes import Hashed
from sigstore.models import Bundle, InvalidBundle
from sigstore.verify import policy
from sigstore.verify.verifier import Verifier


def test_fix_bundle_fixes_missing_checkpoint(capsys, sigstore, asset):
    invalid_bundle = asset("Python-3.12.5.tgz.sigstore")

    # The bundle is invalid, because it's missing a checkpoint
    # for its inclusion proof.
    with pytest.raises(
        InvalidBundle, match="entry must contain inclusion proof, with checkpoint"
    ):
        Bundle.from_json(invalid_bundle.read_text())

    # Running `sigstore plumbing fix-bundle` emits a fixed bundle.
    sigstore("plumbing", "fix-bundle", "--bundle", str(invalid_bundle))

    captures = capsys.readouterr()

    # The bundle now loads correctly.
    bundle = Bundle.from_json(captures.out)

    # We didn't pass `--upgrade-version` so the version is still v0.1.
    assert bundle._inner.media_type == Bundle.BundleType.BUNDLE_0_1

    # ...and the fixed bundle can now be used to verify the `Python-3.12.5.tgz`
    # release.
    verifier = Verifier.production()
    verifier.verify_artifact(
        Hashed(
            algorithm=HashAlgorithm.SHA2_256,
            digest=bytes.fromhex(
                "38dc4e2c261d49c661196066edbfb70fdb16be4a79cc8220c224dfeb5636d405"
            ),
        ),
        bundle,
        policy.AllOf(
            [
                policy.Identity(
                    identity="thomas@python.org", issuer="https://accounts.google.com"
                )
            ]
        ),
    )


def test_fix_bundle_upgrades_bundle(capsys, sigstore, asset):
    invalid_bundle = asset("Python-3.12.5.tgz.sigstore")

    # Running `sigstore plumbing fix-bundle --upgrade-version`
    # emits a fixed bundle.
    sigstore(
        "plumbing", "fix-bundle", "--upgrade-version", "--bundle", str(invalid_bundle)
    )

    captures = capsys.readouterr()

    # The bundle now loads correctly.
    bundle = Bundle.from_json(captures.out)

    # The bundle is now the latest version (v0.3).
    assert bundle._inner.media_type == Bundle.BundleType.BUNDLE_0_3

    # ...and the upgraded (and fixed) bundle can still verify
    # the release.
    # ...and the fixed can now be used to verify the `Python-3.12.5.tgz` release.
    verifier = Verifier.production()
    verifier.verify_artifact(
        Hashed(
            algorithm=HashAlgorithm.SHA2_256,
            digest=bytes.fromhex(
                "38dc4e2c261d49c661196066edbfb70fdb16be4a79cc8220c224dfeb5636d405"
            ),
        ),
        bundle,
        policy.AllOf(
            [
                policy.Identity(
                    identity="thomas@python.org", issuer="https://accounts.google.com"
                )
            ]
        ),
    )
