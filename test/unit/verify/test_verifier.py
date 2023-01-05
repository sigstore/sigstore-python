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

import pretend
import pytest

from sigstore._verify import policy
from sigstore._verify.models import VerificationFailure, VerificationSuccess
from sigstore._verify.verifier import CertificateVerificationFailure, Verifier


@pytest.mark.online
def test_verifier_production():
    verifier = Verifier.production()
    assert verifier is not None


def test_verifier_staging(mock_staging_tuf):
    verifier = Verifier.staging()
    assert verifier is not None


@pytest.mark.online
def test_verifier_one_verification(signing_materials, null_policy):
    materials = signing_materials("a.txt")

    verifier = Verifier.staging()
    assert verifier.verify(materials, null_policy)


@pytest.mark.online
def test_verifier_multiple_verifications(signing_materials, null_policy):
    a_materials = signing_materials("a.txt")
    b_materials = signing_materials("b.txt")

    verifier = Verifier.staging()
    for materials in [a_materials, b_materials]:
        assert verifier.verify(materials, null_policy)


def test_verifier_offline_rekor_bundle(
    signing_materials, null_policy, mock_staging_tuf
):
    materials = signing_materials("offline-rekor.txt")

    verifier = Verifier.staging()
    assert verifier.verify(materials, null_policy)


def test_verify_result_boolish():
    assert not VerificationFailure(reason="foo")
    assert not CertificateVerificationFailure(reason="foo", exception=ValueError("bar"))
    assert VerificationSuccess()


@pytest.mark.online
def test_verifier_email_identity(signing_materials):
    materials = signing_materials("a.txt")
    policy_ = policy.Identity(
        identity="william@yossarian.net",
        issuer="https://github.com/login/oauth",
    )

    verifier = Verifier.staging()
    assert verifier.verify(
        materials,
        policy_,
    )


@pytest.mark.online
def test_verifier_uri_identity(signing_materials):
    materials = signing_materials("c.txt")
    policy_ = policy.Identity(
        identity=(
            "https://github.com/sigstore/"
            "sigstore-python/.github/workflows/ci.yml@refs/pull/288/merge"
        ),
        issuer="https://token.actions.githubusercontent.com",
    )

    verifier = Verifier.staging()
    assert verifier.verify(
        materials,
        policy_,
    )


@pytest.mark.online
def test_verifier_policy_check(signing_materials):
    materials = signing_materials("a.txt")

    # policy that fails to verify for any given cert.
    policy_ = pretend.stub(verify=pretend.call_recorder(lambda cert: False))

    verifier = Verifier.staging()
    assert not verifier.verify(
        materials,
        policy_,
    )


def test_verifier_bad_source(signing_materials, null_policy, monkeypatch):
    materials = signing_materials("bad.txt")

    verifier = Verifier.staging()
    assert not verifier.verify(materials, null_policy)
