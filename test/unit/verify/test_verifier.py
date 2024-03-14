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

from sigstore.verify import policy
from sigstore.verify.models import (
    Bundle,
    VerificationFailure,
    VerificationSuccess,
)
from sigstore.verify.verifier import CertificateVerificationFailure, Verifier


@pytest.mark.online
def test_verifier_production():
    verifier = Verifier.production()
    assert verifier is not None


def test_verifier_staging(mock_staging_tuf):
    verifier = Verifier.staging()
    assert verifier is not None


@pytest.mark.online
def test_verifier_one_verification(signing_materials, null_policy):
    verifier = Verifier.staging()

    (file, bundle) = signing_materials("a.txt", verifier._rekor)

    assert verifier.verify(file.read_bytes(), bundle, null_policy)


@pytest.mark.online
def test_verifier_multiple_verifications(signing_materials, null_policy):
    verifier = Verifier.staging()

    a = signing_materials("a.txt", verifier._rekor)
    b = signing_materials("b.txt", verifier._rekor)

    for file, bundle in [a, b]:
        assert verifier.verify(file.read_bytes(), bundle, null_policy)


def test_verifier_bundle(signing_bundle, null_policy, mock_staging_tuf):
    (file, bundle) = signing_bundle("bundle.txt")

    verifier = Verifier.staging()
    assert verifier.verify(file.read_bytes(), bundle, null_policy)


def test_verify_result_boolish():
    assert not VerificationFailure(reason="foo")
    assert not CertificateVerificationFailure(reason="foo", exception=ValueError("bar"))
    assert VerificationSuccess()


@pytest.mark.online
def test_verifier_email_identity(signing_materials):
    verifier = Verifier.staging()

    (file, bundle) = signing_materials("a.txt", verifier._rekor)
    policy_ = policy.Identity(
        identity="william@yossarian.net",
        issuer="https://github.com/login/oauth",
    )

    assert verifier.verify(
        file.read_bytes(),
        bundle,
        policy_,
    )


@pytest.mark.online
def test_verifier_uri_identity(signing_materials):
    verifier = Verifier.staging()
    (file, bundle) = signing_materials("c.txt", verifier._rekor)
    policy_ = policy.Identity(
        identity=(
            "https://github.com/sigstore/"
            "sigstore-python/.github/workflows/ci.yml@refs/pull/288/merge"
        ),
        issuer="https://token.actions.githubusercontent.com",
    )

    assert verifier.verify(
        file.read_bytes(),
        bundle,
        policy_,
    )


@pytest.mark.online
def test_verifier_policy_check(signing_materials):
    verifier = Verifier.staging()
    (file, bundle) = signing_materials("a.txt", verifier._rekor)

    # policy that fails to verify for any given cert.
    policy_ = pretend.stub(verify=lambda cert: False)

    assert not verifier.verify(
        file.read_bytes(),
        bundle,
        policy_,
    )


@pytest.mark.online
@pytest.mark.xfail
def test_verifier_fail_expiry(signing_materials, null_policy, monkeypatch):
    # FIXME(jl): can't mock:
    # - datetime.datetime.utcfromtimestamp: immutable type.
    # - entry.integrated_time: frozen dataclass.
    # - Certificate.not_valid_{before,after}: rust FFI.
    import datetime

    verifier = Verifier.staging()

    bundle: Bundle
    (file, bundle) = signing_materials("a.txt", verifier._rekor)

    entry = bundle._inner.verification_material.tlog_entries[0]
    entry.integrated_time = datetime.MINYEAR

    assert not verifier.verify(file.read_bytes(), bundle, null_policy)
