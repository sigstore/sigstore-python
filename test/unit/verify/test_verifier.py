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
from sigstore_protobuf_specs.dev.sigstore.common.v1 import HashAlgorithm

from sigstore._utils import sha256_streaming
from sigstore.hashes import Hashed
from sigstore.transparency import LogEntry
from sigstore.verify import policy
from sigstore.verify.models import (
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
    (file, materials) = signing_materials("a.txt")

    verifier = Verifier.staging()
    assert verifier.verify(file.read_bytes(), materials, null_policy)


@pytest.mark.online
def test_verifier_multiple_verifications(signing_materials, null_policy):
    a = signing_materials("a.txt")
    b = signing_materials("b.txt")

    verifier = Verifier.staging()
    for file, materials in [a, b]:
        assert verifier.verify(file.read_bytes(), materials, null_policy)


def test_verifier_offline(signing_bundle, null_policy, mock_staging_tuf):
    (file, materials) = signing_bundle("bundle.txt", offline=True)

    verifier = Verifier.staging()
    assert verifier.verify(file.read_bytes(), materials, null_policy)


def test_verify_result_boolish():
    assert not VerificationFailure(reason="foo")
    assert not CertificateVerificationFailure(reason="foo", exception=ValueError("bar"))
    assert VerificationSuccess()


@pytest.mark.online
def test_verifier_email_identity(signing_materials):
    (file, materials) = signing_materials("a.txt")
    policy_ = policy.Identity(
        identity="william@yossarian.net",
        issuer="https://github.com/login/oauth",
    )

    verifier = Verifier.staging()
    assert verifier.verify(
        file.read_bytes(),
        materials,
        policy_,
    )


@pytest.mark.online
def test_verifier_uri_identity(signing_materials):
    (file, materials) = signing_materials("c.txt")
    policy_ = policy.Identity(
        identity=(
            "https://github.com/sigstore/"
            "sigstore-python/.github/workflows/ci.yml@refs/pull/288/merge"
        ),
        issuer="https://token.actions.githubusercontent.com",
    )

    verifier = Verifier.staging()
    assert verifier.verify(
        file.read_bytes(),
        materials,
        policy_,
    )


@pytest.mark.online
def test_verifier_policy_check(signing_materials):
    (file, materials) = signing_materials("a.txt")

    # policy that fails to verify for any given cert.
    policy_ = pretend.stub(verify=lambda cert: False)

    verifier = Verifier.staging()
    assert not verifier.verify(
        file.read_bytes(),
        materials,
        policy_,
    )


@pytest.mark.online
def test_verifier_invalid_signature(signing_materials, null_policy):
    (file, materials) = signing_materials("bad.txt")

    verifier = Verifier.staging()
    assert not verifier.verify(file.read_bytes(), materials, null_policy)


@pytest.mark.online
def test_verifier_invalid_online_missing_inclusion_proof(
    signing_materials, null_policy, monkeypatch
):
    verifier = Verifier.staging()

    (file, materials) = signing_materials("a.txt")

    with file.open(mode="rb", buffering=0) as input_:
        digest = sha256_streaming(input_)
        hashed = Hashed(algorithm=HashAlgorithm.SHA2_256, digest=digest)

    # Retrieve the entry, strip its inclusion proof, stuff it back
    # into the materials, and then patch out the check that insures the
    # inclusion proof's presence.
    # This effectively emulates a "misbehaving" Rekor instance that returns
    # log entries without corresponding inclusion proofs.
    entry: LogEntry = materials.rekor_entry(hashed, verifier._rekor)
    entry.__dict__["inclusion_proof"] = None
    materials._rekor_entry = entry
    monkeypatch.setattr(materials, "rekor_entry", lambda *a: entry)

    result = verifier.verify(file.read_bytes(), materials, null_policy)
    assert not result
    assert result == VerificationFailure(reason="missing Rekor inclusion proof")


@pytest.mark.online
@pytest.mark.xfail
def test_verifier_fail_expiry(signing_materials, null_policy, monkeypatch):
    # FIXME(jl): can't mock:
    # - datetime.datetime.utcfromtimestamp: immutable type.
    # - entry.integrated_time: frozen dataclass.
    # - Certificate.not_valid_{before,after}: rust FFI.
    import datetime

    verifier = Verifier.staging()

    (file, materials) = signing_materials("a.txt")

    with file.open(mode="rb", buffering=0) as input_:
        digest = sha256_streaming(input_)
        hashed = Hashed(algorithm=HashAlgorithm.SHA2_256, digest=digest)

    entry = materials.rekor_entry(hashed, verifier._rekor)
    monkeypatch.setattr(entry, "integrated_time", datetime.MINYEAR)

    assert not verifier.verify(file.read_bytes(), materials, null_policy)
