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

import pretend
import pytest

from sigstore.dsse import _StatementBuilder, _Subject
from sigstore.errors import VerificationError
from sigstore.models import Bundle
from sigstore.verify import policy
from sigstore.verify.verifier import Verifier


@pytest.mark.production
def test_verifier_production():
    verifier = Verifier.production()
    assert verifier is not None


def test_verifier_staging(mock_staging_tuf):
    verifier = Verifier.staging()
    assert verifier is not None


@pytest.mark.staging
def test_verifier_one_verification(signing_materials, null_policy):
    verifier = Verifier.staging()

    (file, bundle) = signing_materials("a.txt", verifier._rekor)

    verifier.verify_artifact(file.read_bytes(), bundle, null_policy)


@pytest.mark.staging
def test_verifier_inconsistent_log_entry(signing_bundle, null_policy, mock_staging_tuf):
    (file, bundle) = signing_bundle("bundle_cve_2022_36056.txt")

    verifier = Verifier.staging()

    with pytest.raises(
        VerificationError,
        match="transparency log entry is inconsistent with other materials",
    ):
        verifier.verify_artifact(file.read_bytes(), bundle, null_policy)


@pytest.mark.staging
def test_verifier_multiple_verifications(signing_materials, null_policy):
    verifier = Verifier.staging()

    a = signing_materials("a.txt", verifier._rekor)
    b = signing_materials("b.txt", verifier._rekor)

    for file, bundle in [a, b]:
        verifier.verify_artifact(file.read_bytes(), bundle, null_policy)


@pytest.mark.parametrize(
    "filename", ("bundle.txt", "bundle_v3.txt", "bundle_v3_alt.txt")
)
def test_verifier_bundle(signing_bundle, null_policy, mock_staging_tuf, filename):
    (file, bundle) = signing_bundle(filename)

    verifier = Verifier.staging()
    verifier.verify_artifact(file.read_bytes(), bundle, null_policy)


@pytest.mark.staging
def test_verifier_email_identity(signing_materials):
    verifier = Verifier.staging()

    (file, bundle) = signing_materials("a.txt", verifier._rekor)
    policy_ = policy.Identity(
        identity="william@yossarian.net",
        issuer="https://github.com/login/oauth",
    )

    verifier.verify_artifact(
        file.read_bytes(),
        bundle,
        policy_,
    )


@pytest.mark.staging
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

    verifier.verify_artifact(
        file.read_bytes(),
        bundle,
        policy_,
    )


@pytest.mark.staging
def test_verifier_policy_check(signing_materials):
    verifier = Verifier.staging()
    (file, bundle) = signing_materials("a.txt", verifier._rekor)

    # policy that fails to verify for any given cert.
    policy_ = pretend.stub(verify=pretend.raiser(VerificationError("policy failed")))

    with pytest.raises(VerificationError, match="policy failed"):
        verifier.verify_artifact(
            file.read_bytes(),
            bundle,
            policy_,
        )


@pytest.mark.staging
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

    with pytest.raises(VerificationError):
        verifier.verify_artifact(file.read_bytes(), bundle, null_policy)


@pytest.mark.staging
@pytest.mark.ambient_oidc
def test_verifier_dsse_roundtrip(staging):
    signer_cls, verifier_cls, identity = staging

    ctx = signer_cls()
    stmt = (
        _StatementBuilder()
        .subjects(
            [_Subject(name="null", digest={"sha256": hashlib.sha256(b"").hexdigest()})]
        )
        .predicate_type("https://cosign.sigstore.dev/attestation/v1")
        .predicate(
            {
                "Data": "",
                "Timestamp": "2023-12-07T00:37:58Z",
            }
        )
    ).build()

    with ctx.signer(identity) as signer:
        bundle = signer.sign_dsse(stmt)

    verifier = verifier_cls()
    payload_type, payload = verifier.verify_dsse(bundle, policy.UnsafeNoOp())
    assert payload_type == "application/vnd.in-toto+json"
    assert payload == stmt._contents
