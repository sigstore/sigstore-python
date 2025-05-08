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
import logging
from datetime import datetime, timezone

import pretend
import pytest
import rfc3161_client

from sigstore._internal.trust import CertificateAuthority
from sigstore.dsse import StatementBuilder, Subject
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


@pytest.mark.online
@pytest.mark.parametrize(
    "filename", ("bundle.txt", "bundle_v3.txt", "bundle_v3_alt.txt")
)
def test_verifier_bundle(signing_bundle, null_policy, filename):
    (file, bundle) = signing_bundle(filename)

    verifier = Verifier.staging()
    verifier.verify_artifact(file.read_bytes(), bundle, null_policy)


@pytest.mark.parametrize(
    "filename", ("bundle.txt", "bundle_v3.txt", "bundle_v3_alt.txt")
)
def test_verifier_bundle_offline(signing_bundle, null_policy, filename):
    (file, bundle) = signing_bundle(filename)

    verifier = Verifier.staging(offline=True)
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
        StatementBuilder()
        .subjects(
            [Subject(name="null", digest={"sha256": hashlib.sha256(b"").hexdigest()})]
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


class TestVerifierWithTimestamp:
    @pytest.fixture
    def verifier(self, asset) -> Verifier:
        """Returns a Verifier with Timestamp Authorities set."""
        verifier = Verifier.staging(offline=True)
        authority = CertificateAuthority.from_json(asset("tsa/ca.json").as_posix())
        verifier._trusted_root._inner.timestamp_authorities = [authority._inner]
        return verifier

    def test_verifier_verify_timestamp(self, verifier, asset, null_policy):
        verifier.verify_artifact(
            asset("tsa/bundle.txt").read_bytes(),
            Bundle.from_json(asset("tsa/bundle.txt.sigstore").read_bytes()),
            null_policy,
        )

    def test_verifier_no_validity_end(self, verifier, asset, null_policy):
        verifier._trusted_root.get_timestamp_authorities()[
            0
        ]._inner.valid_for.end = None
        verifier.verify_artifact(
            asset("tsa/bundle.txt").read_bytes(),
            Bundle.from_json(asset("tsa/bundle.txt.sigstore").read_bytes()),
            null_policy,
        )

    def test_verifier_without_timestamp(
        self, verifier, asset, null_policy, monkeypatch
    ):
        monkeypatch.setattr(verifier, "_establish_time", lambda *args: [])
        with pytest.raises(VerificationError, match="not enough sources"):
            verifier.verify_artifact(
                asset("tsa/bundle.txt").read_bytes(),
                Bundle.from_json(asset("tsa/bundle.txt.sigstore").read_bytes()),
                null_policy,
            )

    def test_verifier_too_many_timestamp(self, verifier, asset, null_policy):
        with pytest.raises(VerificationError, match="too many"):
            verifier.verify_artifact(
                asset("tsa/bundle.txt").read_bytes(),
                Bundle.from_json(
                    asset("tsa/bundle.many_timestamp.sigstore").read_bytes()
                ),
                null_policy,
            )

    def test_verifier_duplicate_timestamp(self, verifier, asset, null_policy):
        with pytest.raises(VerificationError, match="duplicate"):
            verifier.verify_artifact(
                asset("tsa/bundle.txt").read_bytes(),
                Bundle.from_json(asset("tsa/bundle.duplicate.sigstore").read_bytes()),
                null_policy,
            )

    def test_verifier_outside_validity_range(
        self, caplog, verifier, asset, null_policy
    ):
        # Set a date before the timestamp range
        verifier._trusted_root.get_timestamp_authorities()[
            0
        ]._inner.valid_for.end = datetime(2024, 10, 31, tzinfo=timezone.utc)

        with caplog.at_level(logging.DEBUG, logger="sigstore.verify.verifier"):
            with pytest.raises(VerificationError, match="not enough timestamps"):
                verifier.verify_artifact(
                    asset("tsa/bundle.txt").read_bytes(),
                    Bundle.from_json(asset("tsa/bundle.txt.sigstore").read_bytes()),
                    null_policy,
                )

        assert (
            "Unable to verify Timestamp because not in CA time range."
            == caplog.records[0].message
        )

    def test_verifier_rfc3161_error(
        self, verifier, asset, null_policy, caplog, monkeypatch
    ):
        def verify_function(*args):
            raise rfc3161_client.VerificationError()

        monkeypatch.setattr(rfc3161_client.verify._Verifier, "verify", verify_function)

        with caplog.at_level(logging.DEBUG, logger="sigstore.verify.verifier"):
            with pytest.raises(VerificationError, match="not enough timestamps"):
                verifier.verify_artifact(
                    asset("tsa/bundle.txt").read_bytes(),
                    Bundle.from_json(asset("tsa/bundle.txt.sigstore").read_bytes()),
                    null_policy,
                )

        assert caplog.records[0].message == "Unable to verify Timestamp with CA."

    def test_verifier_no_authorities(self, asset, null_policy):
        verifier = Verifier.staging(offline=True)
        verifier._trusted_root._inner.timestamp_authorities = []

        with pytest.raises(VerificationError, match="no Timestamp Authorities"):
            verifier.verify_artifact(
                asset("tsa/bundle.txt").read_bytes(),
                Bundle.from_json(asset("tsa/bundle.txt.sigstore").read_bytes()),
                null_policy,
            )

    def test_verifier_not_enough_timestamp(
        self, verifier, asset, null_policy, monkeypatch
    ):
        monkeypatch.setattr("sigstore.verify.verifier.VERIFY_TIMESTAMP_THRESHOLD", 2)
        with pytest.raises(VerificationError, match="not enough timestamps"):
            verifier.verify_artifact(
                asset("tsa/bundle.txt").read_bytes(),
                Bundle.from_json(asset("tsa/bundle.txt.sigstore").read_bytes()),
                null_policy,
            )
