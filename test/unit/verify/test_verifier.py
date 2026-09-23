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


import base64
import copy
import hashlib
import json
import logging
from datetime import datetime, timezone

import pretend
import pytest
import rfc3161_client
from sigstore_models.trustroot import v1 as trustroot_v1

from sigstore._internal.trust import CertificateAuthority, KeyringPurpose
from sigstore._utils import sha256_digest
from sigstore.dsse import StatementBuilder, Subject
from sigstore.errors import CertValidationError, VerificationError
from sigstore.models import Bundle, TransparencyLogEntry, TrustedRoot
from sigstore.verify import policy
from sigstore.verify.verifier import Verifier


def test_verifier_rejects_trusted_root_without_tlogs(asset):
    """
    A trusted root carrying no transparency log instances should surface a
    VerificationError, not an IndexError from indexing an empty list.
    """
    raw = json.loads(asset("trusted_root/trustedroot.v1.json").read_bytes())
    raw["tlogs"] = []
    trusted_root = TrustedRoot(
        trustroot_v1.TrustedRoot.from_json(json.dumps(raw).encode())
    )

    # the certificate authorities are left intact, so this reaches the tlog
    # lookup rather than failing earlier in get_fulcio_certs()
    assert trusted_root.get_fulcio_certs()

    with pytest.raises(VerificationError, match="no transparency log"):
        Verifier(trusted_root=trusted_root)


@pytest.mark.production
def test_verifier_production():
    verifier = Verifier.production()
    assert verifier is not None


@pytest.mark.staging
def test_verifier_staging():
    verifier = Verifier.staging()
    assert verifier is not None


@pytest.mark.staging
def test_verifier_one_verification(signing_materials, null_policy):
    verifier = Verifier.staging()

    (file, bundle) = signing_materials("a.txt", verifier._rekor)

    verifier.verify_artifact(file.read_bytes(), bundle, null_policy)


@pytest.mark.staging
def test_verifier_inconsistent_log_entry(signing_bundle, null_policy):
    (file, bundle) = signing_bundle("bundle_cve_2022_36056.txt")

    verifier = Verifier.staging()

    with pytest.raises(
        VerificationError,
        match="transparency log entry is inconsistent with other materials",
    ):
        verifier.verify_artifact(file.read_bytes(), bundle, null_policy)


@pytest.mark.staging
def test_verifier_digest_mismatch(signing_bundle, null_policy):
    """The signature is over correct content, but digest documented in bundle is wrong"""
    (file, bundle) = signing_bundle("bundle.txt")
    bundle._inner.message_signature.message_digest.digest = b""

    verifier = Verifier.staging()
    with pytest.raises(
        VerificationError,
        match="digest mismatch",
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
    "filename",
    ("bundle.txt", "bundle_v3.txt", "bundle_v3_alt.txt", "staging-rekor-v2.txt"),
)
def test_verifier_bundle_artifact(signing_bundle, null_policy, filename):
    (file, bundle) = signing_bundle(filename)

    verifier = Verifier.staging()
    verifier.verify_artifact(file.read_bytes(), bundle, null_policy)


@pytest.mark.online
@pytest.mark.parametrize(
    "filename",
    ("a.dsse.staging-rekor-v2.txt",),
)
def test_verifier_bundle_dsse(signing_bundle, null_policy, filename):
    (file, bundle) = signing_bundle(filename)

    verifier = Verifier.staging()
    verifier.verify_dsse(bundle, null_policy)


@pytest.mark.parametrize(
    "filename", ("bundle.txt", "bundle_v3.txt", "bundle_v3_alt.txt")
)
def test_verifier_bundle_offline(signing_bundle, null_policy, filename):
    (file, bundle) = signing_bundle(filename)

    verifier = Verifier.staging(offline=True)
    verifier.verify_artifact(file.read_bytes(), bundle, null_policy)


def test_verifier_tlog_threshold_one_accepts_one_valid_entry(
    signing_bundle, null_policy
):
    file, bundle = signing_bundle("bundle.txt")
    raw = json.loads(bundle.to_json())

    extra = copy.deepcopy(raw["verificationMaterial"]["tlogEntries"][0])
    extra["logId"]["keyId"] = base64.b64encode(b"\x01" * 32).decode()
    raw["verificationMaterial"]["tlogEntries"].append(extra)

    bundle = Bundle.from_json(json.dumps(raw))
    verifier = Verifier.staging(offline=True)

    verifier.verify_artifact(file.read_bytes(), bundle, null_policy)


def test_verifier_rejects_duplicate_tlog_entries(signing_bundle, null_policy):
    file, bundle = signing_bundle("bundle.txt")
    raw = json.loads(bundle.to_json())

    raw["verificationMaterial"]["tlogEntries"].append(
        copy.deepcopy(raw["verificationMaterial"]["tlogEntries"][0])
    )

    bundle = Bundle.from_json(json.dumps(raw))
    verifier = Verifier.staging(offline=True)

    with pytest.raises(
        VerificationError,
        match="duplicate transparency log entry",
    ):
        verifier.verify_artifact(file.read_bytes(), bundle, null_policy)


def test_verifier_tlog_threshold_requires_operator_metadata(
    signing_bundle, null_policy
):
    file, bundle = signing_bundle("bundle.txt")
    verifier = Verifier.staging(offline=True, tlog_threshold=2)

    with pytest.raises(
        VerificationError,
        match="operator metadata is required",
    ):
        verifier.verify_artifact(file.read_bytes(), bundle, null_policy)


def test_verifier_rejects_invalid_tlog_threshold():
    with pytest.raises(
        ValueError,
        match="transparency log threshold must be at least 1",
    ):
        Verifier.staging(offline=True, tlog_threshold=0)


def _add_synthetic_second_tlog_entry(
    bundle: Bundle,
    log_id: bytes,
) -> TransparencyLogEntry:
    second_inner = copy.deepcopy(bundle._log_entries[0]._inner)
    second_inner.log_id.key_id = log_id
    second_inner.log_index = type(second_inner.log_index)(
        int(second_inner.log_index) + 1
    )

    second = TransparencyLogEntry(second_inner)
    bundle._log_entries.append(second)
    return second


def _configure_two_tlog_operators(
    verifier: Verifier,
    bundle: Bundle,
    *,
    same_operator: bool,
) -> None:
    first_entry_id = bundle._log_entries[0]._inner.log_id.key_id
    trusted_tlogs = verifier._trusted_root._rekor_tlogs(KeyringPurpose.VERIFY)

    first_tlog = copy.deepcopy(
        next(tlog for tlog in trusted_tlogs if tlog.log_id.key_id == first_entry_id)
    )
    second_tlog = copy.deepcopy(
        next(tlog for tlog in trusted_tlogs if tlog.log_id.key_id != first_entry_id)
    )

    first_tlog.operator = "operator-a.example"
    second_tlog.operator = (
        "operator-a.example" if same_operator else "operator-b.example"
    )

    verifier._trusted_root._inner.tlogs = [first_tlog, second_tlog]
    _add_synthetic_second_tlog_entry(bundle, second_tlog.log_id.key_id)


def test_verifier_tlog_threshold_counts_distinct_operators(
    signing_bundle, null_policy, monkeypatch
):
    file, bundle = signing_bundle("bundle.txt")
    verifier = Verifier.staging(offline=True, tlog_threshold=2)
    _configure_two_tlog_operators(
        verifier,
        bundle,
        same_operator=False,
    )

    # Quorum counting is the behavior under test here. The normal cryptographic
    # verification path is covered by the existing verifier tests and by the
    # threshold-1 multi-entry test above.
    monkeypatch.setattr(
        TransparencyLogEntry,
        "_verify",
        lambda self, keyring: None,
    )

    verifier.verify_artifact(file.read_bytes(), bundle, null_policy)


def test_verifier_tlog_threshold_counts_operator_once(
    signing_bundle, null_policy, monkeypatch
):
    file, bundle = signing_bundle("bundle.txt")
    verifier = Verifier.staging(offline=True, tlog_threshold=2)
    _configure_two_tlog_operators(
        verifier,
        bundle,
        same_operator=True,
    )

    monkeypatch.setattr(
        TransparencyLogEntry,
        "_verify",
        lambda self, keyring: None,
    )

    with pytest.raises(
        VerificationError,
        match=r"transparency log threshold not met: 1 < 2",
    ):
        verifier.verify_artifact(file.read_bytes(), bundle, null_policy)


def test_verifier_certificate_chain_rejects_invalid_time(signing_bundle):
    file, bundle = signing_bundle("bundle.txt")
    verifier = Verifier.staging(offline=True)
    tlog_timestamps = verifier._verify_tlog_entries(
        bundle, sha256_digest(file.read_bytes())
    )
    timestamp = verifier._establish_time(bundle, tlog_timestamps)[0]
    timestamp.time = datetime(2000, 1, 1, tzinfo=timezone.utc)

    with pytest.raises(
        CertValidationError, match="failed to build timestamp certificate chain"
    ):
        verifier._verify_chain_at_time(bundle.signing_certificate, timestamp)


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

    def test_verifier_verify_timestamp(self, verifier, asset, null_policy, monkeypatch):
        # asset is a rekor v1 bundle: set threshold to 2 so both integrated time and the
        # TSA timestamp are required
        monkeypatch.setattr("sigstore.verify.verifier.VERIFIED_TIME_THRESHOLD", 2)

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

    @pytest.mark.parametrize(
        "fields_to_delete",
        (
            [],
            ["inclusionPromise"],
            # integratedTime is required to verify the inclusionPromise.
            pytest.param(["integratedTime"], marks=pytest.mark.xfail),
            ["inclusionPromise", "integratedTime"],
        ),
    )
    def test_verifier_verify_no_inclusion_promise_and_integrated_time(
        self, verifier, asset, null_policy, fields_to_delete
    ):
        """
        Ensure that we can still verify a Bundle with an RFC 3161 timestamp if the SET isn't present.

        There is one exception: When inclusionPromise is present, but integratedTime is not, then we expect a failure
        because the integratedTime is required to verify the inclusionPromise.
        """
        bundle_dict = json.loads(asset("tsa/bundle.txt.sigstore").read_bytes())
        (entry_dict,) = bundle_dict["verificationMaterial"]["tlogEntries"]
        for field in fields_to_delete:
            del entry_dict[field]
        # Bundle.from_json() also validates the bundle's layout.
        bundle = Bundle.from_json(json.dumps(bundle_dict))
        verifier.verify_artifact(
            asset("tsa/bundle.txt").read_bytes(),
            bundle,
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
        self, caplog, verifier, asset, null_policy, monkeypatch
    ):
        # asset is a rekor v1 bundle: set threshold to 2 so both integrated time and the
        # TSA timestamp are required
        monkeypatch.setattr("sigstore.verify.verifier.VERIFIED_TIME_THRESHOLD", 2)

        # Set a date before the timestamp range
        verifier._trusted_root.get_timestamp_authorities()[
            0
        ]._inner.valid_for.end = datetime(2024, 10, 31, tzinfo=timezone.utc)

        with caplog.at_level(logging.DEBUG, logger="sigstore.verify.verifier"):
            with pytest.raises(
                VerificationError, match="not enough sources of verified time"
            ):
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
        # asset is a rekor v1 bundle: set threshold to 2 so both integrated time and the
        # TSA timestamp are required
        monkeypatch.setattr("sigstore.verify.verifier.VERIFIED_TIME_THRESHOLD", 2)

        def verify_function(*args):
            raise rfc3161_client.VerificationError()

        monkeypatch.setattr(rfc3161_client.verify._Verifier, "verify", verify_function)

        with caplog.at_level(logging.DEBUG, logger="sigstore.verify.verifier"):
            with pytest.raises(
                VerificationError, match="not enough sources of verified time"
            ):
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

    def test_late_timestamp(self, caplog, verifier, asset, null_policy, monkeypatch):
        """
        Ensures that verifying the signing certificate fails because the timestamp
        is outside the certificate's validity window. The sample bundle
        "tsa/bundle.txt.late_timestamp.sigstore" was generated by adding `time.sleep(12*60)`
        into `sigstore.sign.Signer._finalize_sign()`, just after the entry is posted to Rekor
        but before the timestamp is requested.
        """
        # asset is a rekor v1 bundle: set threshold to 2 so both integrated time and the
        # TSA timestamp are required
        monkeypatch.setattr("sigstore.verify.verifier.VERIFIED_TIME_THRESHOLD", 2)

        with pytest.raises(
            VerificationError, match="not enough sources of verified time"
        ):
            verifier.verify_artifact(
                asset("tsa/bundle.txt").read_bytes(),
                Bundle.from_json(
                    asset("tsa/bundle.txt.late_timestamp.sigstore").read_bytes()
                ),
                null_policy,
            )

    def test_verifier_not_enough_timestamp(
        self, verifier, asset, null_policy, monkeypatch
    ):
        # asset is a rekor v1 bundle: set threshold to 3 so integrated time and one
        # TSA timestamp are not enough
        monkeypatch.setattr("sigstore.verify.verifier.VERIFIED_TIME_THRESHOLD", 3)
        with pytest.raises(
            VerificationError, match="not enough sources of verified time"
        ):
            verifier.verify_artifact(
                asset("tsa/bundle.txt").read_bytes(),
                Bundle.from_json(asset("tsa/bundle.txt.sigstore").read_bytes()),
                null_policy,
            )

    def test_verify_signed_timestamp_regression(self, asset):
        """
        Ensure we correctly verify a timestamp with no embedded certs.

        This is a regression test for # 1482
        """
        verifier = Verifier.staging(offline=True)
        ts = rfc3161_client.decode_timestamp_response(
            asset("tsa/issue1482-timestamp-with-no-cert").read_bytes()
        )
        res = verifier._verify_signed_timestamp(
            ts, asset("tsa/issue1482-message").read_bytes()
        )
        assert res is not None
