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
import hashlib
import json
import logging
from datetime import UTC, datetime, timedelta

import pretend
import pytest
import rfc3161_client
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from sigstore_models.common import v1 as common_v1
from sigstore_models.intoto import Envelope as _Envelope
from sigstore_models.intoto import Signature as _Signature
from sigstore_models.trustroot import v1 as trustroot_v1

from sigstore._internal.rekor import _hashedrekord_from_parts
from sigstore._internal.timestamp import TimestampSource, TimestampVerificationResult
from sigstore._internal.trust import CertificateAuthority
from sigstore._utils import base64_encode_pem_cert, sha256_digest
from sigstore.dsse import Envelope, StatementBuilder, Subject, _pae
from sigstore.errors import CertValidationError, VerificationError
from sigstore.models import Bundle, TrustedRoot
from sigstore.verify import policy
from sigstore.verify.verifier import Verifier, _v2_verifier_from_certificate


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
    (_file, bundle) = signing_bundle(filename)

    verifier = Verifier.staging()
    verifier.verify_dsse(bundle, null_policy)


@pytest.mark.parametrize(
    "filename", ("bundle.txt", "bundle_v3.txt", "bundle_v3_alt.txt")
)
def test_verifier_bundle_offline(signing_bundle, null_policy, filename):
    (file, bundle) = signing_bundle(filename)

    verifier = Verifier.staging(offline=True)
    verifier.verify_artifact(file.read_bytes(), bundle, null_policy)


def test_verifier_certificate_chain_rejects_invalid_time(signing_bundle):
    _, bundle = signing_bundle("bundle.txt")
    verifier = Verifier.staging(offline=True)
    timestamp = verifier._establish_time(bundle)[0]
    timestamp.time = datetime(2000, 1, 1, tzinfo=UTC)

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
        ]._inner.valid_for.end = datetime(2024, 10, 31, tzinfo=UTC)

        with (
            caplog.at_level(logging.DEBUG, logger="sigstore.verify.verifier"),
            pytest.raises(VerificationError, match="not enough sources"),
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

        with (
            caplog.at_level(logging.DEBUG, logger="sigstore.verify.verifier"),
            pytest.raises(VerificationError, match="not enough sources"),
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


_CA_KEY = ec.generate_private_key(ec.SECP384R1())
_CA_NAME = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test-ca")])
_CA_CERT = (
    x509.CertificateBuilder()
    .subject_name(_CA_NAME)
    .issuer_name(_CA_NAME)
    .public_key(_CA_KEY.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.now(UTC) - timedelta(days=1))
    .not_valid_after(datetime.now(UTC) + timedelta(days=1))
    .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    .add_extension(
        x509.KeyUsage(
            digital_signature=False,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=True,
            crl_sign=True,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True,
    )
    .add_extension(
        x509.SubjectKeyIdentifier.from_public_key(_CA_KEY.public_key()),
        critical=False,
    )
    .sign(_CA_KEY, hashes.SHA384())
)


def _leaf_cert(public_key) -> x509.Certificate:
    """
    Returns a code-signing certificate for `public_key`, issued by `_CA_CERT`.
    """
    now = datetime.now(UTC)
    return (
        x509.CertificateBuilder()
        .subject_name(x509.Name([]))
        .issuer_name(_CA_NAME)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(minutes=10))
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CODE_SIGNING]), critical=False
        )
        .add_extension(
            x509.SubjectAlternativeName([x509.RFC822Name("signer@example.com")]),
            critical=True,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(_CA_KEY.public_key()),
            critical=False,
        )
        .sign(_CA_KEY, hashes.SHA384())
    )


def _log_entry(kind: str, version: str, body: str):
    return pretend.stub(
        _verify=pretend.call_recorder(lambda keyring: None),
        _inner=pretend.stub(
            kind_version=pretend.stub(kind=kind, version=version),
            canonicalized_body=body.encode(),
        ),
    )


def _dsse_bundle(cert: x509.Certificate, payload: bytes, signature: bytes):
    payload_type = "application/vnd.in-toto+json"
    envelope = Envelope(
        _Envelope(
            payload=base64.b64encode(payload),
            payload_type=payload_type,
            signatures=[_Signature(sig=base64.b64encode(signature))],
        )
    )
    body = {
        "apiVersion": "0.0.1",
        "kind": "dsse",
        "spec": {
            "envelopeHash": {"algorithm": "sha256", "value": "00" * 32},
            "payloadHash": {
                "algorithm": "sha256",
                "value": hashlib.sha256(payload).hexdigest(),
            },
            "signatures": [
                {
                    "signature": base64.b64encode(signature).decode(),
                    "verifier": base64_encode_pem_cert(cert),
                }
            ],
        },
    }
    return pretend.stub(
        signing_certificate=cert,
        _dsse_envelope=envelope,
        log_entry=_log_entry("dsse", "0.0.1", json.dumps(body)),
    )


def _message_bundle(cert: x509.Certificate, input_: bytes, signature: bytes):
    body = _hashedrekord_from_parts(cert, signature, sha256_digest(input_))
    return pretend.stub(
        signing_certificate=cert,
        _inner=pretend.stub(
            message_signature=pretend.stub(signature=signature, message_digest=None)
        ),
        log_entry=_log_entry(
            "hashedrekord", "0.0.1", body.model_dump_json(by_alias=True)
        ),
    )


class TestSigningKeyTypes:
    """
    Steps (7) and (8) of verification for each kind of signing certificate
    key. Steps (1)-(6) are stubbed out except in
    `test_ed25519_signing_cert_chain`.
    """

    payload = b'{"_type": "https://in-toto.io/Statement/v1"}'

    @pytest.fixture
    def verifier(self, monkeypatch) -> Verifier:
        verifier = Verifier.staging(offline=True)
        monkeypatch.setattr(
            verifier, "_verify_common_signing_cert", lambda bundle, policy: None
        )
        return verifier

    def test_ed25519_dsse(self, verifier, null_policy):
        key = ed25519.Ed25519PrivateKey.generate()
        cert = _leaf_cert(key.public_key())
        signature = key.sign(_pae("application/vnd.in-toto+json", self.payload))

        bundle = _dsse_bundle(cert, self.payload, signature)
        assert verifier.verify_dsse(bundle, null_policy) == (
            "application/vnd.in-toto+json",
            self.payload,
        )

    def test_ed25519_dsse_tampered_payload(self, verifier, null_policy):
        key = ed25519.Ed25519PrivateKey.generate()
        cert = _leaf_cert(key.public_key())
        signature = key.sign(_pae("application/vnd.in-toto+json", self.payload))

        bundle = _dsse_bundle(cert, self.payload + b" ", signature)
        with pytest.raises(VerificationError, match="DSSE: invalid signature"):
            verifier.verify_dsse(bundle, null_policy)

    def test_ed25519_dsse_rekor_v2_entry(self, verifier, null_policy):
        # Rekor v2 records DSSE as a hashedrekord entry, which needs a
        # prehashed signing algorithm; pure Ed25519 has none.
        key = ed25519.Ed25519PrivateKey.generate()
        cert = _leaf_cert(key.public_key())
        signature = key.sign(_pae("application/vnd.in-toto+json", self.payload))

        bundle = _dsse_bundle(cert, self.payload, signature)
        bundle.log_entry = _log_entry("hashedrekord", "0.0.2", "{}")
        with pytest.raises(VerificationError, match="no externalized prehash"):
            verifier.verify_dsse(bundle, null_policy)

    def test_ed25519_message_signature(self, verifier, null_policy):
        key = ed25519.Ed25519PrivateKey.generate()
        cert = _leaf_cert(key.public_key())
        signature = key.sign(self.payload)

        bundle = _message_bundle(cert, self.payload, signature)
        verifier.verify_artifact(self.payload, bundle, null_policy)

    def test_ed25519_message_signature_tampered_input(self, verifier, null_policy):
        key = ed25519.Ed25519PrivateKey.generate()
        cert = _leaf_cert(key.public_key())
        signature = key.sign(self.payload)

        bundle = _message_bundle(cert, self.payload, signature)
        with pytest.raises(VerificationError, match="Signature is invalid for input"):
            verifier.verify_artifact(self.payload + b" ", bundle, null_policy)

    def test_ed25519_message_signature_prehashed_input(self, verifier, null_policy):
        key = ed25519.Ed25519PrivateKey.generate()
        cert = _leaf_cert(key.public_key())
        signature = key.sign(self.payload)

        bundle = _message_bundle(cert, self.payload, signature)
        with pytest.raises(VerificationError, match="full input"):
            verifier.verify_artifact(sha256_digest(self.payload), bundle, null_policy)

    def test_ed25519_message_signature_rekor_v2_entry(self, verifier, null_policy):
        # Rekor v2 hashedrekord entries need a prehashed signing algorithm;
        # pure Ed25519 has none.
        key = ed25519.Ed25519PrivateKey.generate()
        cert = _leaf_cert(key.public_key())
        signature = key.sign(self.payload)

        bundle = _message_bundle(cert, self.payload, signature)
        bundle.log_entry = _log_entry("hashedrekord", "0.0.2", "{}")
        with pytest.raises(VerificationError, match="no externalized prehash"):
            verifier.verify_artifact(self.payload, bundle, null_policy)

    def test_ed25519_signing_cert_chain(self, monkeypatch, null_policy):
        """
        Runs steps (1), (3) and (6) for an Ed25519 signing certificate against
        a test CA. Steps (0), (2), (4) and (5) are stubbed: they need signed
        timestamps, SCTs and log entries, and don't read the signing key.
        """
        verifier = Verifier.staging(offline=True)
        verifier._fulcio_certificate_chain = [_CA_CERT]
        monkeypatch.setattr(
            verifier,
            "_establish_time",
            lambda bundle: [
                TimestampVerificationResult(
                    source=TimestampSource.TRANSPARENCY_SERVICE, time=datetime.now(UTC)
                )
            ],
        )
        verify_sct = pretend.call_recorder(lambda cert, chain, keyring: None)
        monkeypatch.setattr("sigstore.verify.verifier.verify_sct", verify_sct)

        key = ed25519.Ed25519PrivateKey.generate()
        cert = _leaf_cert(key.public_key())
        signature = key.sign(_pae("application/vnd.in-toto+json", self.payload))
        bundle = _dsse_bundle(cert, self.payload, signature)

        assert verifier.verify_dsse(bundle, null_policy)[1] == self.payload
        assert verify_sct.calls[0].args[1] == [_CA_CERT]
        assert len(bundle.log_entry._verify.calls) == 1

        # The certificate's key maps to Ed25519 for Rekor v2 entries.
        assert (
            _v2_verifier_from_certificate(cert).key_details
            == common_v1.PublicKeyDetails.PKIX_ED25519
        )

    def test_weak_ed25519_signing_key(self, verifier, null_policy, weak_ed25519_key):
        cert = _leaf_cert(ed25519.Ed25519PublicKey.from_public_bytes(weak_ed25519_key))
        # The identity point encoding, with S = 0.
        signature = bytes([1]) + bytes(63)

        with pytest.raises(VerificationError, match="invalid Ed25519 public key"):
            verifier.verify_dsse(
                _dsse_bundle(cert, self.payload, signature), null_policy
            )
        with pytest.raises(VerificationError, match="invalid Ed25519 public key"):
            verifier.verify_artifact(
                self.payload,
                _message_bundle(cert, self.payload, signature),
                null_policy,
            )

    def test_ecdsa_dsse(self, verifier, null_policy):
        key = ec.generate_private_key(ec.SECP256R1())
        cert = _leaf_cert(key.public_key())
        signature = key.sign(
            _pae("application/vnd.in-toto+json", self.payload),
            ec.ECDSA(hashes.SHA256()),
        )

        bundle = _dsse_bundle(cert, self.payload, signature)
        assert verifier.verify_dsse(bundle, null_policy)[1] == self.payload

        bundle = _dsse_bundle(cert, self.payload + b" ", signature)
        with pytest.raises(VerificationError, match="DSSE: invalid signature"):
            verifier.verify_dsse(bundle, null_policy)

    def test_ecdsa_message_signature(self, verifier, null_policy):
        key = ec.generate_private_key(ec.SECP256R1())
        cert = _leaf_cert(key.public_key())
        signature = key.sign(self.payload, ec.ECDSA(hashes.SHA256()))

        bundle = _message_bundle(cert, self.payload, signature)
        verifier.verify_artifact(self.payload, bundle, null_policy)
        verifier.verify_artifact(sha256_digest(self.payload), bundle, null_policy)

        with pytest.raises(VerificationError, match="Signature is invalid for input"):
            verifier.verify_artifact(self.payload + b" ", bundle, null_policy)

    def test_unsupported_signing_key(self, verifier, null_policy):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cert = _leaf_cert(key.public_key())

        with pytest.raises(VerificationError, match="unsupported signing certificate"):
            verifier.verify_dsse(_dsse_bundle(cert, self.payload, b"sig"), null_policy)
        with pytest.raises(VerificationError, match="unsupported signing certificate"):
            verifier.verify_artifact(
                self.payload, _message_bundle(cert, self.payload, b"sig"), null_policy
            )
