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
import datetime
import hashlib
import logging
import secrets

import pretend
import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from sigstore_models.common.v1 import HashAlgorithm

import sigstore.oidc
import sigstore.sign
from sigstore._internal.fulcio.client import FulcioCertificateSigningResponse
from sigstore._internal.timestamp import TimestampAuthorityClient
from sigstore.dsse import StatementBuilder, Subject
from sigstore.errors import VerificationError
from sigstore.hashes import Hashed
from sigstore.models import ClientTrustConfig
from sigstore.sign import Signer, SigningContext
from sigstore.verify.policy import UnsafeNoOp


def test_csr_subject_is_stub_for_non_ascii_identity(dummy_jwt, monkeypatch):
    # Regression test for https://github.com/sigstore/sigstore-python/issues/1507.
    # The CSR subject must be a fixed ASCII stub regardless of the identity
    # claim value, because Fulcio ignores the CSR subject entirely and
    # non-ASCII values (e.g. emojis in GHA environment names) produce an
    # invalid IA5String encoding that Fulcio rejects with a 400.
    now = int(datetime.datetime.now().timestamp())
    token_str = dummy_jwt(
        {
            "aud": "sigstore",
            "sub": "repo:org/repo:environment:deploy\U0001f680",
            "iat": now,
            "nbf": now,
            "exp": now + 600,
            "iss": "hxxps://unknown.issuer.example.com/auth",
        }
    )
    identity_token = sigstore.oidc.IdentityToken(token_str)
    # The identity contains a non-ASCII emoji character.
    assert "\U0001f680" in identity_token.identity

    captured_csrs: list = []

    def fake_post(csr, token):
        captured_csrs.append(csr)
        # Return a minimal fake response; _signing_cert will try to call
        # verify_sct on it, which we also patch out below.
        fake_cert = pretend.stub(
            not_valid_after_utc=datetime.datetime(
                9999, 1, 1, tzinfo=datetime.timezone.utc
            )
        )
        return FulcioCertificateSigningResponse(cert=fake_cert, chain=[])

    monkeypatch.setattr(sigstore.sign, "verify_sct", lambda *a, **kw: None)

    fake_signing_cert_endpoint = pretend.stub(post=fake_post)
    fake_fulcio = pretend.stub(signing_cert=fake_signing_cert_endpoint)
    fake_trusted_root = pretend.stub(
        ct_keyring=lambda *a: pretend.stub(verify=lambda *a: None)
    )
    fake_rekor = pretend.stub()
    ctx = SigningContext(
        fulcio=fake_fulcio,
        rekor=fake_rekor,
        trusted_root=fake_trusted_root,
    )

    signer = Signer(identity_token, ctx, cache=False)
    signer._Signer__cached_private_key = ec.generate_private_key(ec.SECP256R1())
    signer._signing_cert()

    assert len(captured_csrs) == 1
    csr = captured_csrs[0]
    email_attrs = csr.subject.get_attributes_for_oid(NameOID.EMAIL_ADDRESS)
    assert len(email_attrs) == 1
    assert email_attrs[0].value == "user@example.com"


# only check the log contents for production: staging is already on
# rekor v2 and we don't currently support log lookups on rekor v2.
# This test can likely be removed once prod also uses rekor v2
@pytest.mark.parametrize("env", ["production"])
@pytest.mark.ambient_oidc
def test_sign_rekor_entry_consistent(request, sign_ctx_and_ident_for_env):
    ctx_cls, identity = sign_ctx_and_ident_for_env

    # NOTE: The actual signer instance is produced lazily, so that parameter
    # expansion doesn't fail in offline tests.
    ctx: SigningContext = ctx_cls()
    assert identity is not None

    payload = secrets.token_bytes(32)
    with ctx.signer(identity) as signer:
        expected_entry = signer.sign_artifact(payload).log_entry

    actual_entry = ctx._rekor.log.entries.get(log_index=expected_entry._inner.log_index)

    assert (
        expected_entry._inner.canonicalized_body
        == actual_entry._inner.canonicalized_body
    )
    assert expected_entry._inner.integrated_time == actual_entry._inner.integrated_time
    assert expected_entry._inner.log_id == actual_entry._inner.log_id
    assert expected_entry._inner.log_index == actual_entry._inner.log_index


@pytest.mark.staging
@pytest.mark.ambient_oidc
def test_sign_with_staging(staging, null_policy):
    ctx_cls, verifier_cls, identity = staging

    ctx: SigningContext = ctx_cls()
    verifier = verifier_cls()
    assert identity is not None

    payload = secrets.token_bytes(32)
    with ctx.signer(identity) as signer:
        bundle = signer.sign_artifact(payload)

    verifier.verify_artifact(payload, bundle, null_policy)


@pytest.mark.parametrize("env", ["staging", "production"])
@pytest.mark.ambient_oidc
def test_sct_verify_keyring_lookup_error(sign_ctx_and_ident_for_env, monkeypatch):
    ctx, identity = sign_ctx_and_ident_for_env

    # a signer whose keyring always fails to lookup a given key.
    ctx: SigningContext = ctx()
    mock = pretend.stub(
        ct_keyring=lambda *a: pretend.stub(verify=pretend.raiser(VerificationError))
    )
    ctx._trusted_root = mock
    assert identity is not None

    payload = secrets.token_bytes(32)
    with pytest.raises(VerificationError, match=r"SCT verify failed:"):
        with ctx.signer(identity) as signer:
            signer.sign_artifact(payload)


@pytest.mark.parametrize("env", ["staging", "production"])
@pytest.mark.ambient_oidc
def test_sct_verify_keyring_error(sign_ctx_and_ident_for_env, monkeypatch):
    ctx, identity = sign_ctx_and_ident_for_env

    # a signer whose keyring throws an internal error.
    ctx: SigningContext = ctx()
    mock = pretend.stub(
        ct_keyring=lambda *a: pretend.stub(verify=pretend.raiser(VerificationError))
    )
    ctx._trusted_root = mock
    assert identity is not None

    payload = secrets.token_bytes(32)

    with pytest.raises(VerificationError):
        with ctx.signer(identity) as signer:
            signer.sign_artifact(payload)


@pytest.mark.parametrize("env", ["staging", "production"])
@pytest.mark.ambient_oidc
def test_identity_proof_fallback_claim(sign_ctx_and_ident_for_env, monkeypatch):
    ctx_cls, identity = sign_ctx_and_ident_for_env

    ctx: SigningContext = ctx_cls()
    assert identity is not None

    # clear out known issuers, forcing the `Identity`'s  `sub` claim to be used
    # as fall back
    monkeypatch.setattr(sigstore.oidc, "_KNOWN_OIDC_ISSUERS", {})

    payload = secrets.token_bytes(32)

    with ctx.signer(identity) as signer:
        signer.sign_artifact(payload)


@pytest.mark.staging
@pytest.mark.ambient_oidc
def test_sign_prehashed(staging):
    sign_ctx_cls, verifier_cls, identity = staging

    sign_ctx = sign_ctx_cls()
    verifier = verifier_cls()

    input_ = secrets.token_bytes(32)
    hashed = Hashed(
        digest=hashlib.sha256(input_).digest(), algorithm=HashAlgorithm.SHA2_256
    )

    with sign_ctx.signer(identity) as signer:
        bundle = signer.sign_artifact(hashed)

    assert bundle._inner.message_signature.message_digest.algorithm == hashed.algorithm
    assert bundle._inner.message_signature.message_digest.digest == hashed.digest

    # verifying against the original input works
    verifier.verify_artifact(input_, bundle=bundle, policy=UnsafeNoOp())
    # verifying against the prehash also works
    verifier.verify_artifact(hashed, bundle=bundle, policy=UnsafeNoOp())


@pytest.mark.staging
@pytest.mark.ambient_oidc
def test_sign_dsse(staging):
    sign_ctx, _, identity = staging

    ctx = sign_ctx()
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
        # Ensures that all of our inner types serialize as expected.
        bundle.to_json()


@pytest.mark.staging
@pytest.mark.ambient_oidc
@pytest.mark.timestamp_authority
class TestSignWithTSA:
    @pytest.fixture
    def sig_ctx(self, asset, tsa_url) -> SigningContext:
        trust_config = ClientTrustConfig.from_json(
            asset("tsa/trust_config.json").read_text()
        )

        trust_config._inner.signing_config.tsa_urls[0].url = tsa_url

        return SigningContext.from_trust_config(trust_config)

    @pytest.fixture
    def identity(self, staging):
        _, _, identity = staging
        return identity

    @pytest.fixture
    def hashed(self) -> Hashed:
        input_ = secrets.token_bytes(32)
        return Hashed(
            digest=hashlib.sha256(input_).digest(), algorithm=HashAlgorithm.SHA2_256
        )

    def test_sign_artifact(self, sig_ctx, identity, hashed):
        with sig_ctx.signer(identity) as signer:
            bundle = signer.sign_artifact(hashed)

        assert bundle.to_json()
        assert (
            bundle.verification_material.timestamp_verification_data.rfc3161_timestamps
        )

    def test_sign_dsse(self, sig_ctx, identity):
        stmt = (
            StatementBuilder()
            .subjects(
                [
                    Subject(
                        name="null", digest={"sha256": hashlib.sha256(b"").hexdigest()}
                    )
                ]
            )
            .predicate_type("https://cosign.sigstore.dev/attestation/v1")
            .predicate(
                {
                    "Data": "",
                    "Timestamp": "2023-12-07T00:37:58Z",
                }
            )
        ).build()

        with sig_ctx.signer(identity) as signer:
            bundle = signer.sign_dsse(stmt)

        assert bundle.to_json()
        assert (
            bundle.verification_material.timestamp_verification_data.rfc3161_timestamps
        )

    def test_with_timestamp_error(self, sig_ctx, identity, hashed, caplog):
        # Simulate here an TSA that returns an invalid Timestamp
        sig_ctx._tsa_clients.append(TimestampAuthorityClient("invalid-url"))

        with caplog.at_level(logging.WARNING, logger="sigstore.sign"):
            with sig_ctx.signer(identity) as signer:
                bundle = signer.sign_artifact(hashed)

        assert caplog.records[0].message.startswith("Unable to use invalid-url")
        assert (
            bundle.verification_material.timestamp_verification_data.rfc3161_timestamps
        )
