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
import secrets

import cryptography.x509 as x509
import pretend
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from sigstore_models.common.v1 import HashAlgorithm

import sigstore.oidc
from sigstore.dsse import StatementBuilder, Subject
from sigstore.errors import VerificationError
from sigstore.hashes import Hashed
from sigstore.sign import Signer, SigningContext
from sigstore.verify.policy import UnsafeNoOp


def _signer_with_identity(identity: str) -> Signer:
    """
    Build a `Signer` wired up just enough to exercise CSR construction,
    without any network access or a real identity token.
    """
    signer = Signer.__new__(Signer)
    signer._identity_token = pretend.stub(_identity=identity)
    signer._Signer__cached_private_key = ec.generate_private_key(ec.SECP256R1())
    return signer


def test_build_csr_has_empty_subject():
    # The CSR carries an empty subject regardless of the identity. Fulcio does
    # not use the subject (sigstore/fulcio#863), so we omit it entirely.
    csr = _signer_with_identity("foo@example.com")._build_csr()

    assert len(csr.subject) == 0

    der = csr.public_bytes(serialization.Encoding.DER)
    reparsed = x509.load_der_x509_csr(der)
    assert len(reparsed.subject) == 0


def test_build_csr_non_ascii_identity_produces_valid_csr():
    # Regression test for sigstore/sigstore-python#1507. A non-ASCII identity
    # (e.g. a GitHub Actions `sub` with a non-ASCII environment name) must not
    # be smuggled into an ASCII-only IA5String EMAIL_ADDRESS attribute, which
    # produces malformed DER that Fulcio rejects with HTTP 400. With the subject
    # omitted, the identity never reaches the CSR.
    identity = "repo:foo/bar:environment:prod-\U0001f600"
    assert any(ord(ch) > 0x7F for ch in identity)

    csr = _signer_with_identity(identity)._build_csr()

    assert len(csr.subject) == 0

    # The CSR serializes to DER and re-parses cleanly, and no subject attribute
    # carries non-ASCII bytes (the malformed-DER condition Fulcio rejects).
    der = csr.public_bytes(serialization.Encoding.DER)
    reparsed = x509.load_der_x509_csr(der)
    assert len(reparsed.subject) == 0


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
