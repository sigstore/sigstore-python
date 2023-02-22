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

import io
import secrets

import jwt
import pretend
import pytest

import sigstore._internal.oidc
from sigstore._internal.keyring import KeyringError, KeyringLookupError
from sigstore._internal.sct import InvalidSctError
from sigstore.oidc import IdentityError, detect_credential
from sigstore.sign import Signer


@pytest.mark.online
def test_signer_production():
    signer = Signer.production()
    assert signer is not None


def test_signer_staging(mock_staging_tuf):
    signer = Signer.staging()
    assert signer is not None


@pytest.mark.online
@pytest.mark.ambient_oidc
@pytest.mark.parametrize("signer", [Signer.production, Signer.staging])
def test_sign_rekor_entry_consistent(signer):
    # NOTE: The actual signer instance is produced lazily, so that parameter
    # expansion doesn't fail in offline tests.
    signer = signer()

    token = detect_credential()
    assert token is not None

    payload = io.BytesIO(secrets.token_bytes(32))
    expected_entry = signer.sign(payload, token).log_entry
    actual_entry = signer._rekor.log.entries.get(log_index=expected_entry.log_index)

    assert expected_entry.uuid == actual_entry.uuid
    assert expected_entry.body == actual_entry.body
    assert expected_entry.integrated_time == actual_entry.integrated_time
    assert expected_entry.log_id == actual_entry.log_id
    assert expected_entry.log_index == actual_entry.log_index


@pytest.mark.online
@pytest.mark.ambient_oidc
@pytest.mark.parametrize("signer", [Signer.production, Signer.staging])
def test_sct_verify_keyring_lookup_error(signer, monkeypatch):
    # a signer whose keyring always fails to lookup a given key.
    signer = signer()
    signer._rekor._ct_keyring = pretend.stub(verify=pretend.raiser(KeyringLookupError))

    token = detect_credential()
    assert token is not None

    payload = io.BytesIO(secrets.token_bytes(32))

    with pytest.raises(
        InvalidSctError,
        match="Invalid key ID in SCT: not found in current keyring.",
    ):
        signer.sign(payload, token)


@pytest.mark.online
@pytest.mark.ambient_oidc
@pytest.mark.parametrize("signer", [Signer.production, Signer.staging])
def test_sct_verify_keyring_error(signer, monkeypatch):
    # a signer whose keyring throws an internal error.
    signer = signer()
    signer._rekor._ct_keyring = pretend.stub(verify=pretend.raiser(KeyringError))

    token = detect_credential()
    assert token is not None

    payload = io.BytesIO(secrets.token_bytes(32))

    with pytest.raises(InvalidSctError):
        signer.sign(payload, token)


@pytest.mark.online
@pytest.mark.ambient_oidc
@pytest.mark.parametrize("signer", [Signer.production, Signer.staging])
def test_identity_proof_claim_lookup(signer, monkeypatch):
    signer = signer()

    token = detect_credential()
    assert token is not None

    # clear out the known issuers, forcing the `Identity`'s  `proof_claim` to be looked up.
    monkeypatch.setattr(sigstore._internal.oidc, "_KNOWN_OIDC_ISSUERS", {})

    payload = io.BytesIO(secrets.token_bytes(32))

    expected_entry = signer.sign(payload, token).log_entry
    actual_entry = signer._rekor.log.entries.get(log_index=expected_entry.log_index)

    assert expected_entry.uuid == actual_entry.uuid
    assert expected_entry.body == actual_entry.body
    assert expected_entry.integrated_time == actual_entry.integrated_time
    assert expected_entry.log_id == actual_entry.log_id
    assert expected_entry.log_index == actual_entry.log_index


def test_identity_token_iss_claim_error(mock_staging_tuf, monkeypatch):
    signer = Signer.staging()
    # identity token is decoded into an empty dict.
    monkeypatch.setattr(
        jwt,
        "decode",
        lambda token, options: {},
    )

    payload = io.BytesIO(b"foobar")
    identity_token = pretend.stub()
    with pytest.raises(
        IdentityError, match="Identity token missing the required `iss` claim"
    ):
        signer.sign(payload, identity_token)


def test_identity_token_aud_claim_error(mock_staging_tuf, monkeypatch):
    signer = Signer.staging()
    # identity token is decoded into an dict with "iss", but not "aud".
    monkeypatch.setattr(
        jwt,
        "decode",
        lambda token, options: {"iss": "https://accounts.google.com"},
    )

    payload = io.BytesIO(b"foobar")
    identity_token = pretend.stub()
    with pytest.raises(
        IdentityError, match="Identity token missing the required `aud` claim"
    ):
        signer.sign(payload, identity_token)


def test_identity_token_audience_error(mock_staging_tuf, monkeypatch):
    signer = Signer.staging()
    # identity token is decoded into an dict with "iss", but unknown "aud"
    monkeypatch.setattr(
        jwt,
        "decode",
        lambda token, options: {"iss": "https://accounts.google.com", "aud": "Jack"},
    )

    payload = io.BytesIO(b"foobar")
    identity_token = pretend.stub()
    with pytest.raises(IdentityError, match="Audience should be '.*', not 'Jack'"):
        signer.sign(payload, identity_token)


def test_identity_token_proof_claim_error(mock_staging_tuf, monkeypatch):
    signer = Signer.staging()
    # identity token is decoded into an dict with "iss", and known "aud",
    # but none of the required claims
    monkeypatch.setattr(
        jwt,
        "decode",
        lambda token, options: {
            "iss": "https://accounts.google.com",
            "aud": "sigstore",
        },
    )

    payload = io.BytesIO(b"foobar")
    identity_token = pretend.stub()
    with pytest.raises(
        IdentityError, match="Identity token missing the required `'email'` claim"
    ):
        signer.sign(payload, identity_token)


def test_identity_token_sub_claim_error(mock_staging_tuf, monkeypatch):
    signer = Signer.staging()
    # identity token is decoded into an dict with unkown "iss", and known "aud"
    monkeypatch.setattr(
        jwt,
        "decode",
        lambda token, options: {
            "iss": "foo.bar",
            "aud": "sigstore",
        },
    )

    payload = io.BytesIO(b"foobar")
    identity_token = pretend.stub()
    with pytest.raises(IdentityError, match="Identity token missing `sub` claim"):
        signer.sign(payload, identity_token)
