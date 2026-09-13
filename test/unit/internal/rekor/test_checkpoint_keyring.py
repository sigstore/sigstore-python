# Copyright 2026 The Sigstore Authors
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

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from sigstore_models.common import v1 as common_v1
from sigstore_models.trustroot import v1 as trustroot_v1

from sigstore._internal.rekor.checkpoint import RekorSignature, SignedNote
from sigstore._internal.trust import RekorKeyring
from sigstore._utils import KeyID, key_id
from sigstore.errors import VerificationError

NAME = "log.example/shard"
CHECKPOINT_ID = b"ckpt"
NOTE = "log.example/shard\n1\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n"


@pytest.fixture(scope="module")
def signers():
    return {
        "ed25519": ed25519.Ed25519PrivateKey.generate(),
        "ecdsa": ec.generate_private_key(ec.SECP256R1()),
        "rsa": rsa.generate_private_key(public_exponent=65537, key_size=2048),
    }


def _log(signer, *, name=NAME, checkpoint_id=CHECKPOINT_ID, log_id=None):
    if isinstance(signer, ed25519.Ed25519PrivateKey):
        details = common_v1.PublicKeyDetails.PKIX_ED25519
    elif isinstance(signer, ec.EllipticCurvePrivateKey):
        details = common_v1.PublicKeyDetails.PKIX_ECDSA_P256_SHA_256
    else:
        details = common_v1.PublicKeyDetails.PKIX_RSA_PKCS1V15_2048_SHA256
    public_key = signer.public_key()
    return trustroot_v1.TransparencyLogInstance(
        base_url=name,
        hash_algorithm=common_v1.HashAlgorithm.SHA2_256,
        public_key=common_v1.PublicKey(
            raw_bytes=base64.b64encode(
                public_key.public_bytes(
                    serialization.Encoding.DER,
                    serialization.PublicFormat.SubjectPublicKeyInfo,
                )
            ),
            key_details=details,
        ),
        log_id=common_v1.LogId(
            key_id=base64.b64encode(key_id(public_key) if log_id is None else log_id)
        ),
        checkpoint_key_id=(
            common_v1.LogId(key_id=base64.b64encode(checkpoint_id))
            if checkpoint_id is not None
            else None
        ),
    )


def _signature(signer, *, name=NAME, identity=CHECKPOINT_ID, text=NOTE):
    data = text.encode()
    if isinstance(signer, ed25519.Ed25519PrivateKey):
        signature = signer.sign(data)
    elif isinstance(signer, ec.EllipticCurvePrivateKey):
        signature = signer.sign(data, ec.ECDSA(hashes.SHA256()))
    else:
        signature = signer.sign(data, padding.PKCS1v15(), hashes.SHA256())
    return RekorSignature(name, identity[:4], base64.b64encode(signature))


def _verify(keyring, signature, *, log_id=b"untrusted bundle hint"):
    return keyring.verify_checkpoint_signature(
        name=signature.name,
        signature_hash=signature.sig_hash,
        signature=base64.b64decode(signature.signature),
        data=NOTE.encode(),
        log_id=KeyID(log_id),
    )


@pytest.mark.parametrize("algorithm", ["ed25519", "ecdsa", "rsa"])
def test_explicit_checkpoint_id_overrides_log_id(signers, algorithm):
    signer = signers[algorithm]
    log = _log(signer, log_id=b"log!" * 8)
    keyring = RekorKeyring([log], legacy=False)

    assert _verify(keyring, _signature(signer))
    assert not _verify(
        keyring,
        _signature(signer, identity=log.log_id.key_id),
        log_id=log.log_id.key_id,
    )


@pytest.mark.parametrize("length", [4, 32])
@pytest.mark.parametrize("explicit", [False, True])
def test_checkpoint_id_lengths_and_missing_field_fallback(signers, length, explicit):
    signer = signers["ed25519"]
    identity = b"abcd" + b"x" * (length - 4)
    log = _log(
        signer,
        checkpoint_id=identity if explicit else None,
        log_id=b"log!" if explicit else identity,
    )
    assert _verify(
        RekorKeyring([log], legacy=False), _signature(signer, identity=identity)
    )


@pytest.mark.parametrize("checkpoint_id", [b"", b"a", b"abc"])
def test_malformed_explicit_checkpoint_id_does_not_fall_back(signers, checkpoint_id):
    log = _log(signers["ed25519"], checkpoint_id=checkpoint_id)
    with pytest.raises(VerificationError, match="at least 4 bytes"):
        RekorKeyring([log], legacy=False)


@pytest.mark.parametrize("log_id", [b"", b"abc"])
def test_malformed_fallback_log_id(signers, log_id):
    log = _log(signers["ed25519"], checkpoint_id=None, log_id=log_id)
    with pytest.raises(VerificationError, match="at least 4 bytes"):
        RekorKeyring([log], legacy=False)


@pytest.mark.parametrize("name", ["", "log.example/a b", "log.example/a+b"])
def test_invalid_trusted_name(signers, name):
    with pytest.raises(VerificationError, match="invalid checkpoint key name"):
        RekorKeyring([_log(signers["ed25519"], name=name)], legacy=False)


def test_name_matching_is_exact(signers):
    signer = signers["ed25519"]
    name = "https://log.example:8443/shard"
    keyring = RekorKeyring([_log(signer, name=name)], legacy=False)

    assert _verify(keyring, _signature(signer, name=name))
    for other in ["log.example:8443/shard", "log.example", name + "/"]:
        assert not _verify(keyring, _signature(signer, name=other))


def test_name_and_id_are_both_required(signers):
    signer = signers["ed25519"]
    keyring = RekorKeyring([_log(signer)], legacy=False)

    assert not _verify(keyring, _signature(signer, name="unknown.example"))
    assert not _verify(keyring, _signature(signer, identity=b"nope"))


def test_unloadable_key_is_not_a_checkpoint_candidate(signers, caplog):
    signer = signers["ed25519"]
    invalid = _log(signer)
    invalid.public_key.raw_bytes = b""
    empty = RekorKeyring([invalid], legacy=False)
    assert not _verify(empty, _signature(signer))
    assert "Failed to load a trusted root key" in caplog.text

    # An unusable log must not prevent a different, valid configured log from
    # verifying, or allow its identity to borrow the valid log's key.
    valid = _log(signer, name="other.example")
    keyring = RekorKeyring([invalid, valid], legacy=False)
    assert _verify(keyring, _signature(signer, name="other.example"))
    assert not _verify(keyring, _signature(signer))


def test_matching_identity_cannot_use_another_trusted_key(signers):
    first, second = signers["ed25519"], signers["ecdsa"]
    keyring = RekorKeyring(
        [_log(first), _log(second, name="other.example")], legacy=False
    )

    assert _verify(keyring, _signature(second, name="other.example"))
    with pytest.raises(VerificationError, match="invalid signature"):
        _verify(keyring, _signature(second))


@pytest.mark.parametrize("reverse", [False, True])
def test_same_name_and_id_keep_all_trusted_candidates(signers, reverse):
    first, second = signers["ed25519"], signers["ecdsa"]
    logs = [_log(first), _log(second)]
    keyring = RekorKeyring(logs[::-1] if reverse else logs, legacy=False)

    assert _verify(keyring, _signature(first))
    assert _verify(keyring, _signature(second))
    with pytest.raises(VerificationError, match="invalid signature"):
        _verify(keyring, _signature(signers["rsa"]))


def test_reused_public_key_keeps_each_trusted_identity(signers):
    signer = signers["ed25519"]
    keyring = RekorKeyring(
        [_log(signer), _log(signer, name="other.example", checkpoint_id=b"next")],
        legacy=False,
    )
    assert _verify(keyring, _signature(signer))
    assert _verify(keyring, _signature(signer, name="other.example", identity=b"next"))
    assert not _verify(keyring, _signature(signer, name="other.example"))


@pytest.mark.parametrize("reverse", [False, True])
def test_note_ignores_unknown_signatures(signers, reverse):
    signer = signers["ed25519"]
    keyring = RekorKeyring([_log(signer)], legacy=False)
    signatures = [
        _signature(signer, name="unknown.example", text="invalid\n"),
        _signature(signer),
        _signature(signer, identity=b"nope", text="invalid\n"),
    ]
    SignedNote(NOTE, signatures[::-1] if reverse else signatures).verify(
        keyring, KeyID(b"irrelevant")
    )


@pytest.mark.parametrize("reverse", [False, True])
def test_note_rejects_known_invalid_signature_before_or_after_valid(signers, reverse):
    first, second = signers["ed25519"], signers["ecdsa"]
    keyring = RekorKeyring(
        [_log(first), _log(second, checkpoint_id=b"next")], legacy=False
    )
    signatures = [
        _signature(first),
        _signature(second, identity=b"next", text="invalid\n"),
    ]
    with pytest.raises(VerificationError, match="invalid signature"):
        SignedNote(NOTE, signatures[::-1] if reverse else signatures).verify(
            keyring, KeyID(b"irrelevant")
        )


def test_note_rejects_only_unknown_signatures(signers):
    signer = signers["ed25519"]
    keyring = RekorKeyring([_log(signer)], legacy=False)
    with pytest.raises(VerificationError, match="no signature from a trusted log"):
        SignedNote(NOTE, [_signature(signer, name="unknown.example")]).verify(
            keyring, KeyID(b"irrelevant")
        )


@pytest.mark.parametrize("checkpoint_id", [CHECKPOINT_ID, b""])
def test_legacy_uses_log_id_hint_and_ignores_checkpoint_metadata(
    signers, checkpoint_id
):
    signer = signers["ed25519"]
    log = _log(signer, name="http://localhost:3003", checkpoint_id=checkpoint_id)
    keyring = RekorKeyring([log], legacy=True)
    signature = _signature(signer, name="rekor-local", identity=log.log_id.key_id)

    assert _verify(keyring, signature, log_id=log.log_id.key_id)
    assert not _verify(keyring, _signature(signer), log_id=log.log_id.key_id)
    # A legacy log ID is an unauthenticated hint, so unknown IDs still try
    # trusted keys after the signature prefix matches the bundle hint.
    assert _verify(keyring, _signature(signer, identity=b"hint"), log_id=b"hint")


@pytest.mark.parametrize("invalid_first", [False, True])
def test_legacy_note_keeps_first_matching_signature_behavior(signers, invalid_first):
    signer = signers["ed25519"]
    log = _log(signer)
    keyring = RekorKeyring([log], legacy=True)
    identity = log.log_id.key_id
    signatures = [
        _signature(signer, identity=identity),
        _signature(signer, identity=identity, text="invalid\n"),
    ]
    note = SignedNote(NOTE, signatures[::-1] if invalid_first else signatures)
    if invalid_first:
        with pytest.raises(VerificationError, match="checkpoint: invalid signature"):
            note.verify(keyring, KeyID(identity))
    else:
        note.verify(keyring, KeyID(identity))
