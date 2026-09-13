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

"""Exercise checkpoint identities through serialized roots and artifact verification."""

import base64
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from sigstore._internal.trust import KeyringPurpose
from sigstore.errors import MetadataError, VerificationError
from sigstore.models import Bundle, TrustedRoot
from sigstore.verify import Verifier, policy

_CHECKPOINT_NAME = "https://checkpoint.example.test"


def _identity() -> policy.Identity:
    return policy.Identity(
        identity="a@tny.town",
        issuer="https://github.com/login/oauth",
    )


@dataclass
class _CheckpointMaterials:
    artifact: bytes
    root: dict[str, Any]
    bundle: Bundle
    signer: Ed25519PrivateKey
    note: str
    log_id: bytes
    checkpoint_id: bytes

    def sign_checkpoint(self, *, key_id: bytes | None = None) -> None:
        signature = self.signer.sign(self.note.encode())
        prefix = self.checkpoint_id if key_id is None else key_id[:4]
        encoded = base64.b64encode(prefix + signature).decode()
        self.bundle.log_entry._inner.inclusion_proof.checkpoint.envelope = (
            f"{self.note}\n\u2014 {_CHECKPOINT_NAME} {encoded}\n"
        )

    def load(self, tmp_path: Path) -> tuple[Verifier, Bundle]:
        """Cross both public JSON loading boundaries before any verification."""
        root_path = tmp_path / "trusted_root.json"
        root_path.write_text(json.dumps(self.root))
        trusted_root = TrustedRoot.from_file(str(root_path))
        bundle = Bundle.from_json(self.bundle.to_json())
        return Verifier(trusted_root=trusted_root), bundle


@pytest.fixture
def checkpoint_materials(signing_bundle, tuf_asset):
    artifact, bundle = signing_bundle("bundle.txt")
    root = json.loads(tuf_asset.target("trusted_root.json"))
    root["mediaType"] = "application/vnd.dev.sigstore.trustedroot.v0.2+json"

    signing_key = Ed25519PrivateKey.generate()
    public_key = signing_key.public_key()
    der_key = public_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    raw_key = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
    log_id = hashlib.sha256(der_key).digest()
    # C2SP signed-note Ed25519 identities bind the name and algorithm to the key.
    checkpoint_id = hashlib.sha256(
        _CHECKPOINT_NAME.encode() + b"\n\x01" + raw_key
    ).digest()[:4]
    assert checkpoint_id != log_id[:4]
    root["tlogs"] = [
        {
            "baseUrl": _CHECKPOINT_NAME,
            "hashAlgorithm": "SHA2_256",
            "publicKey": {
                "rawBytes": base64.b64encode(der_key).decode(),
                "keyDetails": "PKIX_ED25519",
                # The key was valid at the genuine bundle's integrated time.
                # Verification must continue to accept this now-expired key.
                "validFor": {
                    "start": "2023-01-01T00:00:00Z",
                    "end": "2024-01-01T00:00:00Z",
                },
            },
            "logId": {"keyId": base64.b64encode(log_id).decode()},
            "checkpointKeyId": {"keyId": base64.b64encode(checkpoint_id).decode()},
        }
    ]

    entry = bundle.log_entry
    entry._inner.log_id.key_id = log_id
    entry._inner.inclusion_promise.signed_entry_timestamp = signing_key.sign(
        entry._encode_canonical()
    )
    original_note = entry._inner.inclusion_proof.checkpoint.envelope.split("\n\n")[0]
    note = _CHECKPOINT_NAME + "\n" + original_note.split("\n", 1)[1] + "\n"
    materials = _CheckpointMaterials(
        artifact.read_bytes(), root, bundle, signing_key, note, log_id, checkpoint_id
    )
    materials.sign_checkpoint()
    return materials


def test_artifact_v02_checkpoint_identity(checkpoint_materials, tmp_path):
    verifier, bundle = checkpoint_materials.load(tmp_path)

    verifier.verify_artifact(checkpoint_materials.artifact, bundle, _identity())


@pytest.mark.parametrize(
    "name",
    (
        "checkpoint.example.test",
        "https://checkpoint.example.test/",
        "https://other.example.test",
    ),
)
def test_artifact_v02_checkpoint_name_must_match(checkpoint_materials, tmp_path, name):
    checkpoint_materials.root["tlogs"][0]["baseUrl"] = name
    verifier, bundle = checkpoint_materials.load(tmp_path)

    with pytest.raises(VerificationError, match="checkpoint"):
        verifier.verify_artifact(checkpoint_materials.artifact, bundle, _identity())


def test_artifact_v02_checkpoint_id_must_match(checkpoint_materials, tmp_path):
    # A valid signature under the trusted key must not fall back to the log ID
    # when a different checkpoint identity is explicitly configured.
    checkpoint_materials.sign_checkpoint(key_id=checkpoint_materials.log_id)
    verifier, bundle = checkpoint_materials.load(tmp_path)

    with pytest.raises(VerificationError, match="checkpoint"):
        verifier.verify_artifact(checkpoint_materials.artifact, bundle, _identity())


def test_artifact_v02_checkpoint_signature_tampering(checkpoint_materials, tmp_path):
    checkpoint = checkpoint_materials.bundle.log_entry._inner.inclusion_proof.checkpoint
    envelope, encoded = checkpoint.envelope.rsplit(" ", 1)
    signature = bytearray(base64.b64decode(encoded))
    signature[-1] ^= 1
    checkpoint.envelope = envelope + " " + base64.b64encode(signature).decode() + "\n"
    verifier, bundle = checkpoint_materials.load(tmp_path)

    with pytest.raises(VerificationError, match="checkpoint: invalid signature"):
        verifier.verify_artifact(checkpoint_materials.artifact, bundle, _identity())


def test_artifact_v02_checkpoint_root_hash_must_match(checkpoint_materials, tmp_path):
    lines = checkpoint_materials.note.splitlines()
    lines[2] = base64.b64encode(bytes(32)).decode()
    checkpoint_materials.note = "\n".join(lines) + "\n"
    checkpoint_materials.sign_checkpoint()
    verifier, bundle = checkpoint_materials.load(tmp_path)

    with pytest.raises(VerificationError, match="invalid root hash signature"):
        verifier.verify_artifact(checkpoint_materials.artifact, bundle, _identity())


def test_artifact_v02_checkpoint_without_id_uses_log_id(checkpoint_materials, tmp_path):
    del checkpoint_materials.root["tlogs"][0]["checkpointKeyId"]
    checkpoint_materials.sign_checkpoint(key_id=checkpoint_materials.log_id)
    verifier, bundle = checkpoint_materials.load(tmp_path)

    verifier.verify_artifact(checkpoint_materials.artifact, bundle, _identity())


def test_artifact_v01_checkpoint_ignores_new_identity(checkpoint_materials, tmp_path):
    checkpoint_materials.root["mediaType"] = (
        "application/vnd.dev.sigstore.trustedroot+json;version=0.1"
    )
    checkpoint_materials.root["tlogs"][0]["baseUrl"] = "https://different.example.test"
    checkpoint_materials.sign_checkpoint(key_id=checkpoint_materials.log_id)
    verifier, bundle = checkpoint_materials.load(tmp_path)

    verifier.verify_artifact(checkpoint_materials.artifact, bundle, _identity())


def test_artifact_v02_checkpoint_future_key_is_untrusted(
    checkpoint_materials, tmp_path
):
    checkpoint_materials.root["tlogs"][0]["publicKey"]["validFor"] = {
        "start": "2999-01-01T00:00:00Z"
    }
    verifier, bundle = checkpoint_materials.load(tmp_path)

    with pytest.raises(MetadataError, match="Did not find any Rekor keys"):
        verifier.verify_artifact(checkpoint_materials.artifact, bundle, _identity())


def test_v02_checkpoint_expired_key_cannot_sign(checkpoint_materials, tmp_path):
    verifier, _ = checkpoint_materials.load(tmp_path)

    with pytest.raises(MetadataError, match="Did not find any Rekor keys"):
        verifier._trusted_root.rekor_keyring(KeyringPurpose.SIGN)


def test_artifact_v02_checkpoint_retains_identity_policy(
    checkpoint_materials, tmp_path
):
    verifier, bundle = checkpoint_materials.load(tmp_path)
    wrong_identity = policy.Identity(
        identity="other@example.test", issuer="https://github.com/login/oauth"
    )

    with pytest.raises(VerificationError, match="Certificate's SANs do not match"):
        verifier.verify_artifact(checkpoint_materials.artifact, bundle, wrong_identity)


def test_artifact_v02_checkpoint_retains_artifact_verification(
    checkpoint_materials, tmp_path
):
    verifier, bundle = checkpoint_materials.load(tmp_path)

    with pytest.raises(VerificationError, match="digest mismatch"):
        verifier.verify_artifact(
            checkpoint_materials.artifact + b"tampered", bundle, _identity()
        )
