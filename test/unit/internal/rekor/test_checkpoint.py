# Copyright 2025 The Sigstore Authors
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
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sigstore_models.common import v1 as common_v1
from sigstore_models.trustroot import v1 as trustroot_v1

from sigstore._internal.rekor.checkpoint import LogCheckpoint, SignedNote
from sigstore._internal.trust import RekorKeyring
from sigstore.errors import VerificationError


class TestLogCheckpoint:
    def test_from_text_roundtrip(self):
        root_hash = base64.b64encode(b"\x00" * 32).decode()
        text = f"rekor.example - 123\n42\n{root_hash}\nTimestamp: 1\n"
        checkpoint = LogCheckpoint.from_text(text)
        assert checkpoint.origin == "rekor.example - 123"
        assert checkpoint.log_size == 42
        assert checkpoint.log_hash == (b"\x00" * 32).hex()
        assert checkpoint.other_content == ["Timestamp: 1"]

    def test_from_text_too_few_lines(self):
        with pytest.raises(VerificationError, match="too few items"):
            LogCheckpoint.from_text("rekor.example - 123\n42\n")

    def test_from_text_invalid_log_size(self):
        # A non-integer log size must surface as a VerificationError rather than
        # leaking a raw ValueError to callers that only expect VerificationError.
        root_hash = base64.b64encode(b"\x00" * 32).decode()
        with pytest.raises(VerificationError, match="invalid log size"):
            LogCheckpoint.from_text(f"rekor.example - 123\nNOTANINT\n{root_hash}\n")

    def test_from_text_invalid_root_hash(self):
        # An undecodable base64 root hash must also surface as a VerificationError.
        with pytest.raises(VerificationError, match="invalid root hash"):
            LogCheckpoint.from_text("rekor.example - 123\n42\n!!!notbase64!!!\n")


class TestSignedNote:
    @staticmethod
    def _signed_note(name: str, checkpoint_key_id: bytes):
        private_key = Ed25519PrivateKey.generate()
        public_key = common_v1.PublicKey(
            raw_bytes=base64.b64encode(
                private_key.public_key().public_bytes(
                    encoding=serialization.Encoding.DER,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                )
            ),
            key_details=common_v1.PublicKeyDetails.PKIX_ED25519,
        )
        tlog = trustroot_v1.TransparencyLogInstance(
            base_url="https://rekor.example",
            hash_algorithm=common_v1.HashAlgorithm.SHA2_256,
            public_key=public_key,
            log_id=common_v1.LogId(key_id=base64.b64encode(b"legacy-log-id")),
            checkpoint_key_id=common_v1.LogId(
                key_id=base64.b64encode(checkpoint_key_id)
            ),
        )

        root_hash = base64.b64encode(b"\x00" * 32).decode()
        note = f"rekor.example\n42\n{root_hash}\n"
        signature = checkpoint_key_id + private_key.sign(note.encode())
        envelope = f"{note}\n— {name} {base64.b64encode(signature).decode()}\n"
        return SignedNote.from_text(envelope), RekorKeyring([tlog])

    def test_verify_uses_checkpoint_key_id(self):
        signed_note, keyring = self._signed_note("rekor.example", b"\x01\x02\x03\x04")

        signed_note.verify(keyring)

    def test_verify_rejects_wrong_log_name(self):
        signed_note, keyring = self._signed_note("other.example", b"\x01\x02\x03\x04")

        with pytest.raises(VerificationError, match="no valid signature"):
            signed_note.verify(keyring)
