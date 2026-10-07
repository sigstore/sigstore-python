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
from cryptography.hazmat.primitives.asymmetric import ed25519
from sigstore_models.common import v1 as common_v1

from sigstore._internal.rekor.checkpoint import LogCheckpoint, SignedNote
from sigstore._internal.trust import Keyring
from sigstore._utils import checkpoint_key_id, key_id
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
    def _ed25519_keyring(self, private_key):
        """
        Build a RekorKeyring containing the given Ed25519 private key's
        public key, and return it together with the key's log ID form
        (SHA-256 over the DER SPKI, as a Rekor server would report it).
        """
        public_key = private_key.public_key()
        assert isinstance(public_key, ed25519.Ed25519PublicKey)
        der = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        keyring = Keyring(
            [
                common_v1.PublicKey(
                    raw_bytes=base64.b64encode(der),
                    key_details=common_v1.PublicKeyDetails.PKIX_ED25519,
                )
            ]
        )
        return keyring, key_id(public_key)

    def _signed_note(self, key_name, key_hash, signature, note_header):
        sig_line = (
            f"\u2014 {key_name} {base64.b64encode(key_hash + signature).decode()}\n"
        )
        return SignedNote.from_text(note_header + "\n" + sig_line)

    def _note_header(self):
        return (
            "rekor.example - 123\n42\n" + base64.b64encode(b"\x00" * 32).decode() + "\n"
        )

    def test_verify_ed25519_checkpoint_key_id(self):
        """
        A checkpoint signed by an Ed25519 key carries the C2SP key ID
        (sigstore/rekor#2062), not the log ID prefix. `SignedNote.verify`
        must select the signature via the type-dependent key ID.
        """
        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        key_name = "rekor.example"
        note_header = self._note_header()

        key_hash = checkpoint_key_id(public_key, key_name)
        signature = private_key.sign(note_header.encode())

        keyring, log_key_id = self._ed25519_keyring(private_key)
        signed_note = self._signed_note(key_name, key_hash, signature, note_header)

        # The C2SP key hash differs from the log ID prefix; without the
        # type-dependent matching this raises "Signature not found".
        assert key_hash != log_key_id[:4]
        signed_note.verify(keyring, log_key_id)

    def test_verify_ed25519_legacy_key_hash_still_works(self):
        """
        Checkpoints signed before the rekor#2062 key ID change carry the
        truncated DER hash for all key types; those must keep verifying.
        """
        private_key = ed25519.Ed25519PrivateKey.generate()
        key_name = "rekor.example"
        note_header = self._note_header()

        keyring, log_key_id = self._ed25519_keyring(private_key)
        # Legacy form: the note's key hash is the log ID (DER hash) prefix.
        signature = private_key.sign(note_header.encode())
        signed_note = self._signed_note(
            key_name, log_key_id[:4], signature, note_header
        )
        signed_note.verify(keyring, log_key_id)

    def test_verify_ed25519_bad_signature_rejected(self):
        """
        Selecting a signature via its key hash must not weaken verification:
        a bad signature from the right key still fails closed.
        """
        private_key = ed25519.Ed25519PrivateKey.generate()
        other_key = ed25519.Ed25519PrivateKey.generate()
        key_name = "rekor.example"
        note_header = self._note_header()

        key_hash = checkpoint_key_id(private_key.public_key(), key_name)
        # Signed by a *different* key, but carrying the right key's hash.
        signature = other_key.sign(note_header.encode())

        keyring, log_key_id = self._ed25519_keyring(private_key)
        signed_note = self._signed_note(key_name, key_hash, signature, note_header)

        with pytest.raises(VerificationError, match="invalid signature"):
            signed_note.verify(keyring, log_key_id)
