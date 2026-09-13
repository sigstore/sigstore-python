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
import json

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa

from sigstore import dsse
from sigstore.dsse import Error, InvalidEnvelope
from sigstore.errors import VerificationError


class TestEnvelope:
    def test_roundtrip(self):
        raw = json.dumps(
            {
                "payload": base64.b64encode(b"foo").decode(),
                "payloadType": dsse.Envelope._TYPE,
                "signatures": [
                    {"sig": base64.b64encode(b"lol").decode()},
                ],
            }
        )
        evp = dsse.Envelope._from_json(raw)

        assert evp._inner.payload == b"foo"
        assert evp._inner.payload_type == dsse.Envelope._TYPE
        assert evp.signature == b"lol"

        serialized = evp.to_json()
        # envelope matches
        assert dsse.Envelope._from_json(serialized) == evp
        # parsed JSON marches
        assert json.loads(raw) == evp._inner.to_dict()

    def test_missing_signature(self):
        raw = json.dumps(
            {
                "payload": base64.b64encode(b"foo").decode(),
                "payloadType": dsse.Envelope._TYPE,
                "signatures": [],
            }
        )

        with pytest.raises(InvalidEnvelope, match="one signature"):
            dsse.Envelope._from_json(raw)

    def test_empty_signature(self):
        raw = json.dumps(
            {
                "payload": base64.b64encode(b"foo").decode(),
                "payloadType": dsse.Envelope._TYPE,
                "signatures": [
                    {"sig": ""},
                ],
            }
        )

        with pytest.raises(InvalidEnvelope, match="non-empty"):
            dsse.Envelope._from_json(raw)

    def test_multiple_signatures(self):
        raw = json.dumps(
            {
                "payload": base64.b64encode(b"foo").decode(),
                "payloadType": dsse.Envelope._TYPE,
                "signatures": [
                    {"sig": base64.b64encode(b"lol").decode()},
                    {"sig": base64.b64encode(b"lmao").decode()},
                ],
            }
        )

        with pytest.raises(InvalidEnvelope, match="one signature"):
            dsse.Envelope._from_json(raw)


class TestStatement:
    def test_malformed_statement_reports_why(self):
        # An unsupported digest algorithm is rejected by design, but the caller
        # is left guessing: the same message covers a missing field, a bad
        # _type, and a rejected digest. StatementBuilder.build() already
        # surfaces the underlying validation error; parsing should too.
        raw = json.dumps(
            {
                "_type": "https://in-toto.io/Statement/v1",
                "subject": [{"name": "foo", "digest": {"gitCommit": "a" * 40}}],
                "predicateType": "https://example.com/predicate/v1",
                "predicate": {},
            }
        )

        with pytest.raises(Error, match="malformed in-toto statement") as exc:
            dsse.Statement(raw.encode())

        # the cause is preserved, and names the offending field
        assert exc.value.__cause__ is not None
        assert "digest" in str(exc.value)


@pytest.fixture(scope="module", params=[2048, 3072, 4096])
def rsa_signing_key(request):
    return rsa.generate_private_key(public_exponent=65537, key_size=request.param)


def _signed_envelope(payload, payload_type, signature):
    return dsse.Envelope._from_json(
        json.dumps(
            {
                "payload": base64.b64encode(payload).decode(),
                "payloadType": payload_type,
                "signatures": [{"sig": base64.b64encode(signature).decode()}],
            }
        )
    )


class TestSignatureVerification:
    # These tests exercise genuine signatures over DSSE PAE. Certificate identity,
    # trust chains, and transparency-log checks belong to the verifier tests.
    payload = b'{"predicateType":"https://example.com/test/v1","predicate":{}}'
    payload_type = dsse.Envelope._TYPE

    def test_rsa_pkcs1v15_sha256(self, rsa_signing_key):
        pae = dsse._pae(self.payload_type, self.payload)
        signature = rsa_signing_key.sign(pae, padding.PKCS1v15(), hashes.SHA256())
        envelope = _signed_envelope(self.payload, self.payload_type, signature)

        assert dsse._verify(rsa_signing_key.public_key(), envelope) == self.payload

    @pytest.mark.parametrize("unsupported_algorithm", ["pss-sha256", "pkcs1v15-sha384"])
    def test_rsa_rejects_other_signature_algorithms(
        self, rsa_signing_key, unsupported_algorithm
    ):
        pae = dsse._pae(self.payload_type, self.payload)
        if unsupported_algorithm == "pss-sha256":
            signature_padding = padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.DIGEST_LENGTH
            )
            signature_hash = hashes.SHA256()
        else:
            signature_padding = padding.PKCS1v15()
            signature_hash = hashes.SHA384()
        signature = rsa_signing_key.sign(pae, signature_padding, signature_hash)
        # The negative is a valid signature under a different algorithm, not
        # random invalid bytes that would fail under any verification policy.
        rsa_signing_key.public_key().verify(
            signature, pae, signature_padding, signature_hash
        )
        envelope = _signed_envelope(self.payload, self.payload_type, signature)

        with pytest.raises(VerificationError, match="DSSE: invalid signature"):
            dsse._verify(rsa_signing_key.public_key(), envelope)

    @pytest.mark.parametrize("modified_field", ["payload", "payload_type"])
    def test_rsa_signature_binds_payload_and_type(
        self, rsa_signing_key, modified_field
    ):
        pae = dsse._pae(self.payload_type, self.payload)
        signature = rsa_signing_key.sign(pae, padding.PKCS1v15(), hashes.SHA256())
        payload = self.payload + b" " if modified_field == "payload" else self.payload
        payload_type = (
            "application/vnd.example.other+json"
            if modified_field == "payload_type"
            else self.payload_type
        )
        envelope = _signed_envelope(payload, payload_type, signature)

        with pytest.raises(VerificationError, match="DSSE: invalid signature"):
            dsse._verify(rsa_signing_key.public_key(), envelope)

    def test_rsa_rejects_changed_signature(self, rsa_signing_key):
        pae = dsse._pae(self.payload_type, self.payload)
        signature = rsa_signing_key.sign(pae, padding.PKCS1v15(), hashes.SHA256())
        changed_signature = signature[:-1] + bytes([signature[-1] ^ 1])
        envelope = _signed_envelope(self.payload, self.payload_type, changed_signature)

        with pytest.raises(VerificationError, match="DSSE: invalid signature"):
            dsse._verify(rsa_signing_key.public_key(), envelope)

    def test_rsa_rejects_wrong_key(self, rsa_signing_key):
        pae = dsse._pae(self.payload_type, self.payload)
        unrelated_key = rsa.generate_private_key(
            public_exponent=65537, key_size=rsa_signing_key.key_size
        )
        signature = unrelated_key.sign(pae, padding.PKCS1v15(), hashes.SHA256())
        envelope = _signed_envelope(self.payload, self.payload_type, signature)

        with pytest.raises(VerificationError, match="DSSE: invalid signature"):
            dsse._verify(rsa_signing_key.public_key(), envelope)

    def test_rejects_unsupported_rsa_size(self):
        key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
        pae = dsse._pae(self.payload_type, self.payload)
        signature = key.sign(pae, padding.PKCS1v15(), hashes.SHA256())
        key.public_key().verify(signature, pae, padding.PKCS1v15(), hashes.SHA256())
        envelope = _signed_envelope(self.payload, self.payload_type, signature)

        with pytest.raises(VerificationError):
            dsse._verify(key.public_key(), envelope)

    def test_rejects_unsupported_ed25519(self):
        key = ed25519.Ed25519PrivateKey.generate()
        pae = dsse._pae(self.payload_type, self.payload)
        signature = key.sign(pae)
        key.public_key().verify(signature, pae)
        envelope = _signed_envelope(self.payload, self.payload_type, signature)

        with pytest.raises(VerificationError):
            dsse._verify(key.public_key(), envelope)

    @pytest.mark.parametrize("curve", [ec.SECP256R1, ec.SECP384R1, ec.SECP521R1])
    def test_preserves_ecdsa_sha256_verification(self, curve):
        key = ec.generate_private_key(curve())
        pae = dsse._pae(self.payload_type, self.payload)
        signature = key.sign(pae, ec.ECDSA(hashes.SHA256()))
        envelope = _signed_envelope(self.payload, self.payload_type, signature)

        assert dsse._verify(key.public_key(), envelope) == self.payload
