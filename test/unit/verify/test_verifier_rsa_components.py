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

"""RSA signature/body component tests, not certificate or log-trust integration.

Only ``_verify_common_signing_cert`` is isolated. Signatures, bundle parsing,
and Rekor v1/v2 body-consistency verification execute their real implementations.
The reused log proof is structural scaffolding, not valid evidence for these
new signatures; these tests deliberately make no transparency-trust claim.
"""

import base64
import copy
import hashlib
import json
from datetime import datetime, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from sigstore_models.common.v1 import HashAlgorithm

from sigstore import dsse
from sigstore._internal.rekor import _hashedrekord_from_parts
from sigstore._internal.rekor.client_v2 import RekorV2Client
from sigstore._utils import base64_encode_pem_cert, sha256_digest
from sigstore.errors import Error, VerificationError
from sigstore.hashes import Hashed
from sigstore.models import Bundle, TransparencyLogEntry
from sigstore.verify.verifier import Verifier

_INPUT = b"RSA artifact verification component test"


def _certificate(public_key, serial=1):
    issuer = ec.generate_private_key(ec.SECP256R1())
    return (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "leaf")]))
        .issuer_name(
            x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "issuer")])
        )
        .public_key(public_key)
        .serial_number(serial)
        .not_valid_before(datetime(2025, 1, 1, tzinfo=timezone.utc))
        .not_valid_after(datetime(2030, 1, 1, tzinfo=timezone.utc))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(issuer, hashes.SHA256())
    )


def _signer(key_size):
    key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    return key, _certificate(key.public_key())


@pytest.fixture(scope="module", params=[2048, 3072, 4096])
def signer(request):
    return _signer(request.param)


@pytest.fixture(scope="module")
def rsa2048():
    return _signer(2048)


@pytest.fixture
def component_verifier(monkeypatch):
    verifier = object.__new__(Verifier)
    monkeypatch.setattr(
        verifier, "_verify_common_signing_cert", lambda bundle, policy: None
    )
    return verifier


def _bundle(asset, signer, version, *, signature=None, dsse_payload=False):
    key, certificate = signer
    payload_type = dsse.Envelope._TYPE
    signed = dsse._pae(payload_type, _INPUT) if dsse_payload else _INPUT
    if signature is None:
        signature = key.sign(signed, padding.PKCS1v15(), hashes.SHA256())
    if dsse_payload:
        envelope = dsse.Envelope._from_json(
            json.dumps(
                {
                    "payload": base64.b64encode(_INPUT).decode(),
                    "payloadType": payload_type,
                    "signatures": [{"sig": base64.b64encode(signature).decode()}],
                }
            )
        )
        request = RekorV2Client._build_dsse_request(envelope, certificate)
    else:
        request = None

    if version == "0.0.1":
        assert not dsse_payload
        body = _hashedrekord_from_parts(
            certificate, signature, sha256_digest(_INPUT)
        ).model_dump_json(by_alias=True)
    else:
        if request is None:
            request = RekorV2Client._build_hashed_rekord_request(
                sha256_digest(_INPUT), signature, certificate
            )
        content = request["hashedRekordRequestV002"]
        body = json.dumps(
            {
                "apiVersion": "0.0.2",
                "kind": "hashedrekord",
                "spec": {
                    "hashedRekordV002": {
                        "data": {"algorithm": "SHA2_256", "digest": content["digest"]},
                        "signature": content["signature"],
                    }
                },
            }
        )

    # The proof is intentionally NOT verified by this component fixture.
    original = Bundle.from_json(asset("bundle.txt.sigstore").read_bytes())
    entry = copy.deepcopy(original.log_entry._inner)
    entry.kind_version.kind = "hashedrekord"
    entry.kind_version.version = version
    entry.canonicalized_body = body.encode()
    log_entry = TransparencyLogEntry(entry)
    if dsse_payload:
        return Bundle._from_parts(certificate, envelope, log_entry)
    return Bundle.from_parts(certificate, signature, log_entry)


@pytest.mark.parametrize("version", ["0.0.1", "0.0.2"])
@pytest.mark.parametrize("prehashed", [False, True], ids=["bytes", "digest"])
def test_rsa_artifact_signature_and_body(
    asset, signer, version, prehashed, component_verifier, null_policy
):
    bundle = _bundle(asset, signer, version)
    input_ = sha256_digest(_INPUT) if prehashed else _INPUT
    component_verifier.verify_artifact(input_, bundle, null_policy)


@pytest.mark.parametrize("version", ["0.0.1", "0.0.2"])
@pytest.mark.parametrize("digest_bytes", ["mislabeled-sha256", "sha384"])
def test_rsa_artifact_rejects_unsupported_digest_algorithm(
    asset, rsa2048, version, digest_bytes, component_verifier, null_policy
):
    bundle = _bundle(asset, rsa2048, version)
    assert bundle._inner.message_signature.message_digest is None
    digest = (
        sha256_digest(_INPUT).digest
        if digest_bytes == "mislabeled-sha256"
        else hashlib.sha384(_INPUT).digest()
    )
    input_ = Hashed(algorithm=HashAlgorithm.SHA2_384, digest=digest)
    with pytest.raises(Error, match="unknown hash algorithm"):
        component_verifier.verify_artifact(input_, bundle, null_policy)


@pytest.mark.parametrize("version", ["0.0.1", "0.0.2"])
@pytest.mark.parametrize("algorithm", ["pss-sha256", "pkcs1v15-sha384"])
def test_rsa_artifact_rejects_other_algorithms(
    asset, rsa2048, version, algorithm, component_verifier, null_policy
):
    key, _ = rsa2048
    if algorithm == "pss-sha256":
        scheme = padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()), salt_length=hashes.SHA256.digest_size
        )
        digest = hashes.SHA256()
    else:
        scheme = padding.PKCS1v15()
        digest = hashes.SHA384()
    signature = key.sign(_INPUT, scheme, digest)
    key.public_key().verify(signature, _INPUT, scheme, digest)
    bundle = _bundle(asset, rsa2048, version, signature=signature)
    with pytest.raises(VerificationError, match="Signature is invalid for input"):
        component_verifier.verify_artifact(_INPUT, bundle, null_policy)


@pytest.mark.parametrize("version", ["0.0.1", "0.0.2"])
@pytest.mark.parametrize("change", ["input", "key"])
def test_rsa_artifact_rejects_substitution(
    asset, rsa2048, version, change, component_verifier, null_policy
):
    bundle = _bundle(asset, rsa2048, version)
    if change == "input":
        input_ = _INPUT + b"changed"
    else:
        input_ = _INPUT
        _, bundle._signing_certificate = _signer(2048)
    with pytest.raises(VerificationError, match="Signature is invalid for input"):
        component_verifier.verify_artifact(input_, bundle, null_policy)


def _change_body(bundle, field, certificate):
    body = json.loads(bundle.log_entry._inner.canonicalized_body)
    if bundle.log_entry._inner.kind_version.version == "0.0.1":
        signature = body["spec"]["signature"]
        if field == "signature":
            signature["content"] = base64.b64encode(b"different signature").decode()
        else:
            signature["publicKey"]["content"] = base64_encode_pem_cert(certificate)
    else:
        content = body["spec"]["hashedRekordV002"]
        if field == "signature":
            content["signature"]["content"] = base64.b64encode(
                b"different signature"
            ).decode()
        elif field == "certificate":
            content["signature"]["verifier"]["x509Certificate"]["rawBytes"] = (
                base64.b64encode(
                    certificate.public_bytes(serialization.Encoding.DER)
                ).decode()
            )
        elif field == "key_details":
            content["signature"]["verifier"]["keyDetails"] = (
                "PKIX_RSA_PKCS1V15_3072_SHA256"
            )
        elif field == "digest":
            content["data"]["digest"] = base64.b64encode(b"x" * 32).decode()
        else:
            assert field == "hash_algorithm"
            content["data"]["algorithm"] = "SHA2_384"
    bundle.log_entry._inner.canonicalized_body = json.dumps(body).encode()


@pytest.mark.parametrize("version", ["0.0.1", "0.0.2"])
@pytest.mark.parametrize("field", ["signature", "certificate"])
def test_rsa_artifact_rejects_inconsistent_log_body(
    asset, rsa2048, version, field, component_verifier, null_policy
):
    bundle = _bundle(asset, rsa2048, version)
    # A second certificate for the same public key still must not substitute
    # for the exact certificate bound into the transparency entry.
    certificate = _certificate(rsa2048[0].public_key(), serial=2)
    _change_body(bundle, field, certificate)
    with pytest.raises(VerificationError, match="inconsistent with other materials"):
        component_verifier.verify_artifact(_INPUT, bundle, null_policy)


def test_rsa_artifact_rejects_unsupported_size(asset, component_verifier, null_policy):
    bundle = _bundle(asset, _signer(1024), "0.0.1")
    with pytest.raises(VerificationError, match="Unsupported RSA key size: 1024"):
        component_verifier.verify_artifact(_INPUT, bundle, null_policy)


def test_rsa_dsse_rekor_v2_signature_and_body(
    asset, signer, component_verifier, null_policy
):
    bundle = _bundle(asset, signer, "0.0.2", dsse_payload=True)
    assert component_verifier.verify_dsse(bundle, null_policy) == (
        dsse.Envelope._TYPE,
        _INPUT,
    )


@pytest.mark.parametrize(
    "field", ["signature", "certificate", "key_details", "digest", "hash_algorithm"]
)
def test_rsa_dsse_rekor_v2_rejects_inconsistent_log_body(
    asset, rsa2048, field, component_verifier, null_policy
):
    bundle = _bundle(asset, rsa2048, "0.0.2", dsse_payload=True)
    certificate = _certificate(rsa2048[0].public_key(), serial=2)
    _change_body(bundle, field, certificate)
    with pytest.raises(VerificationError, match="inconsistent with other materials"):
        component_verifier.verify_dsse(bundle, null_policy)
