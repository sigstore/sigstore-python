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

"""Offline intoto/0.0.2 bundles with real certificate and transparency evidence.

The RFC 6962 SCT and one-leaf Rekor construction adapts the author's fixture in
https://github.com/sigstore/sigstore-python/pull/1900 (separate, unmerged work).
All keys are disposable and generated in memory; no verifier is mocked. These
tests exercise a synthetic CA/Rekor profile, not enrollment at a public service.
"""

import base64
import hashlib
import json
import struct
from datetime import datetime, timedelta, timezone

import pytest
import rfc8785
from cryptography import x509
from cryptography.hazmat import asn1
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, ExtensionOID, NameOID
from sigstore_models.trustroot.v1 import TrustedRoot as RootModel

from sigstore.errors import VerificationError
from sigstore.models import Bundle, InvalidBundle, TrustedRoot
from sigstore.verify import Verifier
from sigstore.verify.policy import Identity
from sigstore.verify.verifier import _validate_intoto_v002_entry_body

_TIME = datetime(2025, 1, 1, tzinfo=timezone.utc)
_IDENTITY = "intoto-test@example.com"
_ISSUER = "https://issuer.example.com"
_PAYLOAD_TYPE = "application/vnd.in-toto+json"
_PAYLOAD = b'{"test":"synthetic intoto DSSE payload"}'


def _b64(value):
    return base64.b64encode(value).decode()


def _der_key(key):
    return key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )


@pytest.fixture(scope="module")
def intoto_materials():
    ca_key, ct_key, log_key, signing_key = (
        ec.generate_private_key(ec.SECP256R1()) for _ in range(4)
    )
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Synthetic CA")])
    ca = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(1)
        .not_valid_before(_TIME - timedelta(days=1))
        .not_valid_after(_TIME + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(False, False, False, False, False, True, True, None, None),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), False
        )
        .sign(ca_key, hashes.SHA256())
    )

    def leaf(identity, serial):
        builder = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([]))
            .issuer_name(ca_name)
            .public_key(signing_key.public_key())
            .serial_number(serial)
            .not_valid_before(_TIME - timedelta(minutes=5))
            .not_valid_after(_TIME + timedelta(minutes=5))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
            .add_extension(
                x509.KeyUsage(
                    True, False, False, False, False, False, False, None, None
                ),
                True,
            )
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CODE_SIGNING]), False
            )
            .add_extension(
                x509.SubjectAlternativeName([x509.RFC822Name(identity)]), True
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
                False,
            )
            .add_extension(
                x509.UnrecognizedExtension(
                    x509.ObjectIdentifier("1.3.6.1.4.1.57264.1.1"), _ISSUER.encode()
                ),
                False,
            )
        )
        # RFC 6962 section 3.2; encode independently of verifier helpers.
        tbs = builder.sign(ca_key, hashes.SHA256()).tbs_certificate_bytes
        timestamp = int(_TIME.timestamp() * 1000)
        sct_input = (
            struct.pack("!BBQH", 0, 0, timestamp, 1)
            + hashlib.sha256(_der_key(ca_key)).digest()
            + len(tbs).to_bytes(3, "big")
            + tbs
            + b"\x00\x00"
        )
        signature = ct_key.sign(sct_input, ec.ECDSA(hashes.SHA256()))
        sct = (
            b"\x00"
            + hashlib.sha256(_der_key(ct_key)).digest()
            + struct.pack("!QH", timestamp, 0)
            + struct.pack("!BBH", 4, 3, len(signature))
            + signature
        )
        sct_list = struct.pack("!HH", len(sct) + 2, len(sct)) + sct
        cert = builder.add_extension(
            x509.UnrecognizedExtension(
                ExtensionOID.PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS,
                asn1.encode_der(sct_list),
            ),
            False,
        ).sign(ca_key, hashes.SHA256())
        assert cert.tbs_precertificate_bytes == tbs
        return cert

    def log_config(key, url):
        return {
            "baseUrl": url,
            "hashAlgorithm": "SHA2_256",
            "logId": {"keyId": _b64(hashlib.sha256(_der_key(key)).digest())},
            "publicKey": {
                "rawBytes": _b64(_der_key(key)),
                "keyDetails": "PKIX_ECDSA_P256_SHA_256",
                "validFor": {"start": "2024-01-01T00:00:00Z"},
            },
        }

    root = TrustedRoot(
        RootModel.from_json(
            json.dumps(
                {
                    "mediaType": "application/vnd.dev.sigstore.trustedroot+json;version=0.1",
                    "tlogs": [log_config(log_key, "https://log.example.com")],
                    "ctlogs": [log_config(ct_key, "https://ct.example.com")],
                    "certificateAuthorities": [
                        {
                            "subject": {
                                "commonName": "Synthetic CA",
                                "organization": "Test",
                            },
                            "uri": "https://ca.example.com",
                            "certChain": {
                                "certificates": [
                                    {
                                        "rawBytes": _b64(
                                            ca.public_bytes(serialization.Encoding.DER)
                                        )
                                    }
                                ]
                            },
                            "validFor": {"start": "2024-01-01T00:00:00Z"},
                        }
                    ],
                }
            )
        )
    )
    return signing_key, leaf(_IDENTITY, 2), leaf("other@example.com", 3), log_key, root


def _bundle_json(
    materials, mutate_body=None, *, version="0.0.2", padded_signature=False
):
    signing_key, cert, _, log_key, _ = materials
    pae = (
        f"DSSEv1 {len(_PAYLOAD_TYPE)} {_PAYLOAD_TYPE} {len(_PAYLOAD)} ".encode()
        + _PAYLOAD
    )
    signature = _b64(signing_key.sign(pae, ec.ECDSA(hashes.SHA256())))
    if padded_signature:
        # ECDSA DER signatures vary in length. Obtain a padded representation
        # so stripping padding below actually exercises padding recovery.
        for _ in range(32):
            if signature.endswith("="):
                break
            signature = _b64(signing_key.sign(pae, ec.ECDSA(hashes.SHA256())))
        assert signature.endswith("=")
    envelope = {
        "payload": _b64(_PAYLOAD),
        "payloadType": _PAYLOAD_TYPE,
        "signatures": [{"sig": signature}],
    }
    body = {
        "kind": "intoto",
        "apiVersion": "0.0.2",
        "spec": {
            "content": {
                "payloadHash": {
                    "algorithm": "sha256",
                    "value": hashlib.sha256(_PAYLOAD).hexdigest(),
                },
                "hash": {
                    "algorithm": "sha256",
                    "value": hashlib.sha256(json.dumps(envelope).encode()).hexdigest(),
                },
                "envelope": {
                    "payloadType": _PAYLOAD_TYPE,
                    "signatures": [
                        {
                            # Rekor v1 intoto/0.0.2 stores base64 of the DSSE
                            # signature's base64 text, not directly its bytes.
                            "sig": _b64(signature.encode()),
                            "publicKey": _b64(
                                cert.public_bytes(serialization.Encoding.PEM)
                            ),
                        }
                    ],
                },
            }
        },
    }
    if mutate_body:
        mutate_body(body)
    # Mutations happen before both transparency signatures: negative cases
    # have valid inclusion evidence for the inconsistent body being tested.
    body_bytes = rfc8785.dumps(body)
    log_id = hashlib.sha256(_der_key(log_key)).digest()
    leaf_hash = hashlib.sha256(b"\x00" + body_bytes).digest()
    note = f"log.example.com\n1\n{_b64(leaf_hash)}\n"
    checkpoint_signature = log_key.sign(note.encode(), ec.ECDSA(hashes.SHA256()))
    checkpoint = (
        note + f"\n— log.example.com {_b64(log_id[:4] + checkpoint_signature)}\n"
    )
    set_payload = rfc8785.dumps(
        {
            "body": _b64(body_bytes),
            "integratedTime": int(_TIME.timestamp()),
            "logID": log_id.hex(),
            "logIndex": 0,
        }
    )
    return {
        "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
        "verificationMaterial": {
            "certificate": {
                "rawBytes": _b64(cert.public_bytes(serialization.Encoding.DER))
            },
            "tlogEntries": [
                {
                    "logIndex": "0",
                    "logId": {"keyId": _b64(log_id)},
                    "kindVersion": {"kind": "intoto", "version": version},
                    "integratedTime": str(int(_TIME.timestamp())),
                    "canonicalizedBody": _b64(body_bytes),
                    "inclusionPromise": {
                        "signedEntryTimestamp": _b64(
                            log_key.sign(set_payload, ec.ECDSA(hashes.SHA256()))
                        )
                    },
                    "inclusionProof": {
                        "logIndex": "0",
                        "rootHash": _b64(leaf_hash),
                        "treeSize": "1",
                        "hashes": [],
                        "checkpoint": {"envelope": checkpoint},
                    },
                }
            ],
        },
        "dsseEnvelope": envelope,
    }


def _verify(materials, bundle_json, *, identity=_IDENTITY, issuer=_ISSUER):
    return Verifier(trusted_root=materials[4]).verify_dsse(
        Bundle.from_json(json.dumps(bundle_json)),
        Identity(identity=identity, issuer=issuer),
    )


def test_intoto_complete_bundle(intoto_materials):
    assert _verify(intoto_materials, _bundle_json(intoto_materials)) == (
        _PAYLOAD_TYPE,
        _PAYLOAD,
    )


def test_intoto_body_validator_requires_envelope(intoto_materials):
    """Exercise the private helper's defensive guard, not an integration path."""
    bundle = Bundle.from_json(json.dumps(_bundle_json(intoto_materials)))
    bundle._inner.dsse_envelope = None
    with pytest.raises(VerificationError, match="without a DSSE envelope"):
        _validate_intoto_v002_entry_body(bundle)


@pytest.mark.parametrize(
    "representation",
    [
        "crlf-pem",
        "urlsafe-inner-signature",
        "unpadded-inner-signature",
        "key-id",
        "payload",
        "unpadded-payload",
        "envelope-hash",
    ],
)
def test_intoto_equivalent_representations(intoto_materials, representation):
    def mutate(body):
        content = body["spec"]["content"]
        envelope = content["envelope"]
        signature = envelope["signatures"][0]
        if representation == "crlf-pem":
            pem = base64.b64decode(signature["publicKey"])
            signature["publicKey"] = _b64(pem.replace(b"\n", b"\r\n"))
        elif representation == "urlsafe-inner-signature":
            raw = base64.b64decode(base64.b64decode(signature["sig"]))
            signature["sig"] = _b64(base64.urlsafe_b64encode(raw))
        elif representation == "unpadded-inner-signature":
            encoded = base64.b64decode(signature["sig"])
            assert encoded.endswith(b"=")
            signature["sig"] = _b64(encoded.rstrip(b"="))
        elif representation == "key-id":
            # keyid is an unsigned hint and need not match the bundle's hint.
            signature["keyid"] = "untrusted-key-hint"
        elif representation == "payload":
            envelope["payload"] = _b64(_b64(_PAYLOAD).encode())
        elif representation == "unpadded-payload":
            encoded = _b64(_PAYLOAD).encode()
            assert encoded.endswith(b"=")
            envelope["payload"] = _b64(encoded.rstrip(b"="))
        elif representation == "envelope-hash":
            # The original envelope serialization is unavailable. Its hash
            # cannot be recomputed; payload/type/signature/cert are bound separately.
            content["hash"]["value"] = "00" * 32
        else:
            raise AssertionError(representation)

    bundle_json = _bundle_json(
        intoto_materials,
        mutate,
        padded_signature=representation == "unpadded-inner-signature",
    )
    assert _verify(intoto_materials, bundle_json) == (
        _PAYLOAD_TYPE,
        _PAYLOAD,
    )


@pytest.mark.parametrize("field", ["identity", "issuer"])
def test_intoto_identity_denied(intoto_materials, field):
    with pytest.raises(VerificationError, match="SANs do not match|issuer"):
        _verify(
            intoto_materials,
            _bundle_json(intoto_materials),
            **{field: "wrong@example.com"},
        )


@pytest.mark.parametrize(
    "mutation",
    [
        "payload-hash",
        "missing-payload-hash",
        "hash-algorithm",
        "missing-envelope-hash",
        "malformed-envelope-hash",
        "payload-type",
        "payload",
        "invalid-payload-base64",
        "invalid-inner-payload-base64",
        "single-base64-payload",
        "signature",
        "empty-signatures",
        "extra-signature",
        "cross-certificate",
        "certificate-chain",
        "public-key",
        "invalid-public-key-base64",
        "single-base64-signature",
        "invalid-outer-base64",
        "invalid-inner-base64",
        "wrong-body-version",
        "wrong-body-kind",
        "missing-body-kind",
        "v001-body-shape",
    ],
)
def test_intoto_authenticated_body_mismatch(intoto_materials, mutation):
    def mutate(body):
        content = body["spec"]["content"]
        envelope = content["envelope"]
        signature = envelope["signatures"][0]
        if mutation == "payload-hash":
            content["payloadHash"]["value"] = "00" * 32
        elif mutation == "missing-payload-hash":
            del content["payloadHash"]
        elif mutation == "hash-algorithm":
            content["payloadHash"]["algorithm"] = "sha512"
        elif mutation == "missing-envelope-hash":
            del content["hash"]
        elif mutation == "malformed-envelope-hash":
            content["hash"]["value"] = "not-a-sha256-digest"
        elif mutation == "payload-type":
            envelope["payloadType"] = "application/json"
        elif mutation == "payload":
            envelope["payload"] = _b64(_b64(b"different payload").encode())
        elif mutation == "invalid-payload-base64":
            envelope["payload"] = "!" + _b64(_PAYLOAD)
        elif mutation == "invalid-inner-payload-base64":
            envelope["payload"] = _b64(b"!" + _b64(_PAYLOAD).encode())
        elif mutation == "single-base64-payload":
            envelope["payload"] = _b64(_PAYLOAD)
        elif mutation == "signature":
            signature["sig"] = _b64(_b64(b"other signature").encode())
        elif mutation == "empty-signatures":
            envelope["signatures"] = []
        elif mutation == "extra-signature":
            envelope["signatures"].append(dict(signature))
        elif mutation == "cross-certificate":
            # Same public key, separately CA/SCT-signed leaf, different identity.
            signature["publicKey"] = _b64(
                intoto_materials[2].public_bytes(serialization.Encoding.PEM)
            )
        elif mutation == "certificate-chain":
            signature["publicKey"] = _b64(
                base64.b64decode(signature["publicKey"])
                + intoto_materials[2].public_bytes(serialization.Encoding.PEM)
            )
        elif mutation == "public-key":
            signature["publicKey"] = _b64(
                intoto_materials[0]
                .public_key()
                .public_bytes(
                    serialization.Encoding.PEM,
                    serialization.PublicFormat.SubjectPublicKeyInfo,
                )
            )
        elif mutation == "invalid-public-key-base64":
            signature["publicKey"] = "!" + signature["publicKey"]
        elif mutation == "single-base64-signature":
            signature["sig"] = base64.b64decode(signature["sig"]).decode()
        elif mutation == "invalid-outer-base64":
            signature["sig"] = "!" + signature["sig"]
        elif mutation == "invalid-inner-base64":
            signature["sig"] = _b64(b"!" + base64.b64decode(signature["sig"]))
        elif mutation == "wrong-body-version":
            body["apiVersion"] = "0.0.1"
        elif mutation == "wrong-body-kind":
            body["kind"] = "dsse"
        elif mutation == "missing-body-kind":
            del body["kind"]
        elif mutation == "v001-body-shape":
            body["spec"]["publicKey"] = signature["publicKey"]
            content["envelope"] = json.dumps(envelope)
        else:
            raise AssertionError(mutation)

    bundle = Bundle.from_json(json.dumps(_bundle_json(intoto_materials, mutate)))
    verifier = Verifier(trusted_root=intoto_materials[4])
    policy = Identity(identity=_IDENTITY, issuer=_ISSUER)
    # Assert the CA, SCT, policy, SET, Merkle proof and checkpoint all pass.
    # Therefore a public-API rejection below must concern DSSE/body consistency.
    verifier._verify_common_signing_cert(bundle, policy)
    with pytest.raises(VerificationError, match="intoto"):
        verifier.verify_dsse(bundle, policy)


def test_intoto_unsupported_entry_version(intoto_materials):
    with pytest.raises(VerificationError, match="Integrated time|intoto"):
        _verify(intoto_materials, _bundle_json(intoto_materials, version="0.0.1"))


@pytest.mark.parametrize("missing", ["inclusionPromise", "integratedTime"])
def test_intoto_requires_signed_time(intoto_materials, missing):
    bundle_json = _bundle_json(intoto_materials)
    del bundle_json["verificationMaterial"]["tlogEntries"][0][missing]
    if missing == "inclusionPromise":
        # A checkpoint without a SET authenticates inclusion, not integratedTime.
        with pytest.raises(
            InvalidBundle, match="inclusion promise or signed timestamp"
        ):
            _verify(intoto_materials, bundle_json)
    else:
        with pytest.raises(
            VerificationError, match="not enough sources of verified time"
        ):
            _verify(intoto_materials, bundle_json)


@pytest.mark.parametrize(
    "mutation, message",
    [
        ("signature", "invalid"),
        ("certificate", "failed to build timestamp certificate chain"),
        ("checkpoint", "checkpoint: invalid signature"),
        ("set", "SET: invalid inclusion promise"),
        ("proof", "inclusion proof|root hash|inclusion root"),
        ("ct-key", "SCT"),
    ],
)
def test_intoto_crypto_tampering(intoto_materials, mutation, message):
    bundle_json = _bundle_json(intoto_materials)
    material = bundle_json["verificationMaterial"]
    entry = material["tlogEntries"][0]
    root_json = json.loads(intoto_materials[4]._inner.to_json())

    def corrupted(value):
        raw = base64.b64decode(value)
        return _b64(raw[:-1] + bytes([raw[-1] ^ 1]))

    if mutation == "signature":
        signature = bundle_json["dsseEnvelope"]["signatures"][0]
        signature["sig"] = corrupted(signature["sig"])
    elif mutation == "certificate":
        material["certificate"]["rawBytes"] = corrupted(
            material["certificate"]["rawBytes"]
        )
    elif mutation == "checkpoint":
        checkpoint = entry["inclusionProof"]["checkpoint"]
        note, block = checkpoint["envelope"].split("\n\n")
        prefix, signature = block.rstrip().rsplit(" ", 1)
        checkpoint["envelope"] = f"{note}\n\n{prefix} {corrupted(signature)}\n"
    elif mutation == "set":
        promise = entry["inclusionPromise"]
        promise["signedEntryTimestamp"] = corrupted(promise["signedEntryTimestamp"])
    elif mutation == "proof":
        entry["inclusionProof"]["rootHash"] = _b64(b"\x00" * 32)
    elif mutation == "ct-key":
        root_json["ctlogs"][0]["publicKey"]["rawBytes"] = _b64(
            _der_key(ec.generate_private_key(ec.SECP256R1()))
        )
    else:
        raise AssertionError(mutation)

    root = TrustedRoot(RootModel.from_json(json.dumps(root_json)))
    bundle = Bundle.from_json(json.dumps(bundle_json))
    with pytest.raises(VerificationError, match=message):
        Verifier(trusted_root=root).verify_dsse(
            bundle, Identity(identity=_IDENTITY, issuer=_ISSUER)
        )
