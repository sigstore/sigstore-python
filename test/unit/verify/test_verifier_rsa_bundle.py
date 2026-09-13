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

"""Offline RSA bundles with real CA, SCT, checkpoint and SET signatures.

All keys are disposable, generated in memory. No verification step is mocked.
This exercises a synthetic Rekor v1/CA profile, not public-service enrollment.
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
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, ExtensionOID, NameOID
from sigstore_models.trustroot.v1 import TrustedRoot as RootModel

from sigstore.errors import VerificationError
from sigstore.models import Bundle, TrustedRoot
from sigstore.verify import Verifier
from sigstore.verify.policy import Identity

_TIME = datetime(2025, 1, 1, tzinfo=timezone.utc)
_IDENTITY = "rsa-test@example.com"
_ISSUER = "https://issuer.example.com"
_ARTIFACT = b"RSA verification regression\n"


def _b64(value):
    return base64.b64encode(value).decode()


def _der_key(key):
    return key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )


@pytest.fixture(scope="module")
def rsa_bundle_materials():
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ct_key = ec.generate_private_key(ec.SECP256R1())
    log_key = ec.generate_private_key(ec.SECP256R1())
    signing_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
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
            x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([]))
        .issuer_name(ca_name)
        .public_key(signing_key.public_key())
        .serial_number(2)
        .not_valid_before(_TIME - timedelta(minutes=5))
        .not_valid_after(_TIME + timedelta(minutes=5))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
        .add_extension(
            x509.KeyUsage(True, False, False, False, False, False, False, None, None),
            critical=True,
        )
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CODE_SIGNING]), False)
        .add_extension(x509.SubjectAlternativeName([x509.RFC822Name(_IDENTITY)]), True)
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
    # RFC 6962 section 3.2: sign the precertificate TBS without the SCT list.
    # Encode independently of Sigstore's verification/packing helpers.
    tbs = builder.sign(ca_key, hashes.SHA256()).tbs_certificate_bytes
    timestamp = int(_TIME.timestamp() * 1000)
    ct_id = hashlib.sha256(_der_key(ct_key)).digest()
    signed_sct = (
        struct.pack("!BBQH", 0, 0, timestamp, 1)
        + hashlib.sha256(_der_key(ca_key)).digest()
        + len(tbs).to_bytes(3, "big")
        + tbs
        + b"\x00\x00"
    )
    sct_signature = ct_key.sign(signed_sct, ec.ECDSA(hashes.SHA256()))
    sct = (
        b"\x00"
        + ct_id
        + struct.pack("!QH", timestamp, 0)
        + struct.pack("!BBH", 4, 3, len(sct_signature))
        + sct_signature
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
    return signing_key, cert, log_key, root


def _bundle(materials, dsse, *, inconsistent=False):
    signing_key, cert, log_key, _ = materials
    payload = b'{"test":"synthetic RSA DSSE payload"}' if dsse else _ARTIFACT
    payload_type = "application/vnd.in-toto+json"
    data = (
        f"DSSEv1 {len(payload_type)} {payload_type} {len(payload)} ".encode() + payload
        if dsse
        else payload
    )
    signature = signing_key.sign(data, padding.PKCS1v15(), hashes.SHA256())
    logged_signature = b"different signature" if inconsistent else signature
    pem = cert.public_bytes(serialization.Encoding.PEM)
    if dsse:
        content = {
            "dsseEnvelope": {
                "payload": _b64(payload),
                "payloadType": payload_type,
                "signatures": [{"sig": _b64(signature)}],
            }
        }
        body = {
            "kind": "dsse",
            "apiVersion": "0.0.1",
            "spec": {
                "payloadHash": {
                    "algorithm": "sha256",
                    "value": hashlib.sha256(payload).hexdigest(),
                },
                "envelopeHash": {
                    "algorithm": "sha256",
                    "value": hashlib.sha256(
                        json.dumps(content["dsseEnvelope"]).encode()
                    ).hexdigest(),
                },
                "signatures": [
                    {"signature": _b64(logged_signature), "verifier": _b64(pem)}
                ],
            },
        }
    else:
        content = {
            "messageSignature": {
                "signature": _b64(signature),
                "messageDigest": {
                    "algorithm": "SHA2_256",
                    "digest": _b64(hashlib.sha256(payload).digest()),
                },
            }
        }
        body = {
            "kind": "hashedrekord",
            "apiVersion": "0.0.1",
            "spec": {
                "data": {
                    "hash": {
                        "algorithm": "sha256",
                        "value": hashlib.sha256(payload).hexdigest(),
                    }
                },
                "signature": {
                    "content": _b64(logged_signature),
                    "publicKey": {"content": _b64(pem)},
                },
            },
        }
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
    return Bundle.from_json(
        json.dumps(
            {
                "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
                "verificationMaterial": {
                    "certificate": {
                        "rawBytes": _b64(cert.public_bytes(serialization.Encoding.DER))
                    },
                    "tlogEntries": [
                        {
                            "logIndex": "0",
                            "logId": {"keyId": _b64(log_id)},
                            "kindVersion": {"kind": body["kind"], "version": "0.0.1"},
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
                **content,
            }
        )
    )


def _verify(root, bundle, dsse, identity=_IDENTITY):
    verifier = Verifier(trusted_root=root)
    policy = Identity(identity=identity, issuer=_ISSUER)
    if dsse:
        return verifier.verify_dsse(bundle, policy)
    return verifier.verify_artifact(_ARTIFACT, bundle, policy)


@pytest.mark.parametrize("dsse", [False, True], ids=["artifact", "dsse"])
def test_rsa_complete_bundle(rsa_bundle_materials, dsse):
    bundle = _bundle(rsa_bundle_materials, dsse)
    result = _verify(rsa_bundle_materials[3], bundle, dsse)
    if dsse:
        assert result == (
            "application/vnd.in-toto+json",
            b'{"test":"synthetic RSA DSSE payload"}',
        )


@pytest.mark.parametrize("dsse", [False, True], ids=["artifact", "dsse"])
def test_rsa_complete_bundle_identity_denied(rsa_bundle_materials, dsse):
    bundle = _bundle(rsa_bundle_materials, dsse)
    with pytest.raises(VerificationError, match="SANs do not match"):
        _verify(rsa_bundle_materials[3], bundle, dsse, "wrong@example.com")


@pytest.mark.parametrize("dsse", [False, True], ids=["artifact", "dsse"])
def test_rsa_complete_bundle_signed_log_mismatch(rsa_bundle_materials, dsse):
    # All signatures, including SCT/SET/checkpoint, are valid, but the log's
    # authenticated signature field describes a different artifact signature.
    bundle = _bundle(rsa_bundle_materials, dsse, inconsistent=True)
    with pytest.raises(VerificationError, match="inconsistent|signatures do not match"):
        _verify(rsa_bundle_materials[3], bundle, dsse)


@pytest.mark.parametrize("dsse", [False, True], ids=["artifact", "dsse"])
@pytest.mark.parametrize(
    "mutation, message",
    [
        ("signature", "invalid|Signature is invalid"),
        ("certificate", "failed to build timestamp certificate chain"),
        ("checkpoint", "checkpoint: invalid signature"),
        ("set", "SET: invalid inclusion promise"),
        ("ct-key", "SCT"),
        ("log-key", "checkpoint: invalid signature"),
    ],
)
def test_rsa_complete_bundle_tampering(rsa_bundle_materials, dsse, mutation, message):
    bundle_json = json.loads(_bundle(rsa_bundle_materials, dsse).to_json())
    root_json = json.loads(rsa_bundle_materials[3]._inner.to_json())
    material = bundle_json["verificationMaterial"]
    entry = material["tlogEntries"][0]

    def corrupted(value):
        raw = base64.b64decode(value)
        return _b64(raw[:-1] + bytes([raw[-1] ^ 1]))

    if mutation == "signature":
        signature = (
            bundle_json["dsseEnvelope"]["signatures"][0]
            if dsse
            else bundle_json["messageSignature"]
        )
        field = "sig" if dsse else "signature"
        signature[field] = corrupted(signature[field])
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
    else:
        logs = root_json["ctlogs" if mutation == "ct-key" else "tlogs"]
        logs[0]["publicKey"]["rawBytes"] = _b64(
            _der_key(ec.generate_private_key(ec.SECP256R1()))
        )

    bundle = Bundle.from_json(json.dumps(bundle_json))
    root = TrustedRoot(RootModel.from_json(json.dumps(root_json)))
    with pytest.raises(VerificationError, match=message):
        _verify(root, bundle, dsse)
