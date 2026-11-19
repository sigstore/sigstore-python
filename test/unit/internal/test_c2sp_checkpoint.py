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
import hashlib
import struct
from typing import cast

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, mldsa, padding, rsa

from sigstore._internal.c2sp.checkpoint import (
    Checkpoint,
    NoteVerifier,
    SignedCheckpoint,
    compute_note_key_id,
    format_cosignature_v1_message,
    format_subtree_v1_message,
    is_valid_note_name,
)
from sigstore._utils import KeyID, PublicKey, load_der_public_key
from sigstore.errors import VerificationError

# Test keys from rekor-tiles/pkg/note/note_test.go
_ED25519_PRIV_PEM = b"""-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIGuZ8UWTFmXi/26ZgF4VYL8HfLSuW12TN5XMFQRt1Loc
-----END PRIVATE KEY-----
"""

_ECDSA_PRIV_PEM = b"""-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIOMZNOBbRU3CHBjZoc13R8HYNUoqsvce5UlOmRzlOZqUoAoGCCqGSM49
AwEHoUQDQgAEeLw7gX40qy1z7JUhGMAaaDITbV7p2D+C5G9xPEsy/PVAo9H0mgS4
NYzpGirkXxBht+IvvL19WR1X9ANXha5ldQ==
-----END EC PRIVATE KEY-----
"""

_RSA_PRIV_PEM = b"""-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCzuJ5Nonw8CTMK
Sz765sM1bg1ziGLv78lSZK+qrqkhYB+MatVcj9npE5Q6c2C+ORbqk4/8qQ7VhB+4
u0/zpfksPjdoix8f/dVDQvxfhbrjH8mCYD1NZBr7Dg55doV0bD6UScbLauUAveQh
if8EBuagBmHJZdAWQ9iDq+XKk3QfqpAfyFy3RJefvLpxqwiTsYHtNC3/46qSRDnm
iMz3VxdSrphiy8CMGNDAS8YZeou/A6G1sP54xzZ+nDsaUCCKJCmriSHNau25knQd
38EVk2kcf5QB11Dgm+/t1tcOKdq9XMRu8myxAA32cHf1Q8elRCf2aiMC6H+qD68M
3IQfeWIhAgMBAAECggEAALYAAFAefDFQH6ANE3qCtq0lBfo54/eXnQkTbdIrjpt9
/HT2u5tBEiw256VJsm7w4YQsa2Qy0BLp+jXZet4C9pMXboUwXhTHuXCkJW+WvevE
BQ1C6NG2zpvvYDkhDYUZGUaSb/8QAVj+9EgCt34cfvEPhXeu40uo6VpuegbrzG1D
Wr5Ad2JhQi8LZMCqlRBLvBSRPaMHv6KpkII6pPJyeVa99tVk2ivLBsoIPOLmi7i8
GDcedUXJY1r8AArH4ahxPM1QQF/CVxd4zxUUETb5LQ4XwZKxm6y7LMThv6scWFBD
+ey/GUS+u3krpGaBW2AoxS8ubYr5mjvCr0Gg24oZ/QKBgQDX4XUaQE+7RwcUnEVx
KPJj+gsrbsST82KUAR1EB/3XVK2HQweSYk14feQvo1VJL0uAc58BtZwi30IKHBNr
EUvGCee/6CxsvsHYrn4ukvVo4sx1DdjH83ByaACMjLJKDySarBuNcH+L0VCbw699
7n6MaBk+u6QJOmOhJRmtn7HjRQKBgQDVHt5I/uJznMrNSR4p1AgkPmcmaF4m/z9C
fLSz9mra/QzdNSMKTbF5wH7ENlFE6M7GtSVRi2G44eKaoCaQ/xFFhPGPoJrd8tqU
eCH65FYGH0Q3uQryOJ9rQSb/p9697orS7Fb46UQGfxRj5mLoUcmpComPYccod7UF
vfqEX7ojLQKBgQCcWCz96QuVXxhSpeZo0LXTEBicyOjXGZIQDEqMpZkCJNJTvoiy
TD09ATeMBKdUjEsK6TGEBGnim3vxZGnvxaPx9eSACH579x7edWjvBAF1h6N5NqEE
FlsekBGtuIu6tQLWfcSqh4nn0ZymYm8rLdk6iH2YAD8Ja98RqpPROXGUXQKBgHSy
uGkkGH/SBUKvnPKuhd7CxNzFHXkhH1Sa0KASeKR9GAQwyoUj0eCnRULPs2SWTlOE
cXDbb6E7H0goFbYj1SNKDrPk76hFCOdveLvXODuV91bD3niQBMtIG8C1/UPnUOD6
RQ17PaKJB3NEfjhUQKZtfLGkitdf5SHFy12cxWHpAoGAHV6Smruaku5GTLmftp7x
D0+b3FrkQeBT3OFpUVtp0iSixhoBA2YHSofC/SAnqoY7Hw23VUtWHfhPdVowNa2T
cvxSmCAcfkrJHKF1remfUOtN6Ncu9Dyr/rieoxFDqz31lezTAx3T6lLfgtspxplR
fycQ0e/nw1JkypGoL1j4cwM=
-----END PRIVATE KEY-----
"""

_MLDSA_PRIV_PEM = b"""-----BEGIN PRIVATE KEY-----
MDQCAQAwCwYJYIZIAWUDBAMRBCKAII9qENVch/5+4uTrzma75jN+rTCu6Gt6fDSc
WEjtQxH8
-----END PRIVATE KEY-----
"""

# Live staging ML-DSA-44 log public key from v2-root-signing-staging
_STAGING_PQC_ORIGIN = "pqc27-a1.us-east4.rekor.sigstage.dev"
_STAGING_PQC_SPKI_B64 = (
    "MIIFMjALBglghkgBZQMEAxEDggUhAIV6yId5G0DGEajPkfNkL25be3pgRFX6Aog6KXL+XTIaD7LUmvKE"
    "diFLvqsxK0ZNhw/bSttAViccB3osGWmUcrNuJ4Dn8JQ76+AaMWG88igmXIk0qaXhOl4qn0bOXK13Mbs+"
    "d2N0oinX1821uBmNSopQtWkGrQS0OaTFUZjJ3i6Ge9SFK4oIFK/DlcnYFuoMiyyUx5YYeS6IdJG/En65"
    "fXYfUtk9CSgusgXsEhZGXII05u2XEwEa7RGi9vtaBqZqiFFbL73NGpdKaf4+veIoh265WTQynstqJHGR"
    "EUaE1YZJQXHmBJGPcpn5pGQayQyiv6HsODcrBxHClXidIzZYDz0FRKr8+qaYnGz+GFgWLst0zRrYFpgH"
    "I/94Xm4tle7PRsmwDDmdV79pTwGhwO0A88Y7fpbd3eTgk75yMPQcoPSNXU2RJhsGsdiP6jjhy40PgayT"
    "WwzTHE5jCJUMYTUHJ/oUnxO3mj09ZxwIv01m6kOINX4zb2bGgidcfIWXtvdW1Oq9KB3YIxIGghqjyMQG"
    "HkSNK3W4iUQd/kSz9VkCfsVW65fzDSLS0XhBsFZf0JasyZ9EsmGp81wD9bMu3M+2UK015fpiN1yCi+B4"
    "O4ltUfQeZnl5tO44DsuF9O4nZBAY/7F4e8duFLrnClLfKN/arm6/+4VaUSZMuAl5HokSH3tdqDVDiKZR"
    "NJJAPhRSzX+Y6N4g52gWo2Q9/tXYc2MBICuC3ufwP7qzoAX/1iIwu/06EXrpFu9udX1Dw8YdQfEhSVWI"
    "JXvY64xH+NkJmt8dxK3PrnZF8jE7iVf3HWBb4FaTMBeCVgLYdbjqvYC+ZPCnhLDyNqm+I4LhjDd9y29I"
    "ION9jw/Yz3IhgDGo8exXVllKZHlhMmMrbWDr23oeGpGze8ATBB7pWxO2Gc30qMi5njwGI8h8BbSGvzz2"
    "1+u/tVxyY8pNoqF1BIbhz5K//iEKMLZaQexojfFhz0uatBGlBcX+9KnT7M7bTRKjjZ8iYD58V0dx+Vx+"
    "zmGkd6RHrjGUzAXLArxEfnhKWozTBOUq4IrpXuT+ROlsCvMGs+07CnVDb8LqCNqz9gmEu0scq6WiY3wo"
    "V4PC8ZuC88mkUXrqF4yENTuOs+ppA7hkHVRnalT6UqCzfO+h/NhTUVS7Bo1Clz7lMNZyEks7rv46L9E7"
    "gMVivq43AYm722WgMNAEtP1y6kL5adEJiYUw81wdWn2C9GAHacXWpFGyh4PZeUjrseMQo9WRbgmq/qCv"
    "FkpgTSIDjewBJvwOt8Gb3WrBjUxJut1MN0QKw+IMLahrPj8fbdbEWdO+rc29ihxYbaiU8kr8wm8NV7kP"
    "RF8/fl1vkRfDun/GXhW9zZ7C3wVODObH8N226sV5qjSWR8+THCr4COucB914F3OAaEe1W8EcSisezdff"
    "f7yOAW4rq/pb8i1a6pyzKzR5RKwZPbwQugZYEUxPpq//xDWreMLYxvkeFtRoaVb0F9e/ulHuO1r08Myo"
    "Sr0RGCJQVqElvaxErrljJwcRmsH2nQoMOeQMiNA8Jx8Ct96hrTpHHw70A0vDDfSl3Ve0HJIMzORJFTnw"
    "LXD9nQka1QwFdKkSaGMOfKj8refzGnS7IAQJiu3R0B9/KRkk+7jZI9c6nqjID3Op0Mw14j9KVHhHGQm/"
    "JA2twoYF+FMeSHA6k9F4t+Tq3xvK8Y3cTBXSHjEuszUBvKFAdM0H6X5dCwJcfzI5ywVxOOMDfEbJ+xv5"
    "YFuPVFSDBePa05v8lcw="
)
_STAGING_PQC_KEY_ID_B64 = "yamUXBf/d5QJ2jHB8HmHqxX+zHV201aClKtJnFuN5/0="


def _format_sig_line(name: str, key_hint: bytes, raw_sig: bytes) -> str:
    b64 = base64.b64encode(key_hint + raw_sig).decode("ascii")
    return f"— {name} {b64}\n"


@pytest.mark.parametrize(
    ("priv_pem", "expected_uint32", "expected_log_id_hex"),
    [
        (
            _ED25519_PRIV_PEM,
            3839787747,
            "e4de82e34c8c270d87612a3d6a1e297e2cd0ed9cb89ea7aeec8ce4d0b54e6775",
        ),
        (
            _ECDSA_PRIV_PEM,
            2408765216,
            "8f92d720f56c219e34895a76a636a3353ddbf7813f9fa317e19982eafa945328",
        ),
        (
            _RSA_PRIV_PEM,
            2918460683,
            "adf42d0b4478f2d07e5c8c3e63640a7e41b440c19dc47010c3a4936af75d85b6",
        ),
        (
            _MLDSA_PRIV_PEM,
            2079239679,
            "7beeadffbc4d8e7a62f9a444e789a6d472a7502a632523e163824dcda53a008b",
        ),
    ],
)
def test_compute_note_key_id_rekor_tiles_vectors(
    priv_pem: bytes, expected_uint32: int, expected_log_id_hex: str
) -> None:
    priv = serialization.load_pem_private_key(priv_pem, password=None)
    pub = cast(PublicKey, priv.public_key())

    key_id = compute_note_key_id("testkey", pub)
    assert key_id.hex() == expected_log_id_hex
    assert struct.unpack(">I", key_id[:4])[0] == expected_uint32


def test_compute_note_key_id_staging_pqc_trusted_root() -> None:
    pub = load_der_public_key(base64.b64decode(_STAGING_PQC_SPKI_B64))
    key_id = compute_note_key_id(_STAGING_PQC_ORIGIN, pub)
    assert key_id == base64.b64decode(_STAGING_PQC_KEY_ID_B64)


def test_verify_live_staging_mldsa44_checkpoint() -> None:
    # Real ML-DSA-44 checkpoint fetched from https://pqc27-a1.us-east4.rekor.sigstage.dev/api/v2/checkpoint
    # (independent rekor-tiles Go implementation interop vector).
    live_checkpoint = (
        "pqc27-a1.us-east4.rekor.sigstage.dev\n"
        "162993\n"
        "H0KbFE/8KsDRWTe6VulmGDPrbwfF4a0XJMYqxMIVd7M=\n"
        "\n"
        "— pqc27-a1.us-east4.rekor.sigstage.dev "
        "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\n"
    )
    pub = load_der_public_key(base64.b64decode(_STAGING_PQC_SPKI_B64))
    verifier = NoteVerifier.from_public_key(_STAGING_PQC_ORIGIN, pub)
    scp = SignedCheckpoint.from_text(live_checkpoint)
    assert scp.checkpoint.origin == _STAGING_PQC_ORIGIN
    assert scp.checkpoint.tree_size == 162993
    scp.verify([verifier])


def test_c2sp_signed_note_spec_example() -> None:
    # Full example (vkey + signed note) from https://c2sp.org/signed-note#example
    # vkey: example.com/foo+530d903a+AekyeRrm56hApGFkyQR4ZCbV54Id2LKaANYcrnKv3U2k
    vkey_payload = base64.b64decode("AekyeRrm56hApGFkyQR4ZCbV54Id2LKaANYcrnKv3U2k")
    assert vkey_payload[0] == 0x01
    pub = ed25519.Ed25519PublicKey.from_public_bytes(vkey_payload[1:])

    verifier = NoteVerifier.from_public_key("example.com/foo", pub)
    assert verifier.key_hint.hex() == "530d903a"

    sig_bytes = base64.b64decode(
        "Uw2QOkn8srV1yJGh2VYRlL1Tnagv1YEq6TfXppzi2ONncAlTgK7Ztg1ERYNZXsYjOBH3mFXmRKuwHjG1Yu72IneyaQM="
    )
    assert sig_bytes[:4] == verifier.key_hint
    dummy_cp = Checkpoint(origin="example.com/foo", tree_size=0, root_hash=b"\x00" * 32)
    verifier.verify_checkpoint_signature(
        dummy_cp, "This is an example message.\n", sig_bytes[4:]
    )


def test_c2sp_tlog_cosignature_ed25519_spec_example() -> None:
    # Verify Ed25519 cosignature (0x04) key ID calculation and spec example bytes
    # from https://c2sp.org/tlog-cosignature#ed25519
    priv = ed25519.Ed25519PrivateKey.generate()
    pub = priv.public_key()
    origin = "witness.example.com/w1"
    verifier = NoteVerifier.from_public_key(origin, pub, cosignature=True)

    expected_id = hashlib.sha256(
        origin.encode("utf-8")
        + b"\n\x04"
        + pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    ).digest()
    assert verifier.key_id == expected_id

    note_text = (
        "example.com/behind-the-sofa\n"
        "20852163\n"
        "CsUYapGGPo4dkMgIAUqom/Xajj7h2fB2MPA3j2jxq2I=\n"
    )
    assert format_cosignature_v1_message(1679315147, note_text) == (
        b"cosignature/v1\n"
        b"time 1679315147\n"
        b"example.com/behind-the-sofa\n"
        b"20852163\n"
        b"CsUYapGGPo4dkMgIAUqom/Xajj7h2fB2MPA3j2jxq2I=\n"
    )


def test_format_subtree_v1_byte_layout() -> None:
    # Independent byte-level test vector for CosignedSubtree in
    # https://c2sp.org/tlog-cosignature#ml-dsa-44
    root_hash = bytes(range(32))
    msg = format_subtree_v1_message(
        cosigner_name="witness.example",
        timestamp=0x0102030405060708,
        log_origin="log.example/v1",
        tree_size=0x1020304050607080,
        root_hash=root_hash,
    )
    expected = (
        b"subtree/v1\n\x00"
        + bytes([len(b"witness.example")])
        + b"witness.example"
        + b"\x01\x02\x03\x04\x05\x06\x07\x08"
        + bytes([len(b"log.example/v1")])
        + b"log.example/v1"
        + b"\x00\x00\x00\x00\x00\x00\x00\x00"
        + b"\x10\x20\x30\x40\x50\x60\x70\x80"
        + root_hash
    )
    assert msg == expected


@pytest.mark.parametrize(
    ("name", "valid"),
    [
        ("example.com/log", True),
        ("", False),
        ("example+log", False),
        ("example log", False),
        ("example\nlog", False),
        ("example\x00log", False),
    ],
)
def test_is_valid_note_name(name: str, valid: bool) -> None:
    assert is_valid_note_name(name) is valid


def test_compute_note_key_id_errors() -> None:
    pub = ed25519.Ed25519PrivateKey.generate().public_key()
    with pytest.raises(VerificationError, match="invalid key name"):
        compute_note_key_id("bad name", pub)

    with pytest.raises(VerificationError, match="invalid key name"):
        NoteVerifier.from_public_key("bad+name", pub)

    with pytest.raises(VerificationError, match="invalid key name length"):
        compute_note_key_id("a" * 256, pub)

    with pytest.raises(VerificationError, match="key_id must be at least 4 bytes"):
        NoteVerifier.from_public_key("example.com/log", pub, key_id=KeyID(b"\x01\x02"))

    # ML-DSA-65 and ML-DSA-87 are not defined for signature type 0x06
    for unsupported_mldsa in [
        mldsa.MLDSA65PrivateKey.generate().public_key(),
        mldsa.MLDSA87PrivateKey.generate().public_key(),
    ]:
        with pytest.raises(VerificationError, match="unsupported public key type"):
            compute_note_key_id("example.com/log", unsupported_mldsa)
        with pytest.raises(VerificationError, match="unsupported public key type"):
            NoteVerifier.from_public_key("example.com/log", unsupported_mldsa)

    # ECDSA and RSA do not support tlog-cosignature
    ec_pub = ec.generate_private_key(ec.SECP256R1()).public_key()
    with pytest.raises(VerificationError, match="ECDSA keys do not support"):
        compute_note_key_id("example.com/w", ec_pub, cosignature=True)
    with pytest.raises(VerificationError, match="ECDSA keys do not support"):
        NoteVerifier.from_public_key("example.com/w", ec_pub, cosignature=True)

    rsa_priv = cast(
        rsa.RSAPrivateKey,
        serialization.load_pem_private_key(_RSA_PRIV_PEM, password=None),
    )
    with pytest.raises(VerificationError, match="RSA keys do not support"):
        compute_note_key_id("example.com/w", rsa_priv.public_key(), cosignature=True)

    # Unsupported ECDSA curve fails fast at construction time
    secp256k1_pub = ec.generate_private_key(ec.SECP256K1()).public_key()
    with pytest.raises(VerificationError, match="unsupported ECDSA curve"):
        compute_note_key_id("example.com/log", secp256k1_pub)
    with pytest.raises(VerificationError, match="unsupported ECDSA curve"):
        NoteVerifier.from_public_key("example.com/log", secp256k1_pub)


def test_checkpoint_roundtrip_and_errors() -> None:
    root_hash = hashlib.sha256(b"root").digest()
    cp = Checkpoint(
        origin="example.com/log",
        tree_size=123,
        root_hash=root_hash,
        extension_lines=["ext1", "ext2"],
    )
    text = cp.to_text()
    parsed = Checkpoint.from_text(text)
    assert parsed == cp

    b64_root = base64.b64encode(root_hash).decode("ascii")
    non_canonical_root = "A" * 42 + "B="
    for bad_text, match in [
        (f"example.com/log\n123\n{b64_root}", "must end with a newline"),
        ("example.com/log\n123\n", "too few lines"),
        (f"\n123\n{b64_root}\n", "invalid origin"),
        (f"bad origin\n123\n{b64_root}\n", "invalid origin"),
        (f"bad+origin\n123\n{b64_root}\n", "invalid origin"),
        (f"{'a' * 256}\n123\n{b64_root}\n", "invalid origin length"),
        (f"example.com/log\n01\n{b64_root}\n", "invalid tree size"),
        (f"example.com/log\n{'1' * 5000}\n{b64_root}\n", "invalid tree size"),
        ("example.com/log\n123\n\n", "empty root hash"),
        ("example.com/log\n123\n!!!\n", "invalid base64 in root hash"),
        (
            f"example.com/log\n123\n{non_canonical_root}\n",
            "non-canonical base64 in root hash",
        ),
        (
            f"example.com/log\n123\n{base64.b64encode(b'short').decode()}\n",
            "root hash must be 32 bytes",
        ),
        (f"example.com/log\n123\n{b64_root}\n\n", "empty extension line"),
        (f"example.com/log\n123\n{b64_root}\next\x07line\n", "control characters"),
    ]:
        with pytest.raises(VerificationError, match=match):
            Checkpoint.from_text(bad_text)


def test_format_subtree_v1_and_cosignature_v1_errors() -> None:
    root_hash = hashlib.sha256(b"root").digest()

    with pytest.raises(VerificationError, match="invalid cosigner name"):
        format_subtree_v1_message(
            cosigner_name="",
            timestamp=1,
            log_origin="example.com",
            tree_size=1,
            root_hash=root_hash,
        )

    with pytest.raises(VerificationError, match="invalid cosigner name"):
        format_subtree_v1_message(
            cosigner_name="bad cosigner",
            timestamp=1,
            log_origin="example.com",
            tree_size=1,
            root_hash=root_hash,
        )

    with pytest.raises(VerificationError, match="invalid log origin length"):
        format_subtree_v1_message(
            cosigner_name="example.com",
            timestamp=1,
            log_origin="a" * 256,
            tree_size=1,
            root_hash=root_hash,
        )

    with pytest.raises(VerificationError, match="root_hash must be 32 bytes"):
        format_subtree_v1_message(
            cosigner_name="example.com",
            timestamp=1,
            log_origin="example.com",
            tree_size=1,
            root_hash=b"short",
        )

    with pytest.raises(VerificationError, match="invalid cosignature timestamp"):
        format_subtree_v1_message(
            cosigner_name="example.com",
            timestamp=1 << 63,
            log_origin="example.com",
            tree_size=1,
            root_hash=root_hash,
        )

    with pytest.raises(VerificationError, match="invalid subtree range"):
        format_subtree_v1_message(
            cosigner_name="example.com",
            timestamp=0,
            log_origin="example.com",
            tree_size=5,
            root_hash=root_hash,
            start=6,
        )

    with pytest.raises(VerificationError, match="invalid subtree range"):
        format_subtree_v1_message(
            cosigner_name="example.com",
            timestamp=1,
            log_origin="example.com",
            tree_size=1 << 64,
            root_hash=root_hash,
        )

    with pytest.raises(
        VerificationError, match="non-zero start must have zero timestamp"
    ):
        format_subtree_v1_message(
            cosigner_name="example.com",
            timestamp=100,
            log_origin="example.com",
            tree_size=5,
            root_hash=root_hash,
            start=2,
        )

    with pytest.raises(VerificationError, match="invalid cosignature timestamp"):
        format_cosignature_v1_message(-1, b"note")


def test_signed_checkpoint_mldsa_log_and_witnesses() -> None:
    log_origin = "pqc.rekor.example.com"
    root_hash = hashlib.sha256(b"test root hash").digest()
    cp = Checkpoint(origin=log_origin, tree_size=123, root_hash=root_hash)
    note_text = cp.to_text()

    # 1. Sign checkpoint with ML-DSA-44 log key (subtree/v1)
    log_priv = cast(
        mldsa.MLDSA44PrivateKey,
        serialization.load_pem_private_key(_MLDSA_PRIV_PEM, password=None),
    )
    log_verifier = NoteVerifier.from_public_key(log_origin, log_priv.public_key())
    ts_log = 1762260000
    log_msg = format_subtree_v1_message(
        cosigner_name=log_origin,
        timestamp=ts_log,
        log_origin=log_origin,
        tree_size=cp.tree_size,
        root_hash=cp.root_hash,
    )
    log_raw_sig = struct.pack(">Q", ts_log) + log_priv.sign(log_msg)

    # 2. Sign with ML-DSA-44 witness 1 (subtree/v1)
    w1_origin = "witness1.example.com"
    w1_priv = mldsa.MLDSA44PrivateKey.generate()
    w1_verifier = NoteVerifier.from_public_key(
        w1_origin, w1_priv.public_key(), cosignature=True
    )
    ts_w1 = 1762260005
    w1_msg = format_subtree_v1_message(
        cosigner_name=w1_origin,
        timestamp=ts_w1,
        log_origin=log_origin,
        tree_size=cp.tree_size,
        root_hash=cp.root_hash,
    )
    w1_raw_sig = struct.pack(">Q", ts_w1) + w1_priv.sign(w1_msg)

    # 3. Sign with Ed25519 witness 2 (cosignature/v1)
    w2_origin = "witness2.example.com"
    w2_priv = ed25519.Ed25519PrivateKey.generate()
    w2_verifier = NoteVerifier.from_public_key(
        w2_origin, w2_priv.public_key(), cosignature=True
    )
    ts_w2 = 1762260006
    w2_msg = format_cosignature_v1_message(ts_w2, note_text)
    w2_raw_sig = struct.pack(">Q", ts_w2) + w2_priv.sign(w2_msg)

    # 4. Include unknown signatures: completely unknown, same name / different
    # key_id, and different name / same key_id (all MUST be ignored per signed-note)
    unknown_sig_line = _format_sig_line(
        "unknown.example.com", b"\xaa\xbb\xcc\xdd", b"xyz"
    )
    same_name_diff_id = _format_sig_line(
        log_origin,
        bytes([log_verifier.key_hint[0] ^ 0xFF]) + log_verifier.key_hint[1:],
        b"ignored",
    )
    diff_name_same_id = _format_sig_line(
        "other-name.example.com", log_verifier.key_hint, b"ignored"
    )

    full_note = (
        note_text
        + "\n"
        + _format_sig_line(log_origin, log_verifier.key_hint, log_raw_sig)
        + unknown_sig_line
        + same_name_diff_id
        + diff_name_same_id
        + _format_sig_line(w1_origin, w1_verifier.key_hint, w1_raw_sig)
        + _format_sig_line(w2_origin, w2_verifier.key_hint, w2_raw_sig)
    )

    signed_cp = SignedCheckpoint.from_bytes(full_note.encode("utf-8"))
    assert signed_cp.checkpoint == cp
    assert len(signed_cp.signatures) == 6

    # Verify with log + 2 witnesses (including an unrelated log verifier that should be skipped)
    other_log_verifier = NoteVerifier.from_public_key(
        "other.log.example.com", log_priv.public_key()
    )
    signed_cp.verify(
        [other_log_verifier, log_verifier],
        witness_verifiers=[w1_verifier, w2_verifier],
        witness_threshold=2,
    )

    # Fails if threshold is 3
    with pytest.raises(VerificationError, match="witness quorum not met"):
        signed_cp.verify(
            [log_verifier],
            witness_verifiers=[w1_verifier, w2_verifier],
            witness_threshold=3,
        )

    # Multiple valid signatures from the same witness origin (e.g. during key
    # rotation) count as a single witness toward witness_threshold.
    w1_priv_rotated = mldsa.MLDSA44PrivateKey.generate()
    w1_verifier_rotated = NoteVerifier.from_public_key(
        w1_origin, w1_priv_rotated.public_key(), cosignature=True
    )
    w1_raw_sig_rotated = struct.pack(">Q", ts_w1) + w1_priv_rotated.sign(w1_msg)
    same_witness_note = (
        note_text
        + "\n"
        + _format_sig_line(log_origin, log_verifier.key_hint, log_raw_sig)
        + _format_sig_line(w1_origin, w1_verifier.key_hint, w1_raw_sig)
        + _format_sig_line(w1_origin, w1_verifier_rotated.key_hint, w1_raw_sig_rotated)
    )
    with pytest.raises(
        VerificationError, match="witness quorum not met: expected 2, got 1"
    ):
        SignedCheckpoint.from_text(same_witness_note).verify(
            [log_verifier],
            witness_verifiers=[w1_verifier, w1_verifier_rotated],
            witness_threshold=2,
        )


def test_extension_lines_mldsa44_ignored_ed25519_covered() -> None:
    # Per c2sp.org/tlog-checkpoint: ML-DSA-44 ignores extension lines while
    # Ed25519 cosignature/v1 covers them.
    log_origin = "pqc.rekor.example.com"
    root_hash = hashlib.sha256(b"root").digest()
    cp = Checkpoint(
        origin=log_origin,
        tree_size=42,
        root_hash=root_hash,
        extension_lines=["ext=original"],
    )
    note_text = cp.to_text()

    log_priv = mldsa.MLDSA44PrivateKey.generate()
    log_verifier = NoteVerifier.from_public_key(log_origin, log_priv.public_key())
    ts = 1762260000
    log_msg = format_subtree_v1_message(
        cosigner_name=log_origin,
        timestamp=ts,
        log_origin=log_origin,
        tree_size=cp.tree_size,
        root_hash=cp.root_hash,
    )
    log_sig_line = _format_sig_line(
        log_origin,
        log_verifier.key_hint,
        struct.pack(">Q", ts) + log_priv.sign(log_msg),
    )

    w_origin = "witness.example.com"
    w_priv = ed25519.Ed25519PrivateKey.generate()
    w_verifier = NoteVerifier.from_public_key(
        w_origin, w_priv.public_key(), cosignature=True
    )
    w_sig_line = _format_sig_line(
        w_origin,
        w_verifier.key_hint,
        struct.pack(">Q", ts)
        + w_priv.sign(format_cosignature_v1_message(ts, note_text)),
    )

    SignedCheckpoint.from_text(note_text + "\n" + log_sig_line + w_sig_line).verify(
        [log_verifier], witness_verifiers=[w_verifier], witness_threshold=1
    )

    # Tampering the extension line leaves ML-DSA-44 valid but breaks Ed25519 cosignature
    tampered_text = Checkpoint(
        origin=log_origin,
        tree_size=42,
        root_hash=root_hash,
        extension_lines=["ext=tampered"],
    ).to_text()
    SignedCheckpoint.from_text(tampered_text + "\n" + log_sig_line).verify(
        [log_verifier]
    )
    with pytest.raises(VerificationError, match="invalid witness cosignature"):
        SignedCheckpoint.from_text(
            tampered_text + "\n" + log_sig_line + w_sig_line
        ).verify([log_verifier], witness_verifiers=[w_verifier], witness_threshold=1)


@pytest.mark.parametrize("curve", [ec.SECP256R1(), ec.SECP384R1(), ec.SECP521R1()])
def test_signed_checkpoint_ecdsa_curves(curve: ec.EllipticCurve) -> None:
    origin = "ecdsa.log.example.com"
    cp = Checkpoint(
        origin=origin,
        tree_size=10,
        root_hash=hashlib.sha256(b"root").digest(),
    )
    note_text = cp.to_text()

    priv = ec.generate_private_key(curve)
    verifier = NoteVerifier.from_public_key(origin, priv.public_key())

    hash_alg: hashes.HashAlgorithm
    if isinstance(curve, ec.SECP256R1):
        hash_alg = hashes.SHA256()
    elif isinstance(curve, ec.SECP384R1):
        hash_alg = hashes.SHA384()
    else:
        hash_alg = hashes.SHA512()

    raw_sig = priv.sign(note_text.encode("utf-8"), ec.ECDSA(hash_alg))
    full_note = note_text + "\n" + _format_sig_line(origin, verifier.key_hint, raw_sig)

    signed_cp = SignedCheckpoint.from_text(full_note)
    signed_cp.verify([verifier])

    # Tampered signature fails
    bad_note = (
        note_text + "\n" + _format_sig_line(origin, verifier.key_hint, b"bad-sig")
    )
    with pytest.raises(VerificationError, match="invalid log signature"):
        SignedCheckpoint.from_text(bad_note).verify([verifier])


def test_signed_checkpoint_ed25519_and_rsa_logs() -> None:
    origin = "log.example.com"
    cp = Checkpoint(
        origin=origin,
        tree_size=10,
        root_hash=hashlib.sha256(b"root").digest(),
    )
    note_text = cp.to_text()

    # Ed25519 log (0x01)
    ed_priv = ed25519.Ed25519PrivateKey.generate()
    ed_verifier = NoteVerifier.from_public_key(origin, ed_priv.public_key())
    ed_sig = ed_priv.sign(note_text.encode("utf-8"))
    ed_note = note_text + "\n" + _format_sig_line(origin, ed_verifier.key_hint, ed_sig)
    SignedCheckpoint.from_text(ed_note).verify([ed_verifier])

    # RSA log
    rsa_priv = cast(
        rsa.RSAPrivateKey,
        serialization.load_pem_private_key(_RSA_PRIV_PEM, password=None),
    )
    rsa_verifier = NoteVerifier.from_public_key(origin, rsa_priv.public_key())
    rsa_sig = rsa_priv.sign(
        note_text.encode("utf-8"), padding.PKCS1v15(), hashes.SHA256()
    )
    rsa_note = (
        note_text + "\n" + _format_sig_line(origin, rsa_verifier.key_hint, rsa_sig)
    )
    SignedCheckpoint.from_text(rsa_note).verify([rsa_verifier])

    # Invalid RSA signature fails
    bad_rsa_note = (
        note_text + "\n" + _format_sig_line(origin, rsa_verifier.key_hint, b"bad-rsa")
    )
    with pytest.raises(VerificationError, match="invalid log signature"):
        SignedCheckpoint.from_text(bad_rsa_note).verify([rsa_verifier])


def test_note_verifier_signature_errors() -> None:
    origin = "log.example.com"
    cp = Checkpoint(
        origin=origin,
        tree_size=10,
        root_hash=hashlib.sha256(b"root").digest(),
    )
    note_text = cp.to_text()

    # ML-DSA-44 wrong length, zero timestamp (subtree vs checkpoint), and invalid signature
    mldsa_priv = mldsa.MLDSA44PrivateKey.generate()
    mldsa_verifier = NoteVerifier.from_public_key(origin, mldsa_priv.public_key())
    with pytest.raises(VerificationError, match="invalid ML-DSA-44 signature length"):
        mldsa_verifier.verify_checkpoint_signature(cp, note_text, b"short")

    # Subtree cosignature (timestamp == 0) must be rejected as a checkpoint cosignature
    subtree_msg = format_subtree_v1_message(
        cosigner_name=origin,
        timestamp=0,
        log_origin=origin,
        tree_size=cp.tree_size,
        root_hash=cp.root_hash,
    )
    subtree_sig = struct.pack(">Q", 0) + mldsa_priv.sign(subtree_msg)
    with pytest.raises(
        VerificationError,
        match="ML-DSA-44 checkpoint cosignature timestamp must not be zero",
    ):
        mldsa_verifier.verify_checkpoint_signature(cp, note_text, subtree_sig)

    with pytest.raises(VerificationError, match="invalid ML-DSA-44 signature for"):
        mldsa_verifier.verify_checkpoint_signature(
            cp, note_text, struct.pack(">Q", 100) + b"\x00" * 2420
        )

    # Ed25519 cosignature wrong length, zero timestamp, and invalid signature
    ed_priv = ed25519.Ed25519PrivateKey.generate()
    ed_cosig_verifier = NoteVerifier.from_public_key(
        origin, ed_priv.public_key(), cosignature=True
    )
    with pytest.raises(VerificationError, match="invalid Ed25519 cosignature length"):
        ed_cosig_verifier.verify_checkpoint_signature(cp, note_text, b"short")

    with pytest.raises(
        VerificationError, match="Ed25519 cosignature timestamp must not be zero"
    ):
        ed_cosig_verifier.verify_checkpoint_signature(
            cp, note_text, struct.pack(">Q", 0) + b"\x00" * 64
        )

    with pytest.raises(VerificationError, match="invalid Ed25519 signature for"):
        ed_cosig_verifier.verify_checkpoint_signature(
            cp, note_text, struct.pack(">Q", 100) + b"\x00" * 64
        )

    # Ed25519 log signature wrong length
    ed_log_verifier = NoteVerifier.from_public_key(origin, ed_priv.public_key())
    with pytest.raises(VerificationError, match="invalid Ed25519 signature length"):
        ed_log_verifier.verify_checkpoint_signature(cp, note_text, b"short")


def test_signed_checkpoint_parsing_and_verification_errors() -> None:
    root_hash_b64 = base64.b64encode(hashlib.sha256(b"root").digest()).decode("ascii")
    valid_header = f"example.com/log\n10\n{root_hash_b64}\n"
    valid_sig_b64 = base64.b64encode(b"\x01\x02\x03\x04\x05").decode("ascii")
    # Non-canonical base64 for 5 bytes (40 bits -> 7 chars = 42 bits + '='; bit 0 set in 7th char)
    non_canonical_sig_b64 = "AQIDBAU="[0:6] + "V="
    many_sigs = "".join(
        _format_sig_line(f"s{i}.example.com", struct.pack(">I", i), b"\x00")
        for i in range(65)
    )

    with pytest.raises(VerificationError, match="not valid UTF-8"):
        SignedCheckpoint.from_bytes(b"\xff\xfe")

    for bad_note, match in [
        (
            f"{valid_header}\r\n— example.com/log {valid_sig_b64}\n",
            "control characters",
        ),
        (valid_header, "must contain a blank line"),
        (f"{valid_header}\n", "at least one signature"),
        (
            f"{valid_header}\n— example.com/log {valid_sig_b64}",
            "must end with a newline",
        ),
        (f"{valid_header}\n{many_sigs}", "too many signature lines"),
        (
            f"{valid_header}\n-- example.com/log {valid_sig_b64}\n",
            "missing em dash prefix",
        ),
        (
            f"{valid_header}\n— example.com/log extra {valid_sig_b64}\n",
            "expected '<name> <base64>'",
        ),
        (
            f"{valid_header}\n— bad+name {valid_sig_b64}\n",
            "invalid signature line name",
        ),
        (
            f"{valid_header}\n— example.com/log !!!\n",
            "invalid base64 in signature line",
        ),
        (
            f"{valid_header}\n— example.com/log {non_canonical_sig_b64}\n",
            "non-canonical base64 in signature line",
        ),
        (
            f"{valid_header}\n— example.com/log {base64.b64encode(b'1234').decode()}\n",
            "too few bytes",
        ),
        (
            f"{valid_header}\n— example.com/log {valid_sig_b64}\n— example.com/log {valid_sig_b64}\n",
            "duplicate signature line",
        ),
    ]:
        with pytest.raises(VerificationError, match=match):
            SignedCheckpoint.from_text(bad_note)

    signed_cp = SignedCheckpoint.from_text(
        f"{valid_header}\n— example.com/log {valid_sig_b64}\n"
    )
    with pytest.raises(VerificationError, match="invalid witness_threshold"):
        signed_cp.verify([], witness_threshold=-1)

    with pytest.raises(VerificationError, match="no valid log signature found"):
        signed_cp.verify([])

    # Non-cosignature witness verifiers (Ed25519 0x01, ECDSA, RSA) are rejected
    ed_witness_pub = ed25519.Ed25519PrivateKey.generate().public_key()
    bad_ed_witness = NoteVerifier.from_public_key("witness.example", ed_witness_pub)
    ec_witness_pub = ec.generate_private_key(ec.SECP256R1()).public_key()
    bad_ec_witness = NoteVerifier.from_public_key("witness.example", ec_witness_pub)
    rsa_witness_priv = cast(
        rsa.RSAPrivateKey,
        serialization.load_pem_private_key(_RSA_PRIV_PEM, password=None),
    )
    bad_rsa_witness = NoteVerifier.from_public_key(
        "witness.example", rsa_witness_priv.public_key()
    )
    for bad_witness in [bad_ed_witness, bad_ec_witness, bad_rsa_witness]:
        with pytest.raises(
            VerificationError,
            match="must be ML-DSA-44 or Ed25519 with cosignature=True",
        ):
            signed_cp.verify([], witness_verifiers=[bad_witness])

    # A log key also listed in witness_verifiers must NOT count as its own witness
    self_log_priv = mldsa.MLDSA44PrivateKey.generate()
    self_log_verifier = NoteVerifier.from_public_key(
        "example.com/log", self_log_priv.public_key()
    )
    ts = 1762260000
    self_msg = format_subtree_v1_message(
        cosigner_name="example.com/log",
        timestamp=ts,
        log_origin="example.com/log",
        tree_size=10,
        root_hash=hashlib.sha256(b"root").digest(),
    )
    self_signed_note = (
        valid_header
        + "\n"
        + _format_sig_line(
            "example.com/log",
            self_log_verifier.key_hint,
            struct.pack(">Q", ts) + self_log_priv.sign(self_msg),
        )
    )
    with pytest.raises(
        VerificationError, match="witness quorum not met: expected 1, got 0"
    ):
        SignedCheckpoint.from_text(self_signed_note).verify(
            [self_log_verifier],
            witness_verifiers=[self_log_verifier],
            witness_threshold=1,
        )

    # Known witness with invalid signature fails closed and chains root cause
    w_pub = ed25519.Ed25519PrivateKey.generate().public_key()
    w_verifier = NoteVerifier(
        origin="witness.example.com",
        public_key=w_pub,
        key_id=KeyID(b"\x01\x02\x03\x04" + b"\x00" * 28),
        cosignature=True,
    )
    log_priv = ed25519.Ed25519PrivateKey.generate()
    log_verifier = NoteVerifier.from_public_key(
        "example.com/log", log_priv.public_key()
    )
    log_sig = log_priv.sign(valid_header.encode("utf-8"))
    note_with_bad_witness = (
        valid_header
        + "\n"
        + _format_sig_line("example.com/log", log_verifier.key_hint, log_sig)
        + f"— witness.example.com {valid_sig_b64}\n"
    )
    with pytest.raises(
        VerificationError, match="invalid witness cosignature"
    ) as exc_info:
        SignedCheckpoint.from_text(note_with_bad_witness).verify(
            [log_verifier], witness_verifiers=[w_verifier]
        )
    assert isinstance(exc_info.value.__cause__, VerificationError)
