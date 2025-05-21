import hashlib
import secrets

import pytest

from sigstore import dsse
from sigstore._internal.rekor.client_v2 import (
    DEFAULT_KEY_DETAILS,
    DEFAULT_REKOR_URL,
    STAGING_REKOR_URL,
    Certificate,
    Hashed,
    LogEntry,
    RekorV2Client,
    serialization,
    v2,
    v2_intoto,
)

# from sigstore.models import rekor_v1
from sigstore._utils import sha256_digest
from sigstore.sign import ec

ALPHA_REKOR_V2_URL = "https://log2025-alpha1.rekor.sigstage.dev"
LOCAL_REKOR_V2_URL = "http://localhost:3000"


# TODO: add staging and production URLs when available,
# and local after using scaffolding/setup-sigstore-env action
@pytest.fixture(
    params=[
        ALPHA_REKOR_V2_URL,
        pytest.param(STAGING_REKOR_URL, marks=pytest.mark.xfail),
        pytest.param(DEFAULT_REKOR_URL, marks=pytest.mark.xfail),
        pytest.param(LOCAL_REKOR_V2_URL, marks=pytest.mark.xfail),
    ]
)
def client(request) -> RekorV2Client:
    """
    Returns a RekorV2Client. This fixture is paramaterized to return clients with various URLs.
    Test fuctions that consume this fixture will run once for each URL.
    """
    return RekorV2Client(base_url=request.param)


@pytest.fixture()
def sample_hashed_rekord_request_materials(
    staging,
) -> tuple[Hashed, bytes, Certificate]:
    """
    Creates materials needed for `RekorV2Client._build_hashed_rekord_create_entry_request`.
    """
    sign_ctx_cls, _, id_token = staging
    with sign_ctx_cls().signer(id_token) as signer:
        cert = signer._signing_cert()

    hashed_input = sha256_digest(secrets.token_bytes(32))
    signature = signer._private_key.sign(
        hashed_input.digest, ec.ECDSA(hashed_input._as_prehashed())
    )
    return hashed_input, signature, cert


@pytest.fixture()
def sample_hashed_rekord_create_entry_request(
    sample_hashed_rekord_request_materials,
) -> v2.CreateEntryRequest:
    """
    Returns a sample `CreateEntryRequest` for for hashedrekor.
    """
    hashed_input, signature, cert = sample_hashed_rekord_request_materials
    return RekorV2Client._build_hashed_rekord_create_entry_request(
        artifact_hashed_input=hashed_input,
        artifact_signature=signature,
        signining_certificate=cert,
    )


@pytest.fixture()
def sample_dsse_create_entry_request(
    sample_dsse_request_materials,
) -> v2.CreateEntryRequest:
    """
    Returns a sample `CreateEntryRequest` for for dsse.
    """
    envelope, cert = sample_dsse_request_materials
    return RekorV2Client._build_dsse_create_entry_request(
        envelope=envelope, signing_certificate=cert
    )


@pytest.fixture(
    params=[
        sample_hashed_rekord_create_entry_request,
        sample_dsse_create_entry_request,
    ]
)
def sample_create_entry_request(request) -> v2.CreateEntryRequest:
    """
    Returns a sample `CreateEntryRequest`, for each of the the params in the supplied fixture.
    """
    return request.getfixturevalue(request.param.__name__)


@pytest.fixture()
def sample_dsse_request_materials(staging) -> tuple[dsse.Envelope, Certificate]:
    """
    Creates materials needed for `RekorV2Client._build_dsse_create_entry_request`.
    """
    sign_ctx_cls, _, id_token = staging
    with sign_ctx_cls().signer(id_token) as signer:
        cert = signer._signing_cert()
    stmt = (
        dsse.StatementBuilder()
        .subjects(
            [
                dsse.Subject(
                    name="null", digest={"sha256": hashlib.sha256(b"").hexdigest()}
                )
            ]
        )
        .predicate_type("https://cosign.sigstore.dev/attestation/v1")
        .predicate(
            {
                "Data": "",
                "Timestamp": "2023-12-07T00:37:58Z",
            }
        )
    ).build()
    envelope = dsse._sign(key=signer._private_key, stmt=stmt)
    return envelope, cert


@pytest.mark.ambient_oidc
def test_build_hashed_rekord_create_entry_request(
    sample_hashed_rekord_request_materials,
):
    """
    Ensures that we produce the request `CreateEntryRequest` correctly for hashedrekords.
    """
    hashed_input, signature, cert = sample_hashed_rekord_request_materials
    expected_request = v2.CreateEntryRequest(
        hashed_rekord_request_v0_0_2=v2.HashedRekordRequestV002(
            digest=hashed_input.digest,
            signature=v2.Signature(
                content=signature,
                verifier=v2.Verifier(
                    public_key=v2.PublicKey(
                        raw_bytes=cert.public_key().public_bytes(
                            encoding=serialization.Encoding.DER,
                            format=serialization.PublicFormat.SubjectPublicKeyInfo,
                        )
                    ),
                    key_details=DEFAULT_KEY_DETAILS,
                ),
            ),
        )
    )
    actual_request = RekorV2Client._build_hashed_rekord_create_entry_request(
        artifact_hashed_input=hashed_input,
        artifact_signature=signature,
        signining_certificate=cert,
    )
    assert expected_request == actual_request


@pytest.mark.ambient_oidc
def test_build_dsse_create_entry_request(sample_dsse_request_materials):
    """
    Ensures that we produce the request `CreateEntryRequest` correctly for dsses.
    """
    envelope, cert = sample_dsse_request_materials
    expected_request = v2.CreateEntryRequest(
        dsse_request_v0_0_2=v2.DsseRequestV002(
            envelope=v2_intoto.Envelope(
                payload=envelope._inner.payload,
                payload_type=envelope._inner.payload_type,
                signatures=[
                    v2_intoto.Signature(
                        keyid=signature.keyid,
                        sig=signature.sig,
                    )
                    for signature in envelope._inner.signatures
                ],
            ),
            verifiers=[
                v2.Verifier(
                    public_key=v2.PublicKey(
                        raw_bytes=cert.public_key().public_bytes(
                            encoding=serialization.Encoding.DER,
                            format=serialization.PublicFormat.SubjectPublicKeyInfo,
                        )
                    ),
                    key_details=DEFAULT_KEY_DETAILS,
                )
            ],
        )
    )
    actual_request = RekorV2Client._build_dsse_create_entry_request(
        envelope=envelope, signing_certificate=cert
    )
    assert expected_request == actual_request


@pytest.mark.ambient_oidc
def test_create_entry(sample_create_entry_request, client):
    """
    Sends a request to RekorV2 and ensure's the response is parseable to a `LogEntry` and a `TransparencyLogEntry`.
    """
    log_entry = client.create_entry(sample_create_entry_request)
    assert isinstance(log_entry, LogEntry)
    # TODO: Pending https://github.com/sigstore/sigstore-python/pull/1370
    # assert isinstance(log_entry._to_rekor(), rekor_v1.TransparencyLogEntry)
