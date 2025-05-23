import hashlib
import secrets

import pytest

from sigstore import dsse
from sigstore._internal.rekor.client import DEFAULT_REKOR_URL, STAGING_REKOR_URL
from sigstore._internal.rekor.client_v2 import (
    DEFAULT_KEY_DETAILS,
    Certificate,
    Hashed,
    LogEntry,
    RekorV2Client,
    common_v1,
    serialization,
    v2,
    v2_intoto,
)
from sigstore._utils import sha256_digest
from sigstore.models import rekor_v1
from sigstore.sign import ec

ALPHA_REKOR_V2_URL = "https://log2025-alpha1.rekor.sigstage.dev"
LOCAL_REKOR_V2_URL = "http://localhost:3000"


# TODO: add staging and production URLs when available,
# and local after using scaffolding/setup-sigstore-env action
@pytest.fixture(
    scope="session",
    params=[
        ALPHA_REKOR_V2_URL,
        pytest.param(STAGING_REKOR_URL, marks=pytest.mark.xfail),
        pytest.param(DEFAULT_REKOR_URL, marks=pytest.mark.skip),
        pytest.param(LOCAL_REKOR_V2_URL, marks=pytest.mark.skip),
    ],
)
def client(request) -> RekorV2Client:
    """
    Returns a RekorV2Client. This fixture is paramaterized to return clients with various URLs.
    Test fuctions that consume this fixture will run once for each URL.
    """
    return RekorV2Client(base_url=request.param)


@pytest.fixture(scope="session")
def sample_cert_and_private_key(
    staging_signer_verifier_token,
) -> tuple[Certificate, ec.EllipticCurvePrivateKey]:
    """
    Returns a sample Certificate and ec.EllipticCurvePrivateKey.
    """
    sign_ctx_cls, _, identity = staging_signer_verifier_token
    with sign_ctx_cls().signer(identity) as signer:
        return signer._signing_cert(), signer._private_key


@pytest.fixture(scope="session")
def sample_hashed_rekord_request_materials(
    sample_cert_and_private_key,
) -> tuple[Hashed, bytes, Certificate]:
    """
    Creates materials needed for `RekorV2Client._build_hashed_rekord_create_entry_request`.
    """
    cert, private_key = sample_cert_and_private_key
    hashed_input = sha256_digest(secrets.token_bytes(32))
    signature = private_key.sign(
        hashed_input.digest, ec.ECDSA(hashed_input._as_prehashed())
    )
    return hashed_input, signature, cert


@pytest.fixture(scope="session")
def sample_dsse_request_materials(
    sample_cert_and_private_key,
) -> tuple[dsse.Envelope, Certificate]:
    """
    Creates materials needed for `RekorV2Client._build_dsse_create_entry_request`.
    """
    cert, private_key = sample_cert_and_private_key
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
    envelope = dsse._sign(key=private_key, stmt=stmt)
    return envelope, cert


@pytest.fixture(scope="session")
def sample_hashed_rekord_create_entry_request(
    sample_hashed_rekord_request_materials,
) -> v2.CreateEntryRequest:
    """
    Returns a sample `CreateEntryRequest` for for hashedrekor.
    """
    hashed_input, signature, cert = sample_hashed_rekord_request_materials
    return RekorV2Client._build_hashed_rekord_request(
        hashed_input=hashed_input,
        signature=signature,
        certificate=cert,
    )


@pytest.fixture(scope="session")
def sample_dsse_create_entry_request(
    sample_dsse_request_materials,
) -> v2.CreateEntryRequest:
    """
    Returns a sample `CreateEntryRequest` for for dsse.
    """
    envelope, cert = sample_dsse_request_materials
    return RekorV2Client._build_dsse_request(envelope=envelope, certificate=cert)


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
                    x509_certificate=common_v1.X509Certificate(
                        raw_bytes=cert.public_bytes(encoding=serialization.Encoding.DER)
                    ),
                    key_details=DEFAULT_KEY_DETAILS,
                ),
            ),
        )
    )
    actual_request = RekorV2Client._build_hashed_rekord_request(
        hashed_input=hashed_input,
        signature=signature,
        certificate=cert,
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
                    x509_certificate=common_v1.X509Certificate(
                        raw_bytes=cert.public_bytes(encoding=serialization.Encoding.DER)
                    ),
                    key_details=DEFAULT_KEY_DETAILS,
                )
            ],
        )
    )
    actual_request = RekorV2Client._build_dsse_request(
        envelope=envelope, certificate=cert
    )
    assert expected_request == actual_request


@pytest.mark.parametrize(
    "sample_create_entry_request",
    [
        sample_hashed_rekord_create_entry_request.__name__,
        sample_dsse_create_entry_request.__name__,
    ],
)
@pytest.mark.ambient_oidc
def test_create_entry(
    request: pytest.FixtureRequest,
    sample_create_entry_request: str,
    client: RekorV2Client,
):
    """
    Sends a request to RekorV2 and ensure's the response is parseable to a `LogEntry` and a `TransparencyLogEntry`.
    """
    log_entry = client.create_entry(
        request.getfixturevalue(sample_create_entry_request)
    )
    assert isinstance(log_entry, LogEntry)
    assert isinstance(log_entry._to_rekor(), rekor_v1.TransparencyLogEntry)
