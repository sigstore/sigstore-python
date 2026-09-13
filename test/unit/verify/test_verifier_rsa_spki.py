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

"""Replay public-only PSS-subject fixtures without new certificate-builder APIs."""

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509.oid import PublicKeyAlgorithmOID

from sigstore._internal.key_details import _get_key_details
from sigstore._internal.sct import verify_sct
from sigstore._internal.trust import KeyringPurpose
from sigstore.errors import VerificationError
from sigstore.models import Bundle, TrustedRoot
from sigstore.verify import Verifier
from sigstore.verify.policy import Identity


@pytest.fixture(params=["artifact", "dsse"])
def pss_subject_bundle(asset, request):
    bundle = Bundle.from_json(
        asset(f"rsa-pss-spki/{request.param}.sigstore.json").read_bytes()
    )
    root = TrustedRoot.from_file(str(asset("rsa-pss-spki/trusted-root.json")))
    policy = Identity(
        identity="rsa-test@example.com", issuer="https://issuer.example.com"
    )
    artifact = asset("rsa-pss-spki/artifact.txt").read_bytes()
    return request.param, bundle, root, policy, artifact


def test_pss_subject_fixture_has_valid_signatures(pss_subject_bundle):
    """The negative fixture is not simply an invalid certificate or signature."""
    kind, bundle, root, policy, artifact = pss_subject_bundle
    certificate = bundle.signing_certificate
    assert certificate.public_key_algorithm_oid == PublicKeyAlgorithmOID.RSASSA_PSS
    assert isinstance(certificate.signature_algorithm_parameters, ec.ECDSA)
    verifier = Verifier(trusted_root=root)
    timestamps = verifier._establish_time(bundle)
    assert len(timestamps) == 1
    chain = verifier._verify_chain_at_time(certificate, timestamps[0])
    verify_sct(certificate, chain, root.ct_keyring(KeyringPurpose.VERIFY))
    policy.verify(certificate)
    bundle.log_entry._verify(root.rekor_keyring(KeyringPurpose.VERIFY))

    # The mathematical RSA signature is valid, but the certificate's PSS-only
    # subject profile forbids using it as PKCS1v15. Do not confuse these checks.
    public_key = certificate.public_key()
    assert isinstance(public_key, rsa.RSAPublicKey)
    data = bundle._dsse_envelope.pae() if kind == "dsse" else artifact
    public_key.verify(bundle.signature, data, padding.PKCS1v15(), hashes.SHA256())


def test_pss_subject_spki_rejected_by_public_verifier(pss_subject_bundle):
    kind, bundle, root, policy, artifact = pss_subject_bundle
    verifier = Verifier(trusted_root=root)
    with pytest.raises(
        VerificationError, match="Unsupported RSA subject key algorithm"
    ):
        if kind == "dsse":
            verifier.verify_dsse(bundle, policy)
        else:
            verifier.verify_artifact(artifact, bundle, policy)


def test_pss_subject_spki_has_no_pkcs1_key_details(asset):
    bundle = Bundle.from_json(asset("rsa-pss-spki/artifact.sigstore.json").read_bytes())
    with pytest.raises(ValueError, match="Unsupported RSA subject key algorithm"):
        _get_key_details(bundle.signing_certificate)
