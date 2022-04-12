"""
API for verifying artifact signatures.
"""

import base64
import hashlib
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509 import (
    ExtendedKeyUsage,
    KeyUsage,
    RFC822Name,
    SubjectAlternativeName,
    load_pem_x509_certificate,
)
from cryptography.x509.oid import ExtendedKeyUsageOID
from OpenSSL.crypto import X509, X509Store, X509StoreContext

from sigstore._internal.merkle import verify_merkle_inclusion
from sigstore._internal.rekor import (
    RekorClient,
    RekorEntry,
    RekorInclusionProof,
)
from sigstore._internal.set import verify_set


# TODO(alex): Share this with `sign`
def _no_output(*a, **kw):
    pass


FULCIO_ROOT_CERT = "fulcio.crt.pem"


def verify(
    filename, certificate_path, signature_path, cert_email, output=_no_output
) -> None:
    # Read the contents of the package to be verified
    artifact_contents = filename.read().encode()
    sha256_artifact_hash = hashlib.sha256(artifact_contents).hexdigest()

    # Load the signing certificate
    pem_data = certificate_path.read()
    cert = load_pem_x509_certificate(pem_data)

    # Load the signature
    b64_artifact_signature = signature_path.read().encode()
    artifact_signature = base64.b64decode(b64_artifact_signature)

    # In order to verify an artifact, we need to achieve the following:
    #
    # 1) Verify that the signing certificate is signed by the root certificate and that the signing
    #    certificate was valid at the time of signing.
    # 2) Verify that the signing certiticate belongs to the signer
    # 3) Verify that the signature was signed by the public key in the signing certificate
    #
    # And optionally, if we're performing verification online:
    #
    # 4) Verify the inclusion proof supplied by Rekor for this artifact
    # 5) Verify the Signed Entry Timestamp (SET) supplied by Rekor for this artifact

    # 1) Verify that the signing certificate is signed by the root certificate and that the signing
    #    certificate was valid at the time of signing.
    root_cert_path = Path(__file__).parent / FULCIO_ROOT_CERT
    if not root_cert_path.is_file():
        # Error
        return
    pem_bytes = open(root_cert_path, "rb").read()
    root = load_pem_x509_certificate(pem_bytes)

    sign_date = cert.not_valid_before
    openssl_cert = X509.from_cryptography(cert)
    openssl_root = X509.from_cryptography(root)

    store = X509Store()
    store.add_cert(openssl_root)
    store.set_time(sign_date)
    store_ctx = X509StoreContext(store, openssl_cert)
    store_ctx.verify_certificate()

    # 2) Check that the signing certificate contains the proof claim as the subject

    if cert_email is not None:
        # Check usage is "digital signature"
        usage_ext = cert.extensions.get_extension_for_class(KeyUsage)
        assert usage_ext.value.digital_signature

        # Check that extended usage contains "code signing"
        extended_usage_ext = cert.extensions.get_extension_for_class(ExtendedKeyUsage)
        assert ExtendedKeyUsageOID.CODE_SIGNING in extended_usage_ext.value

        # Check that SubjectAlternativeName contains signer identity
        san_ext = cert.extensions.get_extension_for_class(SubjectAlternativeName)
        assert cert_email in san_ext.value.get_values_for_type(RFC822Name)

    # 3) Verify that the signature was signed by the public key in the signing certificate
    signing_key = cert.public_key()
    signing_key.verify(artifact_signature, artifact_contents, hashes.SHA256())

    # The log ID is a hash of a DER encoding of the signing certificate
    desired_log_id = hashlib.sha256(
        cert.public_bytes(encoding=serialization.Encoding.DER)
    ).hexdigest()

    # Retrieve the relevant Rekor entry to verify the inclusion proof and SET
    rekor = RekorClient()
    uuids = rekor.index.retrieve.post(sha256_artifact_hash)
    entry = None
    for uuid in uuids:
        cur_entry: RekorEntry = rekor.log.entries.get(uuid)
        if cur_entry.log_id == desired_log_id:
            entry = cur_entry
            break
    if entry is None:
        # Error
        return None

    # 4) Verify the inclusion proof supplied by Rekor for this artifact
    inclusion_proof = RekorInclusionProof.from_dict(
        entry.verification.get("inclusionProof")
    )
    verify_merkle_inclusion(inclusion_proof)

    # 5) Verify the Signed Entry Timestamp (SET) supplied by Rekor for this artifact
    verify_set(entry)

    return None
