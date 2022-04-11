import base64
import hashlib

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from sigstore._internal.fulcio import (
    FulcioCertificateSigningRequest,
    FulcioClient,
)
from sigstore._internal.oidc import Identity
from sigstore._internal.rekor import RekorClient

# from cryptography.x509 import load_pem_x509_certificate


REKOR_URL = "https://rekor.sigstore.dev"
REKOR_API_HEADERS = {"Content-Type": "application/json", "Accept": "application/json"}


def _no_output(*a, **kw):
    pass


def sign(file_, identity_token, output=_no_output):
    """Public API for signing blobs"""

    output(f"Using payload from: {file_.name}")
    artifact_contents = file_.read().encode()
    sha256_artifact_hash = hashlib.sha256(artifact_contents).hexdigest()

    output("Generating ephemeral keys...")
    # Generate the ephemeral private key
    # private_key = Ed25519PrivateKey.generate()
    # public_key = private_key.public_key()
    private_key = ec.generate_private_key(ec.SECP384R1())
    public_key = private_key.public_key()

    output("Retrieving signed certificate...")
    # fulcio = FulcioClient("http://localhost:5555")
    fulcio = FulcioClient()

    oidc_identity = Identity(identity_token)

    # Build an X.509 Certificiate Signing Request - not currently supported
    """
    builder = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(
            x509.Name(
                [
                    x509.NameAttribute(NameOID.EMAIL_ADDRESS, email_address),
                ]
            )
        )
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
    )
    certificate_request = builder.sign(private_key, hashes.SHA256())
    """
    signed_proof = private_key.sign(
        oidc_identity.proof.encode(), ec.ECDSA(hashes.SHA256())
    )
    certificate_request = FulcioCertificateSigningRequest(public_key, signed_proof)

    certificate_response = fulcio.signing_cert.post(certificate_request, identity_token)

    # Verify the SCT
    # TODO TODO TODO
    sct = certificate_response.sct  # noqa
    cert = certificate_response.cert  # noqa
    # certificate
    # OCSP response
    # public key of fulcio log
    # - no api that exposes the public key, bake it in or get it via TUF
    # - ecdsa PEM encoded key
    # - https://storage.googleapis.com/sigstore-tuf-root
    # - https://github.com/google/certificate-transparency-go/
    output("Successfully verified SCT...")

    # Output the ephemeral certificate
    output("Using ephemeral certificate:")
    output(cert.public_bytes(encoding=serialization.Encoding.PEM))

    # Sign artifact
    artifact_signature = private_key.sign(artifact_contents, ec.ECDSA(hashes.SHA256()))
    b64_artifact_signature = base64.b64encode(artifact_signature).decode()

    # Prepare inputs
    pub_b64 = base64.b64encode(
        public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )

    # Create the transparency log entry
    rekor = RekorClient()
    entry = rekor.log.entries.post(
        b64_artifact_signature=b64_artifact_signature,
        sha256_artifact_hash=sha256_artifact_hash,
        encoded_public_key=pub_b64.decode(),
    )

    output(f"Transparency log entry created with index: {entry.log_index}")

    # Output the signature
    output(f"Signature: {b64_artifact_signature}")

    # Determine what to return here
    return None
