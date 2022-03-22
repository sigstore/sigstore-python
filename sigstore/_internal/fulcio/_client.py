"""
Client implementation for interacting with Fulcio.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class CertificateRequest:
    """Certificate request"""

    pass


@dataclass(frozen=True)
class CertificateResponse:
    """Certificate response"""

    pass


class FulcioClient:
    """The internal Fulcio client"""

    def __init__(self, url: str) -> None:
        """Initialize the client"""
        self.url = url

    def signing_cert(self, req: CertificateRequest) -> CertificateResponse:
        """Get the signing certificate"""
        raise NotImplementedError
