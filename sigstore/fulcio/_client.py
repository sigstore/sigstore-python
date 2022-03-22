"""
Client implementation for interacting with Fulcio.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class CertificateRequest:
    pass


@dataclass(frozen=True)
class CertificateResponse:
    pass


class FulcioClient:
    def __init__(self, url: str) -> None:
        self.url = url

    def signing_cert(self, req: CertificateRequest) -> CertificateResponse:
        raise NotImplementedError
