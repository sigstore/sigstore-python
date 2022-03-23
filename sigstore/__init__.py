"""
The `sigstore` APIs.
"""

from sigstore._sign import sign
from sigstore._verify import verify
from sigstore._version import __version__

__all__ = ["__version__", "sign", "verify"]
