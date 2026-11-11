# Copyright 2023 The Sigstore Authors
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

"""
Exceptions.
"""

import sys
from logging import Logger
from typing import NoReturn

from tuf.api import exceptions


class Error(Exception):
    """Base sigstore exception type. Defines helpers for diagnostics."""

    def diagnostics(self) -> str:
        """Returns human-friendly error information."""

        return str(self)

    def log_and_exit(self, logger: Logger, raise_error: bool = False) -> NoReturn:
        """Prints all relevant error information to stderr and exits."""

        remind_verbose = (
            "Raising original exception:"
            if raise_error
            else "For detailed error information, run sigstore with the `--verbose` flag."
        )

        logger.error(f"{self.diagnostics()}\n{remind_verbose}")

        if raise_error:
            # don't want "during handling another exception"
            self.__suppress_context__ = True
            raise self

        sys.exit(1)


class NetworkError(Error):
    """Raised when a connectivity-related issue occurs."""

    def diagnostics(self) -> str:
        """Returns diagnostics for the error."""
        return self._diagnostics(str(self.__cause__))

    @staticmethod
    def _diagnostics(cause: str | None) -> str:
        cause_ctx = f"\n\nAdditional context:\n\n{cause}" if cause else ""

        return (
            "A network issue occurred.\n\n"
            "Check your internet connection and try again." + cause_ctx
        )


class TUFError(Error):
    """Raised when a TUF error occurs."""

    def __init__(self, message: str):
        """Constructs a `TUFError`."""
        super().__init__(message)
        self.message = message

    def diagnostics(self) -> str:
        """Returns diagnostics specialized to the wrapped TUF error."""
        # Download errors are likely to be ephemeral: just use NetworkError output
        if isinstance(self.__cause__, exceptions.DownloadError):
            return NetworkError._diagnostics(f"{self.message}: {self.__cause__}")

        # Other TUF errors are likely to be cryptic and unrecoverable
        cause_ctx = (
            f"\n\nAdditional context:\n\n{self.__cause__}" if self.__cause__ else ""
        )
        return (
            f"{self.message}.\n\n"
            "Please check any Sigstore instance related arguments and consider "
            "reporting the issue at <https://github.com/sigstore/sigstore-python/issues/new>."
            + cause_ctx
        )


class MetadataError(Error):
    """Raised when TUF metadata does not conform to the expected structure."""

    def diagnostics(self) -> str:
        """Returns diagnostics for the error."""
        return f"""{self}."""


class RootError(Error):
    """Raised when TUF cannot establish its root of trust."""

    def diagnostics(self) -> str:
        """Returns diagnostics for the error."""
        return (
            "Unable to establish root of trust.\n\n"
            "This error may occur when the resources embedded in this "
            "distribution of sigstore-python are out of date."
        )


class VerificationError(Error):
    """
    Raised whenever any phase or subcomponent of Sigstore verification fails.
    """


class CertValidationError(VerificationError):
    """
    Raised when a TSA certificate chain fails to validate during Sigstore verification.

    This is used by CLI to hint that an incorrect Sigstore instance may have been used
    """
