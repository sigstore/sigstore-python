# Copyright 2022 The Sigstore Authors
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
from typing import Any, Mapping


class Error(Exception):
    """Base sigstore exception type. Defines helpers for diagnostics."""

    def diagnostics(self) -> str:
        """Returns human-friendly error information."""

        return """An issue occurred."""

    def print_and_exit(self, raise_error: bool = False) -> None:
        """Prints all relevant error information to stderr and exits."""

        remind_verbose = (
            "Raising original exception:"
            if raise_error
            else "For detailed error information, run sigstore with the `--verbose` flag."
        )

        print(f"{self.diagnostics()}\n{remind_verbose}", file=sys.stderr)

        if raise_error:
            # don't want "during handling another exception"
            self.__suppress_context__ = True
            raise self

        sys.exit(1)


class NetworkError(Error):
    """Raised when a connectivity-related issue occurs."""

    def diagnostics(self) -> str:
        """Returns diagnostics for the error."""
        return """A network issue occurred.

        Check your internet connection and try again.
        """


class TUFError(Error):
    """Raised when a TUF error occurs."""

    def __init__(self, message: str):
        """Constructs a `TUFError`."""
        self.message = message

    from tuf.api import exceptions

    _details: Mapping[Any, str] = {
        exceptions.DownloadError: NetworkError().diagnostics()
    }

    def diagnostics(self) -> str:
        """Returns diagnostics specialized to the wrapped TUF error."""
        details = TUFError._details.get(
            type(self.__context__),
            "Please report this issue at <https://github.com/sigstore/sigstore-python/issues/new>.",
        )

        return f"""{self.message}.

        {details}
        """


class MetadataError(Error):
    """Raised when TUF metadata does not conform to the expected structure."""

    def diagnostics(self) -> str:
        """Returns diagnostics for the error."""
        return f"""{str(self)}."""


class VerificationError(Error):
    """Raised when the verifier returns a `VerificationFailure` result."""

    # HACK(tnytown): Importing this at the top of the module causes circular import issues.
    from sigstore.verify.models import VerificationFailure
    from sigstore.verify.verifier import (
        CertificateVerificationFailure,
        LogEntryMissing,
    )

    def __init__(self, result: VerificationFailure):
        self.message = f"Verification failed: {result.reason}"
        self.result = result

    def diagnostics(self) -> str:
        message = f"Failure reason: {self.result.reason}\n"

        if isinstance(self.result, self.CertificateVerificationFailure):
            message += dedent(
                f"""
                The given certificate could not be verified against the
                root of trust.

                This may be a result of connecting to the wrong Fulcio instance
                (for example, staging instead of production, or vice versa).

                Additional context:

                {self.result.exception}
                """
            )
        elif isinstance(self.result, self.LogEntryMissing):
            message += dedent(
                f"""
                These signing artifacts could not be matched to a entry
                in the configured transparency log.

                This may be a result of connecting to the wrong Rekor instance
                (for example, staging instead of production, or vice versa).

                Additional context:

                Signature: {self.result.signature}

                Artifact hash: {self.result.artifact_hash}
                """
            )
        else:
            message += dedent(
                f"""
                A verification error occurred.

                Additional context:

                {self.result}
                """
            )

        return message
