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
from textwrap import dedent
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
        return """A network issue occurred.

        Check your internet connection and try again.
        """


class TUFError(Error):
    """Raised when a TUF error occurs."""

    def __init__(self, message: str):
        self.message = message

    from tuf.api import exceptions

    _details: Mapping[Any, str] = {
        exceptions.DownloadError: NetworkError().diagnostics()
    }

    def diagnostics(self) -> str:
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
        return f"""{str(self)}."""
