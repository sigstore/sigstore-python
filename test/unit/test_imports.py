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

"""
Regression tests for the `sigstore.models` <-> `sigstore._internal.rekor`
import cycle (see #1536).

`sigstore.models` needs `RekorClient`/`RekorV2Client` (to implement
`SigningConfig.get_tlogs()`) and the Rekor client modules need
`TransparencyLogEntry` (to type their responses). Both used to live in
`sigstore.models`, which forced a lazy, function-local import in
`get_tlogs()` to avoid a circular import at module load time.
`TransparencyLogEntry` now lives in the leaf module
`sigstore._internal.rekor.entry`, which neither `sigstore.models` nor the
Rekor clients need to import lazily.

Each of the modules below sits somewhere on the former cycle. We import each
one first, in its own fresh interpreter (so that Python's module cache can't
paper over an ordering bug), to prove that no matter which module a caller
happens to import first, the whole graph resolves without a
`ImportError`/`AttributeError` from a partially initialized module.
"""

from __future__ import annotations

import subprocess
import sys

import pytest

# Every module that either used to be involved in the cycle, or now sits
# between the two former halves of it.
_CYCLE_MODULES = [
    "sigstore.models",
    "sigstore._internal.rekor.entry",
    "sigstore._internal.rekor.client",
    "sigstore._internal.rekor.client_v2",
    "sigstore._internal.rekor.checkpoint",
    "sigstore._internal.merkle",
]


@pytest.mark.parametrize("module", _CYCLE_MODULES)
def test_import_first_in_fresh_interpreter(module: str) -> None:
    """
    Each formerly-cyclic module can be the very first `sigstore` import in a
    fresh process, regardless of which other modules end up pulling in the
    rest of the package.
    """
    proc = subprocess.run(
        [sys.executable, "-c", f"import {module}"],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr


def test_get_tlogs_does_not_lazily_import_rekor_clients() -> None:
    """
    `SigningConfig.get_tlogs()` previously had to work around the import
    cycle with function-local (lazy) imports of `RekorClient` and
    `RekorV2Client`. Assert that `sigstore.models` now imports them eagerly,
    at module scope, like every other dependency.
    """
    import sigstore.models as models
    from sigstore._internal.rekor.client import RekorClient
    from sigstore._internal.rekor.client_v2 import RekorV2Client

    assert models.RekorClient is RekorClient
    assert models.RekorV2Client is RekorV2Client


def test_transparency_log_entry_is_reexported_not_duplicated() -> None:
    """
    `sigstore.models.TransparencyLogEntry` must be the same object as
    `sigstore._internal.rekor.entry.TransparencyLogEntry`, not a second,
    shadow definition.
    """
    from sigstore._internal.rekor.entry import TransparencyLogEntry as _Entry
    from sigstore.models import TransparencyLogEntry

    assert TransparencyLogEntry is _Entry


def test_invalid_bundle_is_reexported_not_duplicated() -> None:
    """
    `sigstore.models.InvalidBundle`/`IncompatibleEntry` must be the same
    objects as `sigstore.errors.InvalidBundle`/`IncompatibleEntry`, not
    second, shadow definitions.
    """
    from sigstore.errors import IncompatibleEntry as _IncompatibleEntry
    from sigstore.errors import InvalidBundle as _InvalidBundle
    from sigstore.models import IncompatibleEntry, InvalidBundle

    assert InvalidBundle is _InvalidBundle
    assert IncompatibleEntry is _IncompatibleEntry
