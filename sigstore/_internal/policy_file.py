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
Loading of verification policies from TOML policy files.

A policy file describes either a single identity:

```toml
identity = "alice@example.com"
issuer = "https://accounts.google.com"
```

or a list of identities, any one of which is accepted:

```toml
[[any-of]]
identity = "alice@example.com"
issuer = "https://accounts.google.com"

[[any-of]]
identity = "bob@example.com"
issuer = "https://github.com/login/oauth"
```

Every identity requires both an `identity` and an `issuer`.
"""

from __future__ import annotations

import tomllib
from pathlib import Path
from typing import Any

from sigstore.errors import Error
from sigstore.verify import policy


class PolicyFileError(Error):
    """
    Raised when a policy file cannot be read or does not describe a valid policy.
    """


_ANY_OF_KEY = "any-of"
_IDENTITY_KEY = "identity"
_ISSUER_KEY = "issuer"
_IDENTITY_KEYS = (_IDENTITY_KEY, _ISSUER_KEY)


def load_policy(path: Path) -> policy.VerificationPolicy:
    """
    Load a `VerificationPolicy` from the TOML policy file at `path`.

    Raises `PolicyFileError` if the file cannot be read, is not valid TOML,
    or does not describe a valid policy.
    """
    try:
        with path.open("rb") as io:
            document = tomllib.load(io)
    except OSError as exc:
        raise PolicyFileError(f"{path}: {exc.strerror}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise PolicyFileError(f"{path}: invalid TOML: {exc}") from exc
    except UnicodeDecodeError as exc:
        raise PolicyFileError(f"{path}: invalid TOML: not valid UTF-8: {exc}") from exc

    # Every error names the file, followed by the location within it.
    root = f"{path}: policy"

    if not document:
        raise PolicyFileError(
            f"{root}: expected '{_IDENTITY_KEY}' and '{_ISSUER_KEY}', "
            f"or '{_ANY_OF_KEY}'"
        )

    if _ANY_OF_KEY not in document:
        return _identity_from_node(document, root)

    if len(document) != 1:
        raise PolicyFileError(
            f"{root}: '{_ANY_OF_KEY}' cannot be combined with other keys"
        )

    value = document[_ANY_OF_KEY]
    where = f"{root}.{_ANY_OF_KEY}"
    if not isinstance(value, list) or not value:
        raise PolicyFileError(
            f"{where}: expected a non-empty array of identities, got {_describe(value)}"
        )
    return policy.AnyOf(
        [
            _identity_from_node(child, f"{where}[{index}]")
            for index, child in enumerate(value)
        ]
    )


def _identity_from_node(node: Any, where: str) -> policy.Identity:
    """
    Convert a decoded TOML table into an `Identity` policy.

    `where` describes the node's location in the file, for error messages.
    """
    if not isinstance(node, dict):
        raise PolicyFileError(f"{where}: expected a table, got {_describe(node)}")

    unknown = sorted(set(node) - set(_IDENTITY_KEYS))
    if unknown:
        s = "" if len(unknown) == 1 else "s"
        names = ", ".join(f"'{key}'" for key in unknown)
        raise PolicyFileError(
            f"{where}: unknown key{s} {names}; "
            f"expected '{_IDENTITY_KEY}' and '{_ISSUER_KEY}'"
        )

    values = {}
    for key in _IDENTITY_KEYS:
        if key not in node:
            raise PolicyFileError(f"{where}: missing required key '{key}'")
        value = node[key]
        if not isinstance(value, str):
            raise PolicyFileError(
                f"{where}.{key}: expected a string, got {_describe(value)}"
            )
        if not value:
            raise PolicyFileError(f"{where}.{key}: expected a non-empty string")
        values[key] = value

    return policy.Identity(identity=values[_IDENTITY_KEY], issuer=values[_ISSUER_KEY])


def _describe(value: Any) -> str:
    """
    Describe a decoded TOML value in TOML terms, for error messages.
    """
    if isinstance(value, dict):
        return "a table"
    elif isinstance(value, list):
        return "an empty array" if not value else "an array"
    elif isinstance(value, bool):
        return "a boolean"
    elif isinstance(value, str):
        return "a string"
    elif isinstance(value, (int, float)):
        return "a number"
    return type(value).__name__
