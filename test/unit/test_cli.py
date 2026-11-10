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

import pytest

from sigstore._cli import main


def test_invalid_bool_env_exits_cleanly(monkeypatch, capsys):
    """An invalid boolean-style env var is a usage error, not a traceback."""
    monkeypatch.setenv("SIGSTORE_OFFLINE", "maybe")

    with pytest.raises(SystemExit) as exc:
        main(["--help"])

    assert exc.value.code == 2
    err = capsys.readouterr().err
    assert "can't coerce" in err
    assert "Traceback" not in err


def test_valid_bool_env_still_parses(monkeypatch, capsys):
    """A valid boolean-style env var keeps working, including --help."""
    monkeypatch.setenv("SIGSTORE_OFFLINE", "true")

    with pytest.raises(SystemExit) as exc:
        main(["--help"])

    assert exc.value.code == 0
    assert "usage:" in capsys.readouterr().out
