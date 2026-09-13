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

"""Run upstream verification conformance against this editable checkout."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from tempfile import TemporaryDirectory

# Keep these in sync with .github/workflows/conformance.yml (tested below).
CONFORMANCE_REVISION = "21533cde107c734ebc153c3e3a24d75fc9811a36"
CONFORMANCE_XFAIL = (
    "test_verify*intoto-with-custom-trust-root] "
    "test_verify*managed-key-happy-path] "
    "test_verify*managed-key-and-trusted-root]"
)


def client_environment() -> dict[str, str]:
    """Keep the suite isolated, while its subprocesses use the client environment."""
    env = os.environ.copy()
    for name in ("PYTHONPATH", "PYTHONHOME", "PYTEST_ADDOPTS", "PYTEST_PLUGINS"):
        env.pop(name, None)
    for name in list(env):
        if name.startswith("SIGSTORE_"):
            env.pop(name)
    # The protocol wrapper uses /usr/bin/env python3 and execvp("sigstore", ...).
    # Do not resolve sys.executable: its symlink lives in the client virtualenv.
    env["PATH"] = os.pathsep.join((str(Path(sys.executable).parent), os.defpath))
    env["GHA_SIGSTORE_CONFORMANCE_XFAIL"] = CONFORMANCE_XFAIL
    # Release-tracker data is supplied by the CI action, not this local target.
    env["GHA_SIGSTORE_CONFORMANCE_SKIP_CPYTHON_RELEASE_TESTS"] = "true"
    return env


def run_conformance(
    root: Path, suite: Path, suite_python: Path, pytest_args: list[str]
) -> int:
    """Select the upstream suite and propagate pytest's exit status unchanged."""
    env = client_environment()
    imported = subprocess.check_output(
        [sys.executable, "-I", "-c", "import sigstore; print(sigstore.__file__)"],
        cwd=suite,
        env=env,
        text=True,
    ).strip()
    if Path(imported).resolve() != (root / "sigstore/__init__.py").resolve():
        raise RuntimeError("Run with 'uv run --locked --dev' from this checkout")
    print(f"Client checkout: {root}", flush=True)
    print(f"Conformance revision: {CONFORMANCE_REVISION}", flush=True)
    print(
        "Verification only; signing and CPython release-tracker tests skipped.",
        flush=True,
    )
    return subprocess.run(
        [
            str(suite_python),
            "-m",
            "pytest",
            *pytest_args,
            "-c",
            str(suite / "pyproject.toml"),
            "--rootdir",
            str(suite),
            str(suite / "test"),
            # A separate path argument makes pytest's initial discovery load
            # the client's conftest before this custom option is registered.
            f"--entrypoint={root / 'test/integration/sigstore-python-conformance'}",
            "--skip-signing",
        ],
        cwd=suite,
        env=env,
        check=False,
    ).returncode


def main(args: list[str] | None = None) -> int:
    """Fetch the CI-pinned suite and install its requirements outside the dev venv."""
    if os.name == "nt":
        print(
            "The conformance protocol wrapper requires POSIX; use WSL.", file=sys.stderr
        )
        return 1
    root = Path(__file__).resolve().parent.parent
    with TemporaryDirectory(prefix="sigstore-conformance-") as directory:
        workspace = Path(directory)
        suite = workspace / "suite"
        subprocess.run(["git", "init", "--quiet", str(suite)], check=True)
        subprocess.run(
            [
                "git",
                "-C",
                str(suite),
                "fetch",
                "--quiet",
                "--depth=1",
                "https://github.com/sigstore/sigstore-conformance",
                CONFORMANCE_REVISION,
            ],
            check=True,
        )
        subprocess.run(
            ["git", "-C", str(suite), "checkout", "--quiet", "--detach", "FETCH_HEAD"],
            check=True,
        )
        suite_env = workspace / "env"
        subprocess.run(
            ["uv", "venv", "--python", sys.executable, str(suite_env)], check=True
        )
        suite_python = suite_env / "bin/python"
        subprocess.run(
            [
                "uv",
                "pip",
                "sync",
                "--python",
                str(suite_python),
                "--require-hashes",
                str(suite / "requirements.txt"),
            ],
            check=True,
        )
        return run_conformance(
            root, suite, suite_python, sys.argv[1:] if args is None else args
        )


if __name__ == "__main__":
    try:
        sys.exit(main())
    except subprocess.CalledProcessError as error:
        sys.exit(error.returncode)
