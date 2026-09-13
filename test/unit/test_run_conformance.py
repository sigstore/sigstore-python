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

"""Check runner orchestration and pytest collection, not Sigstore cryptography."""

import importlib.util
import os
import re
import subprocess
from functools import partial
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import Mock, call

import pytest

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def runner():
    spec = importlib.util.spec_from_file_location(
        "run_conformance", ROOT / "test/run_conformance.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_ci_pin_and_xfails_match(runner):
    workflow = (ROOT / ".github/workflows/conformance.yml").read_text()
    revision = re.search(
        r"uses: sigstore/sigstore-conformance@([0-9a-f]{40})", workflow
    )
    xfail = re.search(r'\bxfail: "([^"]+)"', workflow)
    assert revision is not None
    assert xfail is not None
    assert runner.CONFORMANCE_REVISION == revision.group(1)
    assert runner.CONFORMANCE_XFAIL.split() == xfail.group(1).split()


def test_client_environment_isolated_from_shell(runner, monkeypatch, tmp_path):
    client_python = tmp_path / "client env" / "bin" / "python"
    monkeypatch.setattr(runner, "sys", SimpleNamespace(executable=str(client_python)))
    poisoned = (
        "PYTHONPATH",
        "PYTHONHOME",
        "PYTEST_ADDOPTS",
        "PYTEST_PLUGINS",
        "SIGSTORE_IDENTITY_TOKEN",
        "SIGSTORE_STAGING",
        "SIGSTORE_TRUST_CONFIG",
        "SIGSTORE_FUTURE_SETTING",
    )
    for name in poisoned:
        monkeypatch.setenv(name, "unwanted")
    monkeypatch.setenv("PATH", str(tmp_path / "global" / "bin"))
    monkeypatch.setenv("GHA_SIGSTORE_CONFORMANCE_XFAIL", "test_*")
    monkeypatch.setenv("GHA_SIGSTORE_CONFORMANCE_SKIP_CPYTHON_RELEASE_TESTS", "false")
    monkeypatch.setenv("HTTPS_PROXY", "https://proxy.example")
    original = os.environ.copy()

    env = runner.client_environment()

    assert not set(poisoned) & env.keys()
    assert env["PATH"] == os.pathsep.join((str(client_python.parent), os.defpath))
    assert env["GHA_SIGSTORE_CONFORMANCE_XFAIL"] == runner.CONFORMANCE_XFAIL
    assert env["GHA_SIGSTORE_CONFORMANCE_SKIP_CPYTHON_RELEASE_TESTS"] == "true"
    assert env["HTTPS_PROXY"] == original["HTTPS_PROXY"]
    assert dict(os.environ) == original


@pytest.mark.parametrize("exit_code", [0, 1, 2, 5])
def test_suite_selection_and_pytest_exit_status(
    runner, monkeypatch, tmp_path, exit_code
):
    root = tmp_path / "client checkout"
    suite = tmp_path / "upstream suite"
    suite_python = tmp_path / "suite env" / "bin" / "python"
    check_output = Mock(return_value=f"{root / 'sigstore/__init__.py'}\n")
    run = Mock(return_value=SimpleNamespace(returncode=exit_code))
    monkeypatch.setattr(
        runner, "subprocess", SimpleNamespace(check_output=check_output, run=run)
    )
    env = runner.client_environment()
    args = ["-k", "happy-path", "-v"]

    assert runner.run_conformance(root, suite, suite_python, args) == exit_code

    check_output.assert_called_once_with(
        [
            runner.sys.executable,
            "-I",
            "-c",
            "import sigstore; print(sigstore.__file__)",
        ],
        cwd=suite,
        env=env,
        text=True,
    )
    run.assert_called_once_with(
        [
            str(suite_python),
            "-m",
            "pytest",
            *args,
            "-c",
            str(suite / "pyproject.toml"),
            "--rootdir",
            str(suite),
            str(suite / "test"),
            f"--entrypoint={root / 'test/integration/sigstore-python-conformance'}",
            "--skip-signing",
        ],
        cwd=suite,
        env=env,
        check=False,
    )


def test_collection_does_not_load_client_conftest(runner, monkeypatch, tmp_path, capfd):
    root = tmp_path / "client checkout"
    entrypoint = root / "test/integration/sigstore-python-conformance"
    entrypoint.parent.mkdir(parents=True)
    entrypoint.write_text("# Placeholder: collection must not execute the wrapper.\n")
    (root / "test/conftest.py").write_text(
        "raise RuntimeError('CLIENT_CONFTEST_MUST_NOT_LOAD')\n"
    )
    suite = tmp_path / "upstream suite"
    (suite / "test").mkdir(parents=True)
    (suite / "pyproject.toml").write_text("[tool.pytest.ini_options]\n")
    (suite / "conftest.py").write_text(
        "def pytest_addoption(parser):\n"
        "    parser.addoption('--entrypoint')\n"
        "    parser.addoption('--skip-signing', action='store_true')\n"
    )
    (suite / "test/test_collection.py").write_text("def test_smoke():\n    pass\n")
    monkeypatch.setattr(
        runner.subprocess,
        "check_output",
        Mock(return_value=str(root / "sigstore/__init__.py")),
    )

    assert (
        runner.run_conformance(
            root, suite, Path(runner.sys.executable), ["--collect-only", "-q"]
        )
        == 0
    )
    captured = capfd.readouterr()
    assert "test_collection.py::test_smoke" in captured.out
    assert "CLIENT_CONFTEST_MUST_NOT_LOAD" not in captured.out + captured.err


def test_rejects_another_sigstore_installation(runner, monkeypatch, tmp_path):
    run = Mock()
    monkeypatch.setattr(
        runner,
        "subprocess",
        SimpleNamespace(
            check_output=Mock(
                return_value=str(tmp_path / "global/sigstore/__init__.py")
            ),
            run=run,
        ),
    )

    with pytest.raises(RuntimeError, match="uv run --locked --dev"):
        runner.run_conformance(
            tmp_path / "checkout", tmp_path / "suite", tmp_path / "env/bin/python", []
        )

    run.assert_not_called()


@pytest.fixture
def setup_runner(runner, monkeypatch, tmp_path):
    # Substitute only the runner's platform check, without affecting pathlib on Windows.
    monkeypatch.setattr(runner, "os", SimpleNamespace(name="posix"))
    monkeypatch.setattr(
        runner, "TemporaryDirectory", partial(TemporaryDirectory, dir=tmp_path)
    )
    monkeypatch.setattr(runner, "subprocess", SimpleNamespace(run=Mock()))
    monkeypatch.setattr(runner, "run_conformance", Mock(return_value=5))
    return runner


def test_setup_uses_pinned_suite_and_hash_checked_separate_environment(
    setup_runner, tmp_path
):
    assert setup_runner.main(["--collect-only"]) == 5

    root, suite, suite_python, args = setup_runner.run_conformance.call_args.args
    assert root == ROOT
    assert suite.parent.parent == tmp_path
    assert suite_python == suite.parent / "env/bin/python"
    assert args == ["--collect-only"]
    assert setup_runner.subprocess.run.call_args_list == [
        call(["git", "init", "--quiet", str(suite)], check=True),
        call(
            [
                "git",
                "-C",
                str(suite),
                "fetch",
                "--quiet",
                "--depth=1",
                "https://github.com/sigstore/sigstore-conformance",
                setup_runner.CONFORMANCE_REVISION,
            ],
            check=True,
        ),
        call(
            ["git", "-C", str(suite), "checkout", "--quiet", "--detach", "FETCH_HEAD"],
            check=True,
        ),
        call(
            [
                "uv",
                "venv",
                "--python",
                setup_runner.sys.executable,
                str(suite.parent / "env"),
            ],
            check=True,
        ),
        call(
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
        ),
    ]
    assert not suite.parent.exists()


@pytest.mark.parametrize("failure_step", range(5))
def test_setup_failure_stops_before_pytest_and_cleans_up(
    setup_runner, tmp_path, failure_step
):
    failure = subprocess.CalledProcessError(17, "setup")
    setup_runner.subprocess.run.side_effect = [None] * failure_step + [failure]

    with pytest.raises(subprocess.CalledProcessError) as caught:
        setup_runner.main([])

    assert caught.value.returncode == 17
    assert setup_runner.subprocess.run.call_count == failure_step + 1
    setup_runner.run_conformance.assert_not_called()
    assert not list(tmp_path.iterdir())


def test_windows_reports_posix_requirement(runner, monkeypatch, capsys):
    monkeypatch.setattr(runner, "os", SimpleNamespace(name="nt"))
    setup = Mock()
    monkeypatch.setattr(runner, "TemporaryDirectory", setup)

    assert runner.main([]) == 1
    assert "WSL" in capsys.readouterr().err
    setup.assert_not_called()
