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

from pathlib import Path

import pytest

from sigstore._internal.policy_file import PolicyFileError, load_policy
from sigstore.errors import VerificationError
from sigstore.verify import policy


@pytest.fixture
def policy_file(tmp_path: Path):
    def _policy_file(contents: str) -> Path:
        path = tmp_path / "policy.toml"
        path.write_text(contents, encoding="utf-8")
        return path

    return _policy_file


class TestLoadPolicy:
    def test_single_identity(self, policy_file):
        policy_ = load_policy(
            policy_file(
                """
                identity = "alice@example.com"
                issuer = "https://accounts.google.com"
                """
            )
        )

        assert isinstance(policy_, policy.Identity)
        assert policy_._identity == "alice@example.com"
        assert isinstance(policy_._issuer, policy.OIDCIssuer)
        assert policy_._issuer._value == "https://accounts.google.com"

    def test_any_of_identities(self, policy_file):
        policy_ = load_policy(
            policy_file(
                """
                # comment 1
                [[any-of]]
                identity = "alice@example.com"
                issuer = "https://accounts.google.com"

                # comment 2
                [[any-of]]
                identity = "bob@example.com"
                issuer = "https://github.com/login/oauth"
                """
            )
        )

        assert isinstance(policy_, policy.AnyOf)
        assert [child._identity for child in policy_._children] == [
            "alice@example.com",
            "bob@example.com",
        ]
        assert [child._issuer._value for child in policy_._children] == [
            "https://accounts.google.com",
            "https://github.com/login/oauth",
        ]

    def test_inline_tables(self, policy_file):
        policy_ = load_policy(
            policy_file(
                """
                any-of = [
                    { identity = "alice@example.com", issuer = "https://accounts.google.com" },
                    { identity = "bob@example.com", issuer = "https://github.com/login/oauth" },
                ]
                """
            )
        )

        assert isinstance(policy_, policy.AnyOf)
        assert len(policy_._children) == 2

    def test_verifies_against_certificate(self, policy_file, signing_bundle):
        _, bundle = signing_bundle("bundle.txt")
        policy_ = load_policy(
            policy_file(
                """
                [[any-of]]
                identity = "foo"
                issuer = "bar"

                [[any-of]]
                identity = "a@tny.town"
                issuer = "https://github.com/login/oauth"
                """
            )
        )

        policy_.verify(bundle.signing_certificate)

    def test_fails_against_certificate(self, policy_file, signing_bundle):
        _, bundle = signing_bundle("bundle.txt")
        policy_ = load_policy(
            policy_file(
                """
                [[any-of]]
                identity = "foo"
                issuer = "bar"

                [[any-of]]
                identity = "a@tny.town"
                issuer = "https://accounts.google.com"
                """
            )
        )

        with pytest.raises(VerificationError, match="0 of 2 policies succeeded"):
            policy_.verify(bundle.signing_certificate)

    def test_missing_file(self, tmp_path):
        with pytest.raises(PolicyFileError, match="No such file or directory"):
            load_policy(tmp_path / "missing.toml")

    def test_invalid_toml(self, policy_file):
        with pytest.raises(PolicyFileError, match="invalid TOML"):
            load_policy(policy_file("identity = "))

    def test_invalid_utf8(self, tmp_path):
        path = tmp_path / "policy.toml"
        path.write_bytes(b'identity = "\xff"\nissuer = "b"\n')

        with pytest.raises(PolicyFileError, match="not valid UTF-8"):
            load_policy(path)

    @pytest.mark.parametrize(
        ("contents", "message"),
        [
            ("", "policy: expected 'identity' and 'issuer', or 'any-of'"),
            ('identity = "a"', "policy: missing required key 'issuer'"),
            ('issuer = "b"', "policy: missing required key 'identity'"),
            (
                'identity = "a"\nissuer = ""',
                "policy.issuer: expected a non-empty string",
            ),
            (
                'identity = ""\nissuer = "b"',
                "policy.identity: expected a non-empty string",
            ),
            (
                'identity = "a"\nissuer = "b"\nunknown = "c"',
                "policy: unknown key 'unknown'; expected 'identity' and 'issuer'",
            ),
            (
                'identity = "a"\nissuer = "b"\nzeta = "c"\nalpha = "d"',
                (
                    "policy: unknown keys 'alpha', 'zeta'; "
                    "expected 'identity' and 'issuer'"
                ),
            ),
            (
                'identity = "a"\nissuer = "b"\noidc-issuer = "c"',
                "policy: unknown key 'oidc-issuer'; expected 'identity' and 'issuer'",
            ),
            (
                'identity = 1\nissuer = "b"',
                "policy.identity: expected a string, got a number",
            ),
            (
                'identity = true\nissuer = "b"',
                "policy.identity: expected a string, got a boolean",
            ),
            (
                'issuer = "b"\n[identity]\nfoo = 1',
                "policy.identity: expected a string, got a table",
            ),
            (
                'identity = "a"\nissuer = ["b"]',
                "policy.issuer: expected a string, got an array",
            ),
            (
                'identity = "a"\nissuer = "b"\nany-of = []',
                "policy: 'any-of' cannot be combined with other keys",
            ),
            (
                "any-of = []",
                (
                    "policy.any-of: expected a non-empty array of identities, "
                    "got an empty array"
                ),
            ),
            (
                'any-of = "a"',
                "policy.any-of: expected a non-empty array of identities, got a string",
            ),
            (
                '[any-of]\nidentity = "a"',
                "policy.any-of: expected a non-empty array of identities, got a table",
            ),
            ('any-of = ["a"]', "policy.any-of[0]: expected a table, got a string"),
            (
                '[[any-of]]\nidentity = "a"\nissuer = "b"\n\n[[any-of]]\nidentity = "c"',
                "policy.any-of[1]: missing required key 'issuer'",
            ),
            (
                '[[any-of]]\nany-of = [{ identity = "a", issuer = "b" }]',
                "policy.any-of[0]: unknown key 'any-of'; expected 'identity' and 'issuer'",
            ),
            (
                '[[all-of]]\nidentity = "a"\nissuer = "b"',
                "policy: unknown key 'all-of'; expected 'identity' and 'issuer'",
            ),
        ],
    )
    def test_invalid_policy(self, policy_file, contents, message):
        path = policy_file(contents)

        with pytest.raises(PolicyFileError) as excinfo:
            load_policy(path)

        assert str(excinfo.value) == f"{path}: {message}"
