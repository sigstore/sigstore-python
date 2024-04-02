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

import pretend
import pytest
from cryptography.x509 import ExtensionNotFound

from sigstore.verify import policy
from sigstore.verify.models import VerificationFailure, VerificationSuccess


class TestVerificationPolicy:
    def test_does_not_init(self):
        with pytest.raises(TypeError, match="Can't instantiate abstract class"):
            policy.VerificationPolicy(pretend.stub())


class TestUnsafeNoOp:
    def test_succeeds(self, monkeypatch):
        logger = pretend.stub(warning=pretend.call_recorder(lambda s: None))
        monkeypatch.setattr(policy, "_logger", logger)

        policy_ = policy.UnsafeNoOp()
        assert policy_.verify(pretend.stub())
        assert logger.warning.calls == [
            pretend.call(
                "unsafe (no-op) verification policy used! no verification performed!"
            )
        ]


class TestAnyOf:
    def test_trivially_false(self):
        policy_ = policy.AnyOf([])
        result = policy_.verify(pretend.stub())
        assert not result
        assert result == VerificationFailure(reason="0 of 0 policies succeeded")

    def test_fails_no_children_match(self, signing_bundle):
        _, bundle = signing_bundle("bundle.txt")
        policy_ = policy.AnyOf(
            [
                policy.Identity(identity="foo", issuer="bar"),
                policy.Identity(identity="baz", issuer="quux"),
            ]
        )

        result = policy_.verify(bundle.signing_certificate)
        assert not result
        assert result == VerificationFailure(reason="0 of 2 policies succeeded")

    def test_succeeds(self, signing_bundle):
        _, bundle = signing_bundle("bundle.txt")
        policy_ = policy.AnyOf(
            [
                policy.Identity(identity="foo", issuer="bar"),
                policy.Identity(identity="baz", issuer="quux"),
                policy.Identity(
                    identity="a@tny.town",
                    issuer="https://github.com/login/oauth",
                ),
            ]
        )

        result = policy_.verify(bundle.signing_certificate)
        assert result
        assert result == VerificationSuccess()


class TestAllOf:
    def test_trivially_false(self):
        policy_ = policy.AllOf([])
        result = policy_.verify(pretend.stub())
        assert not result
        assert result == VerificationFailure(reason="no child policies to verify")

    def test_certificate_extension_not_found(self):
        policy_ = policy.AllOf([policy.Identity(identity="foo", issuer="bar")])
        cert_ = pretend.stub(
            extensions=pretend.stub(
                get_extension_for_oid=pretend.raiser(
                    ExtensionNotFound(oid=pretend.stub(), msg=pretend.stub())
                )
            )
        )

        result = policy_.verify(cert_)
        assert not result
        assert result == VerificationFailure(
            reason=(
                "1 of 1 policies failed: "
                "Certificate does not contain OIDCIssuer "
                "(1.3.6.1.4.1.57264.1.1) extension"
            )
        )

    def test_fails_not_all_children_match(self, signing_bundle):
        _, bundle = signing_bundle("bundle.txt")
        policy_ = policy.AllOf(
            [
                policy.Identity(identity="foo", issuer="bar"),
                policy.Identity(identity="baz", issuer="quux"),
                policy.Identity(
                    identity="a@tny.town",
                    issuer="https://github.com/login/oauth",
                ),
            ]
        )

        result = policy_.verify(bundle.signing_certificate)
        assert not result
        assert result == VerificationFailure(
            reason=(
                "2 of 3 policies failed: "
                "Certificate's OIDCIssuer does not match "
                "(got https://github.com/login/oauth, expected bar), "
                "Certificate's OIDCIssuer does not match "
                "(got https://github.com/login/oauth, expected quux)"
            )
        )

    def test_succeeds(self, signing_bundle):
        _, bundle = signing_bundle("bundle.txt")
        policy_ = policy.AllOf(
            [
                policy.Identity(
                    identity="a@tny.town",
                    issuer="https://github.com/login/oauth",
                ),
                policy.Identity(
                    identity="a@tny.town",
                    issuer="https://github.com/login/oauth",
                ),
            ]
        )

        result = policy_.verify(bundle.signing_certificate)
        assert result


class TestIdentity:
    def test_fails_no_san_match(self, signing_bundle):
        _, bundle = signing_bundle("bundle.txt")
        policy_ = policy.Identity(
            identity="bad@ident.example.com",
            issuer="https://github.com/login/oauth",
        )

        result = policy_.verify(bundle.signing_certificate)
        assert not result
        assert result == VerificationFailure(
            reason=(
                "Certificate's SANs do not match bad@ident.example.com; "
                "actual SANs: {'a@tny.town'}"
            )
        )
