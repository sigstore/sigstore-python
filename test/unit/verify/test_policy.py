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

import re

import pretend
import pytest
from cryptography.x509 import ExtensionNotFound

from sigstore.errors import VerificationError
from sigstore.verify import policy


class TestVerificationPolicy:
    def test_does_not_init(self):
        with pytest.raises(TypeError, match="Can't instantiate abstract class"):
            policy.VerificationPolicy(pretend.stub())


class TestUnsafeNoOp:
    def test_succeeds(self, monkeypatch):
        logger = pretend.stub(warning=pretend.call_recorder(lambda s: None))
        monkeypatch.setattr(policy, "_logger", logger)

        policy_ = policy.UnsafeNoOp()
        policy_.verify(pretend.stub())
        assert logger.warning.calls == [
            pretend.call(
                "unsafe (no-op) verification policy used! no verification performed!"
            )
        ]


class TestAnyOf:
    def test_trivially_false(self):
        policy_ = policy.AnyOf([])

        with pytest.raises(VerificationError, match="0 of 0 policies succeeded"):
            policy_.verify(pretend.stub())

    def test_fails_no_children_match(self, signing_bundle):
        _, bundle = signing_bundle("bundle.txt")
        policy_ = policy.AnyOf(
            [
                policy.Identity(identity="foo", issuer="bar"),
                policy.Identity(identity="baz", issuer="quux"),
            ]
        )

        with pytest.raises(VerificationError, match="0 of 2 policies succeeded"):
            policy_.verify(bundle.signing_certificate)

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

        policy_.verify(bundle.signing_certificate)


class TestAllOf:
    def test_trivially_false(self):
        policy_ = policy.AllOf([])

        with pytest.raises(VerificationError, match="no child policies to verify"):
            policy_.verify(pretend.stub())

    def test_certificate_extension_not_found(self):
        policy_ = policy.AllOf([policy.Identity(identity="foo", issuer="bar")])
        cert_ = pretend.stub(
            extensions=pretend.stub(
                get_extension_for_oid=pretend.raiser(
                    ExtensionNotFound(oid=pretend.stub(), msg=pretend.stub())
                )
            )
        )

        reason = re.escape(
            "Certificate does not contain OIDCIssuer "
            "(1.3.6.1.4.1.57264.1.1) extension"
        )
        with pytest.raises(VerificationError, match=reason):
            policy_.verify(cert_)

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

        with pytest.raises(
            VerificationError,
            match="Certificate's OIDCIssuer does not match",
        ):
            policy_.verify(bundle.signing_certificate)

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

        policy_.verify(bundle.signing_certificate)


class TestIdentity:
    def test_fails_no_san_match(self, signing_bundle):
        _, bundle = signing_bundle("bundle.txt")
        policy_ = policy.Identity(
            identity="bad@ident.example.com",
            issuer="https://github.com/login/oauth",
        )

        with pytest.raises(
            VerificationError,
            match="Certificate's SANs do not match",
        ):
            policy_.verify(bundle.signing_certificate)


class TestSingleExtPolicy:
    def test_succeeds(self, signing_bundle):
        _, bundle = signing_bundle("bundle_v3_github.whl")

        verification_policy_extensions = [
            policy.OIDCIssuer("https://token.actions.githubusercontent.com"),
            policy.GitHubWorkflowTrigger("release"),
            policy.GitHubWorkflowSHA("d8b4a6445f38c48b9137a8099706d9b8073146e4"),
            policy.GitHubWorkflowName("release"),
            policy.GitHubWorkflowRepository("trailofbits/rfc8785.py"),
            policy.GitHubWorkflowRef("refs/tags/v0.1.2"),
            policy.OIDCIssuerV2("https://token.actions.githubusercontent.com"),
            policy.OIDCBuildSignerURI(
                "https://github.com/trailofbits/rfc8785.py/.github/workflows/release.yml@refs/tags/v0.1.2"
            ),
            policy.OIDCBuildSignerDigest("d8b4a6445f38c48b9137a8099706d9b8073146e4"),
            policy.OIDCRunnerEnvironment("github-hosted"),
            policy.OIDCSourceRepositoryURI("https://github.com/trailofbits/rfc8785.py"),
            policy.OIDCSourceRepositoryDigest(
                "d8b4a6445f38c48b9137a8099706d9b8073146e4"
            ),
            policy.OIDCSourceRepositoryRef("refs/tags/v0.1.2"),
            policy.OIDCSourceRepositoryIdentifier("768213997"),
            policy.OIDCSourceRepositoryOwnerURI("https://github.com/trailofbits"),
            policy.OIDCSourceRepositoryOwnerIdentifier("2314423"),
            policy.OIDCBuildConfigURI(
                "https://github.com/trailofbits/rfc8785.py/.github/workflows/release.yml@refs/tags/v0.1.2"
            ),
            policy.OIDCBuildConfigDigest("d8b4a6445f38c48b9137a8099706d9b8073146e4"),
            policy.OIDCBuildTrigger("release"),
            policy.OIDCRunInvocationURI(
                "https://github.com/trailofbits/rfc8785.py/actions/runs/8351058501/attempts/1"
            ),
            policy.OIDCSourceRepositoryVisibility("public"),
        ]

        policy_ = policy.AllOf(verification_policy_extensions)
        policy_.verify(bundle.signing_certificate)
