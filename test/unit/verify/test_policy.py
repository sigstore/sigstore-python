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

    def test_v1_only_custom_policy_compat(self, signing_bundle):
        _, bundle = signing_bundle("bundle.txt")

        class CertOnlyPolicy:
            def verify(self, cert) -> None:
                return

        cert_only: policy.VerificationPolicy = CertOnlyPolicy()

        # Continues to work in v1 AllOf / AnyOf
        policy.AllOf([cert_only]).verify(bundle.signing_certificate)
        policy.AnyOf([cert_only]).verify(bundle.signing_certificate)

        # Fails closed with VerificationError (not AttributeError) for v2 claims
        with pytest.raises(
            VerificationError,
            match="CertOnlyPolicy does not support claims verification",
        ):
            policy.AllOf([cert_only]).verify_claims({})

        with pytest.raises(VerificationError, match="0 of 1 policies succeeded"):
            policy.AnyOf([cert_only]).verify_claims({})

        # AnyOf skips unsupported children and succeeds if another child matches
        policy.AnyOf(
            [cert_only, policy.OIDCIssuer("https://example.com")]
        ).verify_claims({"issuer": "https://example.com"})

    def test_custom_policy_with_verify_claims(self, signing_bundle):
        _, bundle = signing_bundle("bundle.txt")

        class DualPolicy:
            def verify(self, cert) -> None:
                return

            def verify_claims(self, claims) -> None:
                if claims.get("custom") != "ok":
                    raise VerificationError("custom mismatch")

        dual: policy.VerificationPolicy = DualPolicy()
        policy.AllOf([dual]).verify(bundle.signing_certificate)
        policy.AllOf([dual]).verify_claims({"custom": "ok"})
        with pytest.raises(VerificationError, match="custom mismatch"):
            policy.AllOf([dual]).verify_claims({})


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

    def test_verify_claims_succeeds(self, monkeypatch):
        logger = pretend.stub(warning=pretend.call_recorder(lambda s: None))
        monkeypatch.setattr(policy, "_logger", logger)

        policy_ = policy.UnsafeNoOp()
        policy_.verify_claims({})
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

    def test_verify_claims_trivially_false(self):
        policy_ = policy.AnyOf([])

        with pytest.raises(VerificationError, match="0 of 0 policies succeeded"):
            policy_.verify_claims({})

    def test_verify_claims_fails_no_children_match(self):
        policy_ = policy.AnyOf(
            [
                policy.Identity(identity="foo", issuer="bar"),
                policy.Identity(identity="baz", issuer="quux"),
            ]
        )

        with pytest.raises(VerificationError, match="0 of 2 policies succeeded"):
            policy_.verify_claims(
                {
                    "identity": "a@tny.town",
                    "issuer": "https://github.com/login/oauth",
                }
            )

    def test_verify_claims_succeeds(self):
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

        policy_.verify_claims(
            {
                "identity": "a@tny.town",
                "issuer": "https://github.com/login/oauth",
            }
        )

    def test_verify_claims_skips_deprecated_v1_child(self):
        policy_ = policy.AnyOf(
            [
                policy.GitHubWorkflowTrigger("push"),
                policy.OIDCBuildTrigger("push"),
            ]
        )

        policy_.verify_claims({"build-trigger": "push"})


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
            "Certificate does not contain OIDCIssuer (1.3.6.1.4.1.57264.1.1) extension"
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

    def test_verify_claims_trivially_false(self):
        policy_ = policy.AllOf([])

        with pytest.raises(VerificationError, match="no child policies to verify"):
            policy_.verify_claims({})

    def test_verify_claims_fails_not_all_children_match(self):
        policy_ = policy.AllOf(
            [
                policy.Identity(
                    identity="a@tny.town",
                    issuer="https://github.com/login/oauth",
                ),
                policy.Identity(identity="foo", issuer="bar"),
            ]
        )

        with pytest.raises(
            VerificationError,
            match="Claim OIDCIssuer \\('issuer'\\) does not match",
        ):
            policy_.verify_claims(
                {
                    "identity": "a@tny.town",
                    "issuer": "https://github.com/login/oauth",
                }
            )

    def test_verify_claims_succeeds(self):
        policy_ = policy.AllOf(
            [
                policy.Identity(
                    identity="a@tny.town",
                    issuer="https://github.com/login/oauth",
                ),
                policy.OIDCRunnerEnvironment("github-hosted"),
            ]
        )

        policy_.verify_claims(
            {
                "identity": "a@tny.town",
                "issuer": "https://github.com/login/oauth",
                "runner-environment": "github-hosted",
            }
        )


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

    @pytest.mark.parametrize("issuer", [None, ""])
    def test_verify_claims_without_issuer_in_policy(self, issuer):
        policy_ = policy.Identity(identity="a@tny.town", issuer=issuer)
        policy_.verify_claims(
            {
                "identity": "a@tny.town",
                "issuer": "https://github.com/login/oauth",
            }
        )

        # Matches v1 AllOf([OIDCIssuer(...), Identity(identity=..., issuer=None)]) composition
        composed = policy.AllOf(
            [
                policy.OIDCIssuerV2("https://github.com/login/oauth"),
                policy_,
            ]
        )
        composed.verify_claims(
            {
                "identity": "a@tny.town",
                "issuer": "https://github.com/login/oauth",
            }
        )

    def test_verify_claims_missing_issuer_claim(self):
        policy_ = policy.Identity(
            identity="a@tny.town",
            issuer="https://github.com/login/oauth",
        )

        with pytest.raises(
            VerificationError,
            match="Claims do not contain OIDCIssuer \\('issuer'\\) claim",
        ):
            policy_.verify_claims({"identity": "a@tny.town"})

    def test_verify_claims_issuer_mismatch(self):
        policy_ = policy.Identity(
            identity="a@tny.town",
            issuer="https://github.com/login/oauth",
        )

        with pytest.raises(
            VerificationError,
            match="Claim OIDCIssuer \\('issuer'\\) does not match",
        ):
            policy_.verify_claims(
                {
                    "identity": "a@tny.town",
                    "issuer": "https://accounts.google.com",
                }
            )

    def test_verify_claims_missing_identity_claim(self):
        policy_ = policy.Identity(
            identity="a@tny.town",
            issuer="https://github.com/login/oauth",
        )

        with pytest.raises(
            VerificationError,
            match="Claims do not contain 'identity' claim",
        ):
            policy_.verify_claims({"issuer": "https://github.com/login/oauth"})

    def test_verify_claims_identity_mismatch(self):
        policy_ = policy.Identity(
            identity="bad@ident.example.com",
            issuer="https://github.com/login/oauth",
        )

        with pytest.raises(
            VerificationError,
            match="Claim 'identity' does not match \\(got 'a@tny.town', expected 'bad@ident.example.com'\\)",
        ):
            policy_.verify_claims(
                {
                    "identity": "a@tny.town",
                    "issuer": "https://github.com/login/oauth",
                }
            )

    def test_verify_claims_succeeds(self):
        policy_ = policy.Identity(
            identity="a@tny.town",
            issuer="https://github.com/login/oauth",
        )

        policy_.verify_claims(
            {
                "identity": "a@tny.town",
                "issuer": "https://github.com/login/oauth",
            }
        )


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

    def test_verify_claims_succeeds(self):
        claims = {
            "issuer": "https://token.actions.githubusercontent.com",
            "build-signer-uri": "https://github.com/trailofbits/rfc8785.py/.github/workflows/release.yml@refs/tags/v0.1.2",
            "build-signer-digest": "d8b4a6445f38c48b9137a8099706d9b8073146e4",
            "runner-environment": "github-hosted",
            "source-repository-uri": "https://github.com/trailofbits/rfc8785.py",
            "source-repository-digest": "d8b4a6445f38c48b9137a8099706d9b8073146e4",
            "source-repository-ref": "refs/tags/v0.1.2",
            "source-repository-identifier": "768213997",
            "source-repository-owner-uri": "https://github.com/trailofbits",
            "source-repository-owner-identifier": "2314423",
            "build-config-uri": "https://github.com/trailofbits/rfc8785.py/.github/workflows/release.yml@refs/tags/v0.1.2",
            "build-config-digest": "d8b4a6445f38c48b9137a8099706d9b8073146e4",
            "build-trigger": "release",
            "run-invocation-uri": "https://github.com/trailofbits/rfc8785.py/actions/runs/8351058501/attempts/1",
            "source-repository-visibility-at-signing": "public",
        }

        verification_policy_extensions = [
            policy.OIDCIssuer("https://token.actions.githubusercontent.com"),
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
        policy_.verify_claims(claims)

    @pytest.mark.parametrize(
        "deprecated_cls",
        [
            policy.GitHubWorkflowTrigger,
            policy.GitHubWorkflowSHA,
            policy.GitHubWorkflowName,
            policy.GitHubWorkflowRepository,
            policy.GitHubWorkflowRef,
        ],
    )
    def test_verify_claims_deprecated_v1_extension(self, deprecated_cls):
        policy_ = deprecated_cls("value")
        with pytest.raises(
            VerificationError,
            match="is a deprecated Fulcio v1 extension and is not supported in v2 claims",
        ):
            policy_.verify_claims({})

    def test_verify_claims_missing_claim(self):
        policy_ = policy.OIDCRunnerEnvironment("github-hosted")
        with pytest.raises(
            VerificationError,
            match="Claims do not contain OIDCRunnerEnvironment \\('runner-environment'\\) claim",
        ):
            policy_.verify_claims({})

    def test_verify_claims_mismatch(self):
        policy_ = policy.OIDCRunnerEnvironment("github-hosted")
        with pytest.raises(
            VerificationError,
            match="Claim OIDCRunnerEnvironment \\('runner-environment'\\) does not match \\(got 'self-hosted', expected 'github-hosted'\\)",
        ):
            policy_.verify_claims({"runner-environment": "self-hosted"})
