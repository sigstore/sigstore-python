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
APIs for describing identity verification "policies", which describe how the identities
passed into an individual verification step are verified.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from collections.abc import Mapping
from typing import Protocol

from cryptography.hazmat import asn1
from cryptography.x509 import (
    Certificate,
    ExtensionNotFound,
    ObjectIdentifier,
    OtherName,
    RFC822Name,
    SubjectAlternativeName,
    UniformResourceIdentifier,
)

from sigstore.errors import VerificationError

_logger = logging.getLogger(__name__)

# From: https://github.com/sigstore/fulcio/blob/main/docs/oid-info.md
# and https://github.com/sigstore/fulcio/blob/main/pkg/certificate/extensions.go
# Each tuple maps an OIDC attribute to (X.509 ObjectIdentifier, C2SP tlog-proof claim name).
_OIDC_ISSUER = (ObjectIdentifier("1.3.6.1.4.1.57264.1.1"), "issuer")
_OIDC_GITHUB_WORKFLOW_TRIGGER = (
    ObjectIdentifier("1.3.6.1.4.1.57264.1.2"),
    None,
)
_OIDC_GITHUB_WORKFLOW_SHA = (ObjectIdentifier("1.3.6.1.4.1.57264.1.3"), None)
_OIDC_GITHUB_WORKFLOW_NAME = (ObjectIdentifier("1.3.6.1.4.1.57264.1.4"), None)
_OIDC_GITHUB_WORKFLOW_REPOSITORY = (
    ObjectIdentifier("1.3.6.1.4.1.57264.1.5"),
    None,
)
_OIDC_GITHUB_WORKFLOW_REF = (ObjectIdentifier("1.3.6.1.4.1.57264.1.6"), None)
_OTHERNAME_OID = ObjectIdentifier("1.3.6.1.4.1.57264.1.7")
_OIDC_ISSUER_V2 = (ObjectIdentifier("1.3.6.1.4.1.57264.1.8"), "issuer")
_OIDC_BUILD_SIGNER_URI = (
    ObjectIdentifier("1.3.6.1.4.1.57264.1.9"),
    "build-signer-uri",
)
_OIDC_BUILD_SIGNER_DIGEST = (
    ObjectIdentifier("1.3.6.1.4.1.57264.1.10"),
    "build-signer-digest",
)
_OIDC_RUNNER_ENVIRONMENT = (
    ObjectIdentifier("1.3.6.1.4.1.57264.1.11"),
    "runner-environment",
)
_OIDC_SOURCE_REPOSITORY_URI = (
    ObjectIdentifier("1.3.6.1.4.1.57264.1.12"),
    "source-repository-uri",
)
_OIDC_SOURCE_REPOSITORY_DIGEST = (
    ObjectIdentifier("1.3.6.1.4.1.57264.1.13"),
    "source-repository-digest",
)
_OIDC_SOURCE_REPOSITORY_REF = (
    ObjectIdentifier("1.3.6.1.4.1.57264.1.14"),
    "source-repository-ref",
)
_OIDC_SOURCE_REPOSITORY_IDENTIFIER = (
    ObjectIdentifier("1.3.6.1.4.1.57264.1.15"),
    "source-repository-identifier",
)
_OIDC_SOURCE_REPOSITORY_OWNER_URI = (
    ObjectIdentifier("1.3.6.1.4.1.57264.1.16"),
    "source-repository-owner-uri",
)
_OIDC_SOURCE_REPOSITORY_OWNER_IDENTIFIER = (
    ObjectIdentifier("1.3.6.1.4.1.57264.1.17"),
    "source-repository-owner-identifier",
)
_OIDC_BUILD_CONFIG_URI = (
    ObjectIdentifier("1.3.6.1.4.1.57264.1.18"),
    "build-config-uri",
)
_OIDC_BUILD_CONFIG_DIGEST = (
    ObjectIdentifier("1.3.6.1.4.1.57264.1.19"),
    "build-config-digest",
)
_OIDC_BUILD_TRIGGER = (
    ObjectIdentifier("1.3.6.1.4.1.57264.1.20"),
    "build-trigger",
)
_OIDC_RUN_INVOCATION_URI = (
    ObjectIdentifier("1.3.6.1.4.1.57264.1.21"),
    "run-invocation-uri",
)
_OIDC_SOURCE_REPOSITORY_VISIBILITY = (
    ObjectIdentifier("1.3.6.1.4.1.57264.1.22"),
    "source-repository-visibility-at-signing",
)


class _SingleClaimPolicy(ABC):
    """
    An ABC for verification policies that check a single OIDC identity claim,
    represented either as an X.509 extension in a Fulcio certificate or as a
    claim in a `c2sp.org/tlog-proof@v1` `extra` map.
    """

    oid: ObjectIdentifier
    """
    The OID of the X.509 extension being checked.
    """

    claim_name: str | None = None
    """
    The claim key in a `c2sp.org/tlog-proof@v1` `extra` map corresponding to
    this attribute, or `None` if this attribute is not present in v2 claims.
    """

    def __init__(self, value: str) -> None:
        """
        Creates the new policy, with `value` as the expected value during
        verification.
        """
        self._value = value

    def verify(self, cert: Certificate) -> None:
        """
        Verify this policy against `cert`.

        Raises `VerificationError` on failure.
        """
        try:
            ext = cert.extensions.get_extension_for_oid(self.oid).value
        except ExtensionNotFound:
            raise VerificationError(
                f"Certificate does not contain {self.__class__.__name__} "
                f"({self.oid.dotted_string}) extension"
            )

        # NOTE(ww): mypy is confused by the `Extension[ExtensionType]` returned
        # by `get_extension_for_oid` above.
        ext_value = ext.value.decode()  # type: ignore[attr-defined]
        if ext_value != self._value:
            raise VerificationError(
                f"Certificate's {self.__class__.__name__} does not match "
                f"(got '{ext_value}', expected '{self._value}')"
            )

    def verify_claims(self, claims: Mapping[str, str]) -> None:
        """
        Verify this policy against a `c2sp.org/tlog-proof@v1` claims mapping.

        Raises `VerificationError` on failure.
        """
        if self.claim_name is None:
            raise VerificationError(
                f"{self.__class__.__name__} ({self.oid.dotted_string}) is a "
                "deprecated Fulcio v1 extension and is not supported in v2 claims"
            )

        if self.claim_name not in claims:
            raise VerificationError(
                f"Claims do not contain {self.__class__.__name__} "
                f"('{self.claim_name}') claim"
            )

        claim_value = claims[self.claim_name]
        if claim_value != self._value:
            raise VerificationError(
                f"Claim {self.__class__.__name__} ('{self.claim_name}') does not match "
                f"(got '{claim_value}', expected '{self._value}')"
            )


class _SingleClaimPolicyV2(_SingleClaimPolicy):
    """
    A base class for verification policies that check a single OIDC identity
    claim, where the X.509 extension value is formatted as a DER-encoded string
    with ASN.1 tag UTF8String (0x0C) and universal tag class.
    """

    def verify(self, cert: Certificate) -> None:
        """
        Verify this policy against `cert`.

        Raises `VerificationError` on failure.
        """
        try:
            ext = cert.extensions.get_extension_for_oid(self.oid).value
        except ExtensionNotFound:
            raise VerificationError(
                f"Certificate does not contain {self.__class__.__name__} "
                f"({self.oid.dotted_string}) extension"
            )

        # NOTE(ww): mypy is confused by the `Extension[ExtensionType]` returned
        # by `get_extension_for_oid` above.
        ext_value = asn1.decode_der(str, ext.value)  # type: ignore[attr-defined]
        if ext_value != self._value:
            raise VerificationError(
                f"Certificate's {self.__class__.__name__} does not match "
                f"(got {ext_value}, expected {self._value})"
            )


class OIDCIssuer(_SingleClaimPolicy):
    """
    Verifies the certificate's OIDC issuer, identified by
    an X.509v3 extension tagged with `1.3.6.1.4.1.57264.1.1`.
    """

    oid, claim_name = _OIDC_ISSUER


class GitHubWorkflowTrigger(_SingleClaimPolicy):
    """
    Verifies the certificate's GitHub Actions workflow trigger,
    identified by an X.509v3 extension tagged with `1.3.6.1.4.1.57264.1.2`.
    """

    oid, claim_name = _OIDC_GITHUB_WORKFLOW_TRIGGER


class GitHubWorkflowSHA(_SingleClaimPolicy):
    """
    Verifies the certificate's GitHub Actions workflow commit SHA,
    identified by an X.509v3 extension tagged with `1.3.6.1.4.1.57264.1.3`.
    """

    oid, claim_name = _OIDC_GITHUB_WORKFLOW_SHA


class GitHubWorkflowName(_SingleClaimPolicy):
    """
    Verifies the certificate's GitHub Actions workflow name,
    identified by an X.509v3 extension tagged with `1.3.6.1.4.1.57264.1.4`.
    """

    oid, claim_name = _OIDC_GITHUB_WORKFLOW_NAME


class GitHubWorkflowRepository(_SingleClaimPolicy):
    """
    Verifies the certificate's GitHub Actions workflow repository,
    identified by an X.509v3 extension tagged with `1.3.6.1.4.1.57264.1.5`.
    """

    oid, claim_name = _OIDC_GITHUB_WORKFLOW_REPOSITORY


class GitHubWorkflowRef(_SingleClaimPolicy):
    """
    Verifies the certificate's GitHub Actions workflow ref,
    identified by an X.509v3 extension tagged with `1.3.6.1.4.1.57264.1.6`.
    """

    oid, claim_name = _OIDC_GITHUB_WORKFLOW_REF


class OIDCIssuerV2(_SingleClaimPolicyV2):
    """
    Verifies the certificate's OIDC issuer, identified by
    an X.509v3 extension tagged with `1.3.6.1.4.1.57264.1.8`.
    The difference with `OIDCIssuer` is that the value for
    this extension is formatted to the RFC 5280 specification
    as a DER-encoded string.
    """

    oid, claim_name = _OIDC_ISSUER_V2


class OIDCBuildSignerURI(_SingleClaimPolicyV2):
    """
    Verifies the certificate's OIDC Build Signer URI, identified by
    an X.509v3 extension tagged with `1.3.6.1.4.1.57264.1.9`.
    """

    oid, claim_name = _OIDC_BUILD_SIGNER_URI


class OIDCBuildSignerDigest(_SingleClaimPolicyV2):
    """
    Verifies the certificate's OIDC Build Signer Digest, identified by
    an X.509v3 extension tagged with `1.3.6.1.4.1.57264.1.10`.
    """

    oid, claim_name = _OIDC_BUILD_SIGNER_DIGEST


class OIDCRunnerEnvironment(_SingleClaimPolicyV2):
    """
    Verifies the certificate's OIDC Runner Environment, identified by
    an X.509v3 extension tagged with `1.3.6.1.4.1.57264.1.11`.
    """

    oid, claim_name = _OIDC_RUNNER_ENVIRONMENT


class OIDCSourceRepositoryURI(_SingleClaimPolicyV2):
    """
    Verifies the certificate's OIDC Source Repository URI, identified by
    an X.509v3 extension tagged with `1.3.6.1.4.1.57264.1.12`.
    """

    oid, claim_name = _OIDC_SOURCE_REPOSITORY_URI


class OIDCSourceRepositoryDigest(_SingleClaimPolicyV2):
    """
    Verifies the certificate's OIDC Source Repository Digest, identified by
    an X.509v3 extension tagged with `1.3.6.1.4.1.57264.1.13`.
    """

    oid, claim_name = _OIDC_SOURCE_REPOSITORY_DIGEST


class OIDCSourceRepositoryRef(_SingleClaimPolicyV2):
    """
    Verifies the certificate's OIDC Source Repository Ref, identified by
    an X.509v3 extension tagged with `1.3.6.1.4.1.57264.1.14`.
    """

    oid, claim_name = _OIDC_SOURCE_REPOSITORY_REF


class OIDCSourceRepositoryIdentifier(_SingleClaimPolicyV2):
    """
    Verifies the certificate's OIDC Source Repository Identifier, identified by
    an X.509v3 extension tagged with `1.3.6.1.4.1.57264.1.15`.
    """

    oid, claim_name = _OIDC_SOURCE_REPOSITORY_IDENTIFIER


class OIDCSourceRepositoryOwnerURI(_SingleClaimPolicyV2):
    """
    Verifies the certificate's OIDC Source Repository Owner URI, identified by
    an X.509v3 extension tagged with `1.3.6.1.4.1.57264.1.16`.
    """

    oid, claim_name = _OIDC_SOURCE_REPOSITORY_OWNER_URI


class OIDCSourceRepositoryOwnerIdentifier(_SingleClaimPolicyV2):
    """
    Verifies the certificate's OIDC Source Repository Owner Identifier, identified by
    an X.509v3 extension tagged with `1.3.6.1.4.1.57264.1.17`.
    """

    oid, claim_name = _OIDC_SOURCE_REPOSITORY_OWNER_IDENTIFIER


class OIDCBuildConfigURI(_SingleClaimPolicyV2):
    """
    Verifies the certificate's OIDC Build Config URI, identified by
    an X.509v3 extension tagged with `1.3.6.1.4.1.57264.1.18`.
    """

    oid, claim_name = _OIDC_BUILD_CONFIG_URI


class OIDCBuildConfigDigest(_SingleClaimPolicyV2):
    """
    Verifies the certificate's OIDC Build Config Digest, identified by
    an X.509v3 extension tagged with `1.3.6.1.4.1.57264.1.19`.
    """

    oid, claim_name = _OIDC_BUILD_CONFIG_DIGEST


class OIDCBuildTrigger(_SingleClaimPolicyV2):
    """
    Verifies the certificate's OIDC Build Trigger, identified by
    an X.509v3 extension tagged with `1.3.6.1.4.1.57264.1.20`.
    """

    oid, claim_name = _OIDC_BUILD_TRIGGER


class OIDCRunInvocationURI(_SingleClaimPolicyV2):
    """
    Verifies the certificate's OIDC Run Invocation URI, identified by
    an X.509v3 extension tagged with `1.3.6.1.4.1.57264.1.21`.
    """

    oid, claim_name = _OIDC_RUN_INVOCATION_URI


class OIDCSourceRepositoryVisibility(_SingleClaimPolicyV2):
    """
    Verifies the certificate's OIDC Source Repository Visibility
    At Signing, identified by an X.509v3 extension tagged with
    `1.3.6.1.4.1.57264.1.22`.
    """

    oid, claim_name = _OIDC_SOURCE_REPOSITORY_VISIBILITY


class VerificationPolicy(Protocol):
    """
    A protocol type describing the interface that all verification policies
    conform to.
    """

    @abstractmethod
    def verify(self, cert: Certificate) -> None:
        """
        Verify the given `cert` against this policy, raising `VerificationError`
        on failure.
        """
        raise NotImplementedError  # pragma: no cover

    @abstractmethod
    def verify_claims(self, claims: Mapping[str, str]) -> None:
        """
        Verify the given `c2sp.org/tlog-proof@v1` `claims` against this policy,
        raising `VerificationError` on failure.
        """
        raise NotImplementedError  # pragma: no cover


class AnyOf:
    """
    The "any of" policy, corresponding to a logical OR between child policies.

    An empty list of child policies is considered trivially invalid.
    """

    def __init__(self, children: list[VerificationPolicy]):
        """
        Create a new `AnyOf`, with the given child policies.
        """
        self._children = children

    def verify(self, cert: Certificate) -> None:
        """
        Verify `cert` against the policy.

        Raises `VerificationError` on failure.
        """

        for child in self._children:
            try:
                child.verify(cert)
            except VerificationError:
                pass
            else:
                return

        raise VerificationError(f"0 of {len(self._children)} policies succeeded")

    def verify_claims(self, claims: Mapping[str, str]) -> None:
        """
        Verify `claims` against the policy.

        Raises `VerificationError` on failure.
        """

        for child in self._children:
            try:
                child.verify_claims(claims)
            except VerificationError:
                pass
            else:
                return

        raise VerificationError(f"0 of {len(self._children)} policies succeeded")


class AllOf:
    """
    The "all of" policy, corresponding to a logical AND between child
    policies.

    An empty list of child policies is considered trivially invalid.
    """

    def __init__(self, children: list[VerificationPolicy]):
        """
        Create a new `AllOf`, with the given child policies.
        """

        self._children = children

    def verify(self, cert: Certificate) -> None:
        """
        Verify `cert` against the policy.
        """

        # Without this, we'd consider empty lists of child policies trivially valid.
        # This is almost certainly not what the user wants and is a potential
        # source of API misuse, so we explicitly disallow it.
        if len(self._children) < 1:
            raise VerificationError("no child policies to verify")

        for child in self._children:
            child.verify(cert)

    def verify_claims(self, claims: Mapping[str, str]) -> None:
        """
        Verify `claims` against the policy.
        """

        if len(self._children) < 1:
            raise VerificationError("no child policies to verify")

        for child in self._children:
            child.verify_claims(claims)


class UnsafeNoOp:
    """
    The "no-op" policy, corresponding to a no-op "verification".

    **This policy is fundamentally insecure. You cannot use it safely.
    It must not be used to verify any sort of certificate identity, because
    it cannot do so. Using this policy is equivalent to reducing the
    verification proof down to an integrity check against a completely
    untrusted and potentially attacker-created signature. It must only
    be used for testing purposes.**
    """

    def verify(self, cert: Certificate) -> None:
        """
        Verify `cert` against the policy.
        """

        _logger.warning(
            "unsafe (no-op) verification policy used! no verification performed!"
        )

    def verify_claims(self, claims: Mapping[str, str]) -> None:
        """
        Verify `claims` against the policy.
        """

        _logger.warning(
            "unsafe (no-op) verification policy used! no verification performed!"
        )


class Identity:
    """
    Verifies the certificate's "identity", corresponding to the X.509v3 SAN.

    Identities can be verified modulo an OIDC issuer, to prevent an unexpected
    issuer from offering a particular identity.

    Supported SAN types include emails, URIs, and Sigstore-specific "other names".
    """

    _issuer: OIDCIssuer | None

    def __init__(self, *, identity: str, issuer: str | None = None):
        """
        Create a new `Identity`, with the given expected identity and issuer values.
        """

        self._identity = identity
        if issuer:
            self._issuer = OIDCIssuer(issuer)
        else:
            self._issuer = None

    def verify(self, cert: Certificate) -> None:
        """
        Verify `cert` against the policy.
        """

        if self._issuer:
            self._issuer.verify(cert)

        # Build a set of all valid identities.
        san_ext = cert.extensions.get_extension_for_class(SubjectAlternativeName).value
        all_sans = set(san_ext.get_values_for_type(RFC822Name))
        all_sans.update(san_ext.get_values_for_type(UniformResourceIdentifier))
        all_sans.update(
            [
                on.value.decode()
                for on in san_ext.get_values_for_type(OtherName)
                if on.type_id == _OTHERNAME_OID
            ]
        )

        verified = self._identity in all_sans
        if not verified:
            raise VerificationError(
                f"Certificate's SANs do not match {self._identity}; actual SANs: {all_sans}"
            )

    def verify_claims(self, claims: Mapping[str, str]) -> None:
        """
        Verify `claims` against the policy.

        In `c2sp.org/identity-transparency/v1`, the OIDC issuer is the leaf's
        `root_of_trust`, so `issuer` must be specified in the policy when
        verifying claims.
        """

        if self._issuer is None:
            raise VerificationError(
                "Identity policy must specify an issuer when verifying claims"
            )
        self._issuer.verify_claims(claims)

        if "identity" not in claims:
            raise VerificationError("Claims do not contain 'identity' claim")

        actual_identity = claims["identity"]
        if actual_identity != self._identity:
            raise VerificationError(
                f"Claim 'identity' does not match (got '{actual_identity}', expected '{self._identity}')"
            )
