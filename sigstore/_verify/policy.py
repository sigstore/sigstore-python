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
from typing import cast

try:
    from typing import Protocol
except ImportError:  # pragma: no cover
    # TODO(ww): Remove when our minimum Python is 3.8.
    from typing_extensions import Protocol  # type: ignore[assignment]

from cryptography.x509 import (
    Certificate,
    ExtensionNotFound,
    ObjectIdentifier,
    OtherName,
    RFC822Name,
    SubjectAlternativeName,
    UniformResourceIdentifier,
)

from sigstore._verify.models import (
    VerificationFailure,
    VerificationResult,
    VerificationSuccess,
)

logger = logging.getLogger(__name__)

# From: https://github.com/sigstore/fulcio/blob/main/docs/oid-info.md
_OIDC_ISSUER_OID = ObjectIdentifier("1.3.6.1.4.1.57264.1.1")
_OIDC_GITHUB_WORKFLOW_TRIGGER_OID = ObjectIdentifier("1.3.6.1.4.1.57264.1.2")
_OIDC_GITHUB_WORKFLOW_SHA_OID = ObjectIdentifier("1.3.6.1.4.1.57264.1.3")
_OIDC_GITHUB_WORKFLOW_NAME_OID = ObjectIdentifier("1.3.6.1.4.1.57264.1.4")
_OIDC_GITHUB_WORKFLOW_REPOSITORY_OID = ObjectIdentifier("1.3.6.1.4.1.57264.1.5")
_OIDC_GITHUB_WORKFLOW_REF_OID = ObjectIdentifier("1.3.6.1.4.1.57264.1.6")
_OTHERNAME_OID = ObjectIdentifier("1.3.6.1.4.1.57264.1.7")


class _SingleX509ExtPolicy(ABC):
    """
    An ABC for verification policies that boil down to checking a single
    X.509 extension's value.
    """

    oid: ObjectIdentifier
    """
    The OID of the extension being checked.
    """

    def __init__(self, value: str) -> None:
        """
        Creates the new policy, with `value` as the expected value during
        verification.
        """
        self._value = value

    def verify(self, cert: Certificate) -> VerificationResult:
        """
        Verify this policy against `cert`.
        """
        try:
            ext = cert.extensions.get_extension_for_oid(self.oid).value
        except ExtensionNotFound:
            return VerificationFailure(
                reason=(
                    f"Certificate does not contain {self.__class__.__name__} "
                    f"({self.oid.dotted_string}) extension"
                )
            )

        # NOTE(ww): mypy is confused by the `Extension[ExtensionType]` returned
        # by `get_extension_for_oid` above.
        ext_value = ext.value.decode()  # type: ignore[attr-defined]
        if ext_value != self._value:
            return VerificationFailure(
                reason=(
                    f"Certificate's {self.__class__.__name__} does not match "
                    f"(got {ext_value}, expected {self._value})"
                )
            )

        return VerificationSuccess()


class OIDCIssuer(_SingleX509ExtPolicy):
    """
    Verifies the certificate's OIDC issuer, identified by
    an X.509v3 extension tagged with `1.3.6.1.4.1.57264.1.1`.
    """

    oid = _OIDC_ISSUER_OID


class GitHubWorkflowTrigger(_SingleX509ExtPolicy):
    """
    Verifies the certificate's GitHub Actions workflow trigger,
    identified by an X.509v3 extension tagged with `1.3.6.1.4.1.57264.1.2`.
    """

    oid = _OIDC_GITHUB_WORKFLOW_TRIGGER_OID


class GitHubWorkflowSHA(_SingleX509ExtPolicy):
    """
    Verifies the certificate's GitHub Actions workflow commit SHA,
    identified by an X.509v3 extension tagged with `1.3.6.1.4.1.57264.1.3`.
    """

    oid = _OIDC_GITHUB_WORKFLOW_SHA_OID


class GitHubWorkflowName(_SingleX509ExtPolicy):
    """
    Verifies the certificate's GitHub Actions workflow name,
    identified by an X.509v3 extension tagged with `1.3.6.1.4.1.57264.1.4`.
    """

    oid = _OIDC_GITHUB_WORKFLOW_NAME_OID


class GitHubWorkflowRepository(_SingleX509ExtPolicy):
    """
    Verifies the certificate's GitHub Actions workflow repository,
    identified by an X.509v3 extension tagged with `1.3.6.1.4.1.57264.1.5`.
    """

    oid = _OIDC_GITHUB_WORKFLOW_REPOSITORY_OID


class GitHubWorkflowRef(_SingleX509ExtPolicy):
    """
    Verifies the certificate's GitHub Actions workflow ref,
    identified by an X.509v3 extension tagged with `1.3.6.1.4.1.57264.1.6`.
    """

    oid = _OIDC_GITHUB_WORKFLOW_REF_OID


class VerificationPolicy(Protocol):
    """
    A protocol type describing the interface that all verification policies
    conform to.
    """

    @abstractmethod
    def verify(self, cert: Certificate) -> VerificationResult:
        """
        Verify the given `cert` against this policy, returning a `VerificationResult`.
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

    def verify(self, cert: Certificate) -> VerificationResult:
        """
        Verify `cert` against the policy.
        """
        verified = any(child.verify(cert) for child in self._children)
        if verified:
            return VerificationSuccess()
        else:
            return VerificationFailure(
                reason=f"0 of {len(self._children)} policies succeeded"
            )


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

    def verify(self, cert: Certificate) -> VerificationResult:
        """
        Verify `cert` against the policy.
        """

        # Without this, we'd consider empty lists of child policies trivially valid.
        # This is almost certainly not what the user wants and is a potential
        # source of API misuse, so we explicitly disallow it.
        if len(self._children) < 1:
            return VerificationFailure(reason="no child policies to verify")

        # NOTE(ww): We need the cast here because MyPy can't tell that
        # `VerificationResult.__bool__` is invariant with
        # `VerificationSuccess | VerificationFailure`.
        results = [child.verify(cert) for child in self._children]
        failures = [
            cast(VerificationFailure, result).reason for result in results if not result
        ]
        if len(failures) > 0:
            inner_reasons = ", ".join(failures)
            return VerificationFailure(
                reason=f"{len(failures)} of {len(self._children)} policies failed: {inner_reasons}"
            )
        return VerificationSuccess()


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

    def verify(self, cert: Certificate) -> VerificationResult:
        """
        Verify `cert` against the policy.
        """

        logger.warning(
            "unsafe (no-op) verification policy used! no verification performed!"
        )
        return VerificationSuccess()


class Identity:
    """
    Verifies the certificate's "identity", corresponding to the X.509v3 SAN.
    Identities are verified modulo an OIDC issuer, so the issuer's URI
    is also required.

    Supported SAN types include emails, URIs, and Sigstore-specific "other names".
    """

    def __init__(self, *, identity: str, issuer: str):
        """
        Create a new `Identity`, with the given expected identity and issuer values.
        """

        self._identity = identity
        self._issuer = OIDCIssuer(issuer)

    def verify(self, cert: Certificate) -> VerificationResult:
        """
        Verify `cert` against the policy.
        """

        issuer_verified: VerificationResult = self._issuer.verify(cert)
        if not issuer_verified:
            return issuer_verified

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
            return VerificationFailure(
                reason=f"Certificate's SANs do not match {self._identity}; actual SANs: {all_sans}"
            )

        return VerificationSuccess()
