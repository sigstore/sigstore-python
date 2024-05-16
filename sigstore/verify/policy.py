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
from typing import Protocol

from cryptography.x509 import (
    Certificate,
    ExtensionNotFound,
    ObjectIdentifier,
    OtherName,
    RFC822Name,
    SubjectAlternativeName,
    UniformResourceIdentifier,
)
from pyasn1.codec.der.decoder import decode as der_decode
from pyasn1.type.char import UTF8String

from sigstore.errors import VerificationError

_logger = logging.getLogger(__name__)

# From: https://github.com/sigstore/fulcio/blob/main/docs/oid-info.md
_OIDC_ISSUER_OID = ObjectIdentifier("1.3.6.1.4.1.57264.1.1")
_OIDC_GITHUB_WORKFLOW_TRIGGER_OID = ObjectIdentifier("1.3.6.1.4.1.57264.1.2")
_OIDC_GITHUB_WORKFLOW_SHA_OID = ObjectIdentifier("1.3.6.1.4.1.57264.1.3")
_OIDC_GITHUB_WORKFLOW_NAME_OID = ObjectIdentifier("1.3.6.1.4.1.57264.1.4")
_OIDC_GITHUB_WORKFLOW_REPOSITORY_OID = ObjectIdentifier("1.3.6.1.4.1.57264.1.5")
_OIDC_GITHUB_WORKFLOW_REF_OID = ObjectIdentifier("1.3.6.1.4.1.57264.1.6")
_OTHERNAME_OID = ObjectIdentifier("1.3.6.1.4.1.57264.1.7")
_OIDC_ISSUER_V2_OID = ObjectIdentifier("1.3.6.1.4.1.57264.1.8")
_OIDC_BUILD_SIGNER_URI_OID = ObjectIdentifier("1.3.6.1.4.1.57264.1.9")
_OIDC_BUILD_SIGNER_DIGEST_OID = ObjectIdentifier("1.3.6.1.4.1.57264.1.10")
_OIDC_RUNNER_ENVIRONMENT_OID = ObjectIdentifier("1.3.6.1.4.1.57264.1.11")
_OIDC_SOURCE_REPOSITORY_URI_OID = ObjectIdentifier("1.3.6.1.4.1.57264.1.12")
_OIDC_SOURCE_REPOSITORY_DIGEST_OID = ObjectIdentifier("1.3.6.1.4.1.57264.1.13")
_OIDC_SOURCE_REPOSITORY_REF_OID = ObjectIdentifier("1.3.6.1.4.1.57264.1.14")
_OIDC_SOURCE_REPOSITORY_IDENTIFIER_OID = ObjectIdentifier("1.3.6.1.4.1.57264.1.15")
_OIDC_SOURCE_REPOSITORY_OWNER_URI_OID = ObjectIdentifier("1.3.6.1.4.1.57264.1.16")
_OIDC_SOURCE_REPOSITORY_OWNER_IDENTIFIER_OID = ObjectIdentifier(
    "1.3.6.1.4.1.57264.1.17"
)
_OIDC_BUILD_CONFIG_URI_OID = ObjectIdentifier("1.3.6.1.4.1.57264.1.18")
_OIDC_BUILD_CONFIG_DIGEST_OID = ObjectIdentifier("1.3.6.1.4.1.57264.1.19")
_OIDC_BUILD_TRIGGER_OID = ObjectIdentifier("1.3.6.1.4.1.57264.1.20")
_OIDC_RUN_INVOCATION_URI_OID = ObjectIdentifier("1.3.6.1.4.1.57264.1.21")
_OIDC_SOURCE_REPOSITORY_VISIBILITY_OID = ObjectIdentifier("1.3.6.1.4.1.57264.1.22")


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

    def verify(self, cert: Certificate) -> None:
        """
        Verify this policy against `cert`.

        Raises `VerificationError` on failure.
        """
        try:
            ext = cert.extensions.get_extension_for_oid(self.oid).value
        except ExtensionNotFound:
            raise VerificationError(
                (
                    f"Certificate does not contain {self.__class__.__name__} "
                    f"({self.oid.dotted_string}) extension"
                )
            )

        # NOTE(ww): mypy is confused by the `Extension[ExtensionType]` returned
        # by `get_extension_for_oid` above.
        ext_value = ext.value.decode()  # type: ignore[attr-defined]
        if ext_value != self._value:
            raise VerificationError(
                (
                    f"Certificate's {self.__class__.__name__} does not match "
                    f"(got '{ext_value}', expected '{self._value}')"
                )
            )


class _SingleX509ExtPolicyV2(_SingleX509ExtPolicy):
    """
    An base class for verification policies that boil down to checking a single
    X.509 extension's value, where the value is formatted as a DER-encoded string,
    the ASN.1 tag is UTF8String (0x0C) and the tag class is universal.
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
                (
                    f"Certificate does not contain {self.__class__.__name__} "
                    f"({self.oid.dotted_string}) extension"
                )
            )

        # NOTE(ww): mypy is confused by the `Extension[ExtensionType]` returned
        # by `get_extension_for_oid` above.
        ext_value = der_decode(ext.value, UTF8String)[0].decode()  # type: ignore[attr-defined]
        if ext_value != self._value:
            raise VerificationError(
                (
                    f"Certificate's {self.__class__.__name__} does not match "
                    f"(got {ext_value}, expected {self._value})"
                )
            )


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


class OIDCIssuerV2(_SingleX509ExtPolicyV2):
    """
    Verifies the certificate's OIDC issuer, identified by
    an X.509v3 extension tagged with `1.3.6.1.4.1.57264.1.8`.
    The difference with `OIDCIssuer` is that the value for
    this extension is formatted to the RFC 5280 specification
    as a DER-encoded string.
    """

    oid = _OIDC_ISSUER_V2_OID


class OIDCBuildSignerURI(_SingleX509ExtPolicyV2):
    """
    Verifies the certificate's OIDC Build Signer URI, identified by
    an X.509v3 extension tagged with `1.3.6.1.4.1.57264.1.9`.
    """

    oid = _OIDC_BUILD_SIGNER_URI_OID


class OIDCBuildSignerDigest(_SingleX509ExtPolicyV2):
    """
    Verifies the certificate's OIDC Build Signer Digest, identified by
    an X.509v3 extension tagged with `1.3.6.1.4.1.57264.1.10`.
    """

    oid = _OIDC_BUILD_SIGNER_DIGEST_OID


class OIDCRunnerEnvironment(_SingleX509ExtPolicyV2):
    """
    Verifies the certificate's OIDC Runner Environment, identified by
    an X.509v3 extension tagged with `1.3.6.1.4.1.57264.1.11`.
    """

    oid = _OIDC_RUNNER_ENVIRONMENT_OID


class OIDCSourceRepositoryURI(_SingleX509ExtPolicyV2):
    """
    Verifies the certificate's OIDC Source Repository URI, identified by
    an X.509v3 extension tagged with `1.3.6.1.4.1.57264.1.12`.
    """

    oid = _OIDC_SOURCE_REPOSITORY_URI_OID


class OIDCSourceRepositoryDigest(_SingleX509ExtPolicyV2):
    """
    Verifies the certificate's OIDC Source Repository Digest, identified by
    an X.509v3 extension tagged with `1.3.6.1.4.1.57264.1.13`.
    """

    oid = _OIDC_SOURCE_REPOSITORY_DIGEST_OID


class OIDCSourceRepositoryRef(_SingleX509ExtPolicyV2):
    """
    Verifies the certificate's OIDC Source Repository Ref, identified by
    an X.509v3 extension tagged with `1.3.6.1.4.1.57264.1.14`.
    """

    oid = _OIDC_SOURCE_REPOSITORY_REF_OID


class OIDCSourceRepositoryIdentifier(_SingleX509ExtPolicyV2):
    """
    Verifies the certificate's OIDC Source Repository Identifier, identified by
    an X.509v3 extension tagged with `1.3.6.1.4.1.57264.1.15`.
    """

    oid = _OIDC_SOURCE_REPOSITORY_IDENTIFIER_OID


class OIDCSourceRepositoryOwnerURI(_SingleX509ExtPolicyV2):
    """
    Verifies the certificate's OIDC Source Repository Owner URI, identified by
    an X.509v3 extension tagged with `1.3.6.1.4.1.57264.1.16`.
    """

    oid = _OIDC_SOURCE_REPOSITORY_OWNER_URI_OID


class OIDCSourceRepositoryOwnerIdentifier(_SingleX509ExtPolicyV2):
    """
    Verifies the certificate's OIDC Source Repository Owner Identifier, identified by
    an X.509v3 extension tagged with `1.3.6.1.4.1.57264.1.17`.
    """

    oid = _OIDC_SOURCE_REPOSITORY_OWNER_IDENTIFIER_OID


class OIDCBuildConfigURI(_SingleX509ExtPolicyV2):
    """
    Verifies the certificate's OIDC Build Config URI, identified by
    an X.509v3 extension tagged with `1.3.6.1.4.1.57264.1.18`.
    """

    oid = _OIDC_BUILD_CONFIG_URI_OID


class OIDCBuildConfigDigest(_SingleX509ExtPolicyV2):
    """
    Verifies the certificate's OIDC Build Config Digest, identified by
    an X.509v3 extension tagged with `1.3.6.1.4.1.57264.1.19`.
    """

    oid = _OIDC_BUILD_CONFIG_DIGEST_OID


class OIDCBuildTrigger(_SingleX509ExtPolicyV2):
    """
    Verifies the certificate's OIDC Build Trigger, identified by
    an X.509v3 extension tagged with `1.3.6.1.4.1.57264.1.20`.
    """

    oid = _OIDC_BUILD_TRIGGER_OID


class OIDCRunInvocationURI(_SingleX509ExtPolicyV2):
    """
    Verifies the certificate's OIDC Run Invocation URI, identified by
    an X.509v3 extension tagged with `1.3.6.1.4.1.57264.1.21`.
    """

    oid = _OIDC_RUN_INVOCATION_URI_OID


class OIDCSourceRepositoryVisibility(_SingleX509ExtPolicyV2):
    """
    Verifies the certificate's OIDC Source Repository Visibility
    At Signing, identified by an X.509v3 extension tagged with
    `1.3.6.1.4.1.57264.1.22`.
    """

    oid = _OIDC_SOURCE_REPOSITORY_VISIBILITY_OID


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
