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


from abc import abstractmethod
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
from pydantic import BaseModel, StrictStr

_OIDC_ISSUER_OID = ObjectIdentifier("1.3.6.1.4.1.57264.1.1")
_OTHERNAME_OID = ObjectIdentifier("1.3.6.1.4.1.57264.1.7")


class VerificationResult(BaseModel):
    success: bool

    def __bool__(self) -> bool:
        return self.success


class VerificationSuccess(VerificationResult):
    success: bool = True


class VerificationFailure(VerificationResult):
    success: bool = False
    reason: str


class VerificationPolicy(Protocol):
    @abstractmethod
    def verify(self, cert: Certificate) -> VerificationResult:
        raise NotImplementedError


class AnyOf:
    """
    The "any of" policy, corresponding to a logical OR between child policies.
    """

    def __init__(self, children: list[VerificationPolicy]):
        self._children = children

    def verify(self, cert: Certificate) -> VerificationResult:
        verified = any(child.verify(cert) for child in self._children)
        if verified:
            return VerificationSuccess()
        else:
            return VerificationFailure(
                reason=f"0 of {len(self._children)} policies succeeded"
            )


class _OIDCIssuerMixin(BaseModel):
    """
    Verifies the certificate's OIDC issuer, identified by
    an X.509v3 extension tagged with `1.3.6.1.4.1.57264.1.1`.

    See: <https://github.com/sigstore/fulcio/blob/main/docs/oid-info.md#1361415726411--issuer>
    """

    issuer: StrictStr

    def verify(self, cert: Certificate) -> VerificationResult:
        # Check that the OIDC issuer extension is present, and contains the expected
        # issuer string (which is probably a URL).
        try:
            oidc_issuer = cert.extensions.get_extension_for_oid(_OIDC_ISSUER_OID).value
        except ExtensionNotFound:
            return VerificationFailure(
                reason="Certificate does not contain OIDC issuer extension"
            )

        # NOTE(ww): mypy is confused by the `Extension[ExtensionType]` returned
        # by `get_extension_for_oid` above.
        issuer_value = oidc_issuer.value.decode()  # type: ignore[attr-defined]
        if issuer_value != self.issuer:
            return VerificationFailure(
                reason=(
                    "Certificate's OIDC issuer does not match "
                    f"(got {issuer_value}, expected {self.issuer})"
                )
            )

        return VerificationSuccess()


class Identity(_OIDCIssuerMixin):
    identity: StrictStr

    def verify(self, cert: Certificate) -> VerificationResult:
        issuer_verified = super().verify(cert)
        if not issuer_verified:
            return issuer_verified

        san_ext = cert.extensions.get_extension_for_class(SubjectAlternativeName)
        verified = (
            self.identity in san_ext.value.get_values_for_type(RFC822Name)
            or self.identity
            in san_ext.value.get_values_for_type(UniformResourceIdentifier)
            or OtherName(_OTHERNAME_OID, self.identity.encode())
            in san_ext.value.get_values_for_type(OtherName)
        )

        if not verified:
            return VerificationFailure(
                reason=f"Certificate's SANs do not match {self.identity}"
            )

        return VerificationSuccess()
