# Copyright 2024 The Sigstore Authors
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
Models for the predicates used in in-toto statements
"""

import enum
from typing import Any, Literal, Union

from pydantic import (
    BaseModel,
    ConfigDict,
    RootModel,
    StrictBytes,
    StrictStr,
    model_validator,
)
from pydantic.alias_generators import to_camel
from typing_extensions import Self

from sigstore.dsse import Digest


class PredicateType(str, enum.Enum):
    """
    Currently supported predicate types
    """

    SLSA_v0_2 = "https://slsa.dev/provenance/v0.2"
    SLSA_v1_0 = "https://slsa.dev/provenance/v1"


# Common models
SourceDigest = Literal["sha1", "gitCommit"]
DigestSetSource = RootModel[dict[Union[Digest, SourceDigest], str]]
"""
Same as `dsse.DigestSet` but with `sha1` added.

Since this model is not used to verify hashes, but to parse predicates that might
contain hashes, we include this weak hash algorithm. This is because provenance
providers like GitHub use SHA1 in their predicates to refer to git commit hashes.
"""


class Predicate(BaseModel):
    """
    Base model for in-toto predicates
    """

    pass


class _SLSAConfigBase(BaseModel):
    """
    Base class used to configure the models
    """

    model_config = ConfigDict(alias_generator=to_camel, extra="forbid")


# Models for SLSA Provenance v0.2


class BuilderV0_1(_SLSAConfigBase):
    """
    The Builder object used by SLSAPredicateV0_2
    """

    id: StrictStr


class ConfigSource(_SLSAConfigBase):
    """
    The ConfigSource object used by Invocation in v0.2
    """

    uri: StrictStr | None = None
    digest: DigestSetSource | None = None
    entry_point: StrictStr | None = None


class Invocation(_SLSAConfigBase):
    """
    The Invocation object used by SLSAPredicateV0_2
    """

    config_source: ConfigSource | None = None
    parameters: dict[str, Any] | None = None
    environment: dict[str, Any] | None = None


class Completeness(_SLSAConfigBase):
    """
    The Completeness object used by Metadata in v0.2
    """

    parameters: bool | None = None
    environment: bool | None = None
    materials: bool | None = None


class Material(_SLSAConfigBase):
    """
    The Material object used by Metadata in v0.2
    """

    uri: StrictStr | None = None
    digest: DigestSetSource | None = None


class Metadata(_SLSAConfigBase):
    """
    The Metadata object used by SLSAPredicateV0_2
    """

    build_invocation_id: StrictStr | None = None
    build_started_on: StrictStr | None = None
    build_finished_on: StrictStr | None = None
    completeness: Completeness | None = None
    reproducible: bool | None = None


class SLSAPredicateV0_2(Predicate, _SLSAConfigBase):
    """
    Represents the predicate object corresponding to the type "https://slsa.dev/provenance/v0.2"
    """

    builder: BuilderV0_1
    build_type: StrictStr
    invocation: Invocation | None = None
    metadata: Metadata | None = None
    build_config: dict[str, Any] | None = None
    materials: list[Material] | None = None


# Models for SLSA Provenance v1.0


class ResourceDescriptor(_SLSAConfigBase):
    """
    The ResourceDescriptor object defined defined by the in-toto attestations spec
    """

    name: StrictStr | None = None
    uri: StrictStr | None = None
    digest: DigestSetSource | None = None
    content: StrictBytes | None = None
    download_location: StrictStr | None = None
    media_type: StrictStr | None = None
    annotations: dict[StrictStr, Any] | None = None

    @model_validator(mode="after")
    def check_required_fields(self: Self) -> Self:
        """
        While all fields are optional, at least one of the fields `uri`, `digest` or
        `content` must be present
        """
        if not self.uri and not self.digest and not self.content:
            raise ValueError(
                "A ResourceDescriptor MUST specify one of uri, digest or content at a minimum"
            )
        return self


class BuilderV1_0(_SLSAConfigBase):
    """
    The Builder object used by RunDetails in v1.0
    """

    id: StrictStr
    builder_dependencies: list[ResourceDescriptor] | None = None
    version: dict[StrictStr, StrictStr] | None = None


class BuildMetadata(_SLSAConfigBase):
    """
    The BuildMetadata object used by RunDetails
    """

    invocation_id: StrictStr | None = None
    started_on: StrictStr | None = None
    finished_on: StrictStr | None = None


class RunDetails(_SLSAConfigBase):
    """
    The RunDetails object used by SLSAPredicateV1_0
    """

    builder: BuilderV1_0
    metadata: BuildMetadata | None = None
    byproducts: list[ResourceDescriptor] | None = None


class BuildDefinition(_SLSAConfigBase):
    """
    The BuildDefinition object used by SLSAPredicateV1_0
    """

    build_type: StrictStr
    external_parameters: dict[StrictStr, Any]
    internal_parameters: dict[str, Any] | None = None
    resolved_dependencies: list[ResourceDescriptor] | None = None


class SLSAPredicateV1_0(Predicate, _SLSAConfigBase):
    """
    Represents the predicate object corresponding to the type "https://slsa.dev/provenance/v1"
    """

    build_definition: BuildDefinition
    run_details: RunDetails
