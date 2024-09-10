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

from typing import Any, Dict, List, Literal, Optional, TypeVar, Union

from pydantic import (
    AliasChoices,
    BaseModel,
    ConfigDict,
    Field,
    RootModel,
    StrictBytes,
    StrictStr,
    model_validator,
)
from pydantic.alias_generators import to_camel

from sigstore.dsse import Digest

PREDICATE_TYPE_SLSA_v0_2 = "https://slsa.dev/provenance/v0.2"
PREDICATE_TYPE_SLSA_v1_0 = "https://slsa.dev/provenance/v1"

SUPPORTED_PREDICATE_TYPES = [PREDICATE_TYPE_SLSA_v0_2, PREDICATE_TYPE_SLSA_v1_0]

# Common models

DigestSetSource = RootModel[Dict[Union[Digest, Literal["sha1"]], str]]
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

    model_config = ConfigDict(alias_generator=to_camel)


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

    uri: Optional[StrictStr] = None
    digest: Optional[DigestSetSource] = None
    entry_point: Optional[StrictStr] = None


class Invocation(_SLSAConfigBase):
    """
    The Invocation object used by SLSAPredicateV0_2
    """

    config_source: Optional[ConfigSource] = None
    parameters: Optional[Dict[str, Any]] = None
    environment: Optional[Dict[str, Any]] = None


class Completeness(_SLSAConfigBase):
    """
    The Completeness object used by Metadata in v0.2
    """

    parameters: Optional[bool] = None
    environment: Optional[bool] = None
    materials: Optional[bool] = None


class Material(_SLSAConfigBase):
    """
    The Material object used by Metadata in v0.2
    """

    uri: Optional[StrictStr] = None
    digest: Optional[DigestSetSource] = None


class Metadata(_SLSAConfigBase):
    """
    The Metadata object used by SLSAPredicateV0_2
    """

    # We add a manual alias here because some provenance generators
    # (like `slsa-github-generator`) incorrectly use BuildInvocationID
    # instead of BuildInvocationId (ID vs Id)
    build_invocation_id: Optional[StrictStr] = Field(
        default=None,
        validation_alias=AliasChoices("buildInvocationId", "buildInvocationID"),
    )
    build_started_on: Optional[StrictStr] = None
    build_finished_on: Optional[StrictStr] = None
    completeness: Optional[Completeness] = None
    reproducible: Optional[bool] = None


class SLSAPredicateV0_2(Predicate, _SLSAConfigBase):
    """
    Represents the predicate object corresponding to the type "https://slsa.dev/provenance/v0.2"
    """

    builder: BuilderV0_1
    build_type: StrictStr
    invocation: Optional[Invocation] = None
    metadata: Optional[Metadata] = None
    build_config: Optional[Dict[str, Any]] = None
    materials: Optional[List[Material]] = None


# Models for SLSA Provenance v1.0

Self = TypeVar("Self", bound="ResourceDescriptor")


class ResourceDescriptor(_SLSAConfigBase):
    """
    The ResourceDescriptor object defined defined by the in-toto attestations spec
    """

    name: Optional[StrictStr]
    uri: Optional[StrictStr]
    digest: DigestSetSource
    content: Optional[StrictBytes] = None
    download_location: Optional[StrictStr] = None
    media_type: Optional[StrictStr] = None
    annotations: Optional[Dict[StrictStr, Any]] = None

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
    builder_dependencies: List[ResourceDescriptor] = Field(
        ..., alias="builderDependencies"
    )
    version: Dict[StrictStr, StrictStr]


class BuildMetadata(_SLSAConfigBase):
    """
    The BuildMetadata object used by RunDetails
    """

    invocation_id: StrictStr
    started_on: StrictStr
    finished_on: StrictStr


class RunDetails(_SLSAConfigBase):
    """
    The RunDetails object used by SLSAPredicateV1_0
    """

    builder: BuilderV1_0
    metadata: BuildMetadata
    byproducts: List[ResourceDescriptor]


class BuildDefinition(_SLSAConfigBase):
    """
    The BuildDefinition object used by SLSAPredicateV1_0
    """

    build_type: StrictStr
    external_parameters: Dict[StrictStr, Any]
    internal_parameters: Dict[str, Any]
    resolved_dependencies: List[ResourceDescriptor]


class SLSAPredicateV1_0(Predicate, _SLSAConfigBase):
    """
    Represents the predicate object corresponding to the type "https://slsa.dev/provenance/v1"
    """

    build_definition: BuildDefinition
    run_details: RunDetails
