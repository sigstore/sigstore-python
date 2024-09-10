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
    BaseModel,
    Field,
    RootModel,
    StrictBytes,
    StrictStr,
    model_validator,
)

from sigstore.dsse import Digest

PREDICATE_TYPE_SLSA_v0_2 = "https://slsa.dev/provenance/v0.2"
PREDICATE_TYPE_SLSA_v1_0 = "https://slsa.dev/provenance/v1"

PREDICATE_TYPES_CLI_MAP = {
    "slsaprovenance0_2": PREDICATE_TYPE_SLSA_v0_2,
    "slsaprovenance1_0": PREDICATE_TYPE_SLSA_v1_0,
}

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


# Models for SLSA Provenance v0.2


class BuilderV0_1(BaseModel):
    """
    The Builder object used by SLSAPredicateV0_2
    """

    id: StrictStr


class ConfigSource(BaseModel):
    """
    The ConfigSource object used by Invocation in v0.2
    """

    uri: Optional[StrictStr]
    digest: Optional[DigestSetSource]
    entry_point: Optional[StrictStr] = Field(None, alias="entryPoint")


class Invocation(BaseModel):
    """
    The Invocation object used by SLSAPredicateV0_2
    """

    config_source: Optional[ConfigSource] = Field(None, alias="configSource")
    parameters: Optional[Dict[str, Any]]
    environment: Optional[Dict[str, Any]]


class Completeness(BaseModel):
    """
    The Completeness object used by Metadata in v0.2
    """

    parameters: Optional[bool]
    environment: Optional[bool]
    materials: Optional[bool]


class Material(BaseModel):
    """
    The Material object used by Metadata in v0.2
    """

    uri: Optional[StrictStr]
    digest: Optional[DigestSetSource]


class Metadata(BaseModel):
    """
    The Metadata object used by SLSAPredicateV0_2
    """

    build_invocation_id: Optional[StrictStr] = Field(None, alias="buildInvocationId")
    build_started_on: Optional[StrictStr] = Field(None, alias="buildStartedOn")
    build_finished_on: Optional[StrictStr] = Field(None, alias="buildFinishedOn")
    completeness: Optional[Completeness]
    reproducible: Optional[bool]


class SLSAPredicateV0_2(Predicate):
    """
    Represents the predicate object corresponding to the type "https://slsa.dev/provenance/v0.2"
    """

    builder: BuilderV0_1
    build_type: StrictStr = Field(..., alias="buildType")
    invocation: Optional[Invocation]
    metadata: Optional[Metadata]
    build_config: Optional[Dict[str, Any]] = Field(None, alias="buildConfig")
    materials: Optional[List[Material]]


# Models for SLSA Provenance v1.0

Self = TypeVar("Self", bound="ResourceDescriptor")


class ResourceDescriptor(BaseModel):
    """
    The ResourceDescriptor object defined defined by the in-toto attestations spec
    """

    name: Optional[StrictStr]
    uri: Optional[StrictStr]
    digest: DigestSetSource = Field(...)
    content: Optional[StrictBytes]
    download_location: Optional[StrictStr] = Field(None, alias="downloadLocation")
    media_type: Optional[StrictStr] = Field(None, alias="mediaType")
    annotations: Optional[Dict[StrictStr, Any]]

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


class BuilderV1_0(BaseModel):
    """
    The Builder object used by RunDetails in v1.0
    """

    id: StrictStr
    builder_dependencies: List[ResourceDescriptor] = Field(
        ..., alias="builderDependencies"
    )
    version: Dict[StrictStr, StrictStr]


class BuildMetadata(BaseModel):
    """
    The BuildMetadata object used by RunDetails
    """

    invocation_id: StrictStr = Field(..., alias="invocationId")
    started_on: StrictStr = Field(..., alias="startedOn")
    finished_on: StrictStr = Field(..., alias="finishedOn")


class RunDetails(BaseModel):
    """
    The RunDetails object used by SLSAPredicateV1_0
    """

    builder: BuilderV1_0
    metadata: BuildMetadata
    byproducts: List[ResourceDescriptor]


class BuildDefinition(BaseModel):
    """
    The BuildDefinition object used by SLSAPredicateV1_0
    """

    build_type: StrictStr = Field(..., alias="buildType")
    external_parameters: Dict[StrictStr, Any] = Field(..., alias="externalParameters")
    internal_parameters: Dict[str, Any] = Field(..., alias="internalParameters")
    resolved_dependencies: List[ResourceDescriptor] = Field(
        ..., alias="resolvedDependencies"
    )


class SLSAPredicateV1_0(Predicate):
    """
    Represents the predicate object corresponding to the type "https://slsa.dev/provenance/v1"
    """

    build_definition: BuildDefinition = Field(..., alias="buildDefinition")
    run_details: RunDetails = Field(..., alias="runDetails")
