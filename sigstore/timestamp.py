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
Utilities to deal with Signed Timestamps.
"""

import enum
from dataclasses import dataclass
from datetime import datetime


class TimestampSource(enum.Enum):
    """Represents the source of a timestamp."""

    TIMESTAMP_AUTHORITY = enum.auto()
    TRANSPARENCY_SERVICE = enum.auto()


@dataclass
class TimestampVerificationResult:
    """Represents a timestamp used by the Verifier.

    A Timestamp either comes from a Timestamping Service (RFC3161) or the Transparency
    Service.
    """

    source: TimestampSource
    time: datetime
