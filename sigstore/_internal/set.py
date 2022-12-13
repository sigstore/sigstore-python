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
Utilities for verifying Signed Entry Timestamps.
"""

import base64

import cryptography.hazmat.primitives.asymmetric.ec as ec
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes

from sigstore._internal.rekor import RekorClient, RekorEntry


class InvalidSetError(Exception):
    """
    Raised during SET verification if an SET is invalid in some way.
    """

    pass


def verify_set(client: RekorClient, entry: RekorEntry) -> None:
    """
    Verify the Signed Entry Timestamp for a given Rekor `entry` using the given `client`.
    """

    signed_entry_ts = base64.b64decode(entry.signed_entry_timestamp)

    try:
        client._pubkey.verify(
            signature=signed_entry_ts,
            data=entry.encode_canonical(),
            signature_algorithm=ec.ECDSA(hashes.SHA256()),
        )
    except InvalidSignature as inval_sig:
        raise InvalidSetError("invalid signature") from inval_sig
