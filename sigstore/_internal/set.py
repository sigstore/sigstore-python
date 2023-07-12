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

from cryptography.exceptions import InvalidSignature

from sigstore._internal.rekor import RekorClient
from sigstore._utils import KeyID
from sigstore.transparency import LogEntry


class InvalidSETError(Exception):
    """
    Raised during SET verification if an SET is invalid in some way.
    """

    pass


def verify_set(client: RekorClient, entry: LogEntry) -> None:
    """
    Verify the inclusion promise (Signed Entry Timestamp) for a given transparency log
    `entry` using the given `client`.

    Fails if the given log entry does not contain an inclusion promise.
    """
    if entry.inclusion_promise is None:
        raise InvalidSETError("invalid log entry: no inclusion promise")

    signed_entry_ts = base64.b64decode(entry.inclusion_promise)

    try:
        client._rekor_keyring.verify(
            key_id=KeyID(bytes.fromhex(entry.log_id)),
            signature=signed_entry_ts,
            data=entry.encode_canonical(),
        )
    except InvalidSignature as inval_sig:
        raise InvalidSETError("invalid signature") from inval_sig
