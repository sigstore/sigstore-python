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

import base64
import json

import pytest

from sigstore import dsse
from sigstore.dsse import InvalidEnvelope


class TestEnvelope:
    def test_roundtrip(self):
        raw = json.dumps(
            {
                "payload": base64.b64encode(b"foo").decode(),
                "payloadType": dsse.Envelope._TYPE,
                "signatures": [
                    {"sig": base64.b64encode(b"lol").decode()},
                ],
            }
        )
        evp = dsse.Envelope._from_json(raw)

        assert evp._inner.payload == b"foo"
        assert evp._inner.payload_type == dsse.Envelope._TYPE
        assert evp.signature == b"lol"

        serialized = evp.to_json()
        assert serialized == raw
        assert dsse.Envelope._from_json(serialized) == evp

    def test_missing_signature(self):
        raw = json.dumps(
            {
                "payload": base64.b64encode(b"foo").decode(),
                "payloadType": dsse.Envelope._TYPE,
                "signatures": [],
            }
        )

        with pytest.raises(InvalidEnvelope, match="one signature"):
            dsse.Envelope._from_json(raw)

    def test_empty_signature(self):
        raw = json.dumps(
            {
                "payload": base64.b64encode(b"foo").decode(),
                "payloadType": dsse.Envelope._TYPE,
                "signatures": [
                    {"sig": ""},
                ],
            }
        )

        with pytest.raises(InvalidEnvelope, match="non-empty"):
            dsse.Envelope._from_json(raw)

    def test_multiple_signatures(self):
        raw = json.dumps(
            {
                "payload": base64.b64encode(b"foo").decode(),
                "payloadType": dsse.Envelope._TYPE,
                "signatures": [
                    {"sig": base64.b64encode(b"lol").decode()},
                    {"sig": base64.b64encode(b"lmao").decode()},
                ],
            }
        )

        with pytest.raises(InvalidEnvelope, match="one signature"):
            dsse.Envelope._from_json(raw)