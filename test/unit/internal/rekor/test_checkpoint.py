# Copyright 2025 The Sigstore Authors
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

import pytest

from sigstore._internal.rekor.checkpoint import LogCheckpoint
from sigstore.errors import VerificationError


class TestLogCheckpoint:
    def test_from_text_roundtrip(self):
        root_hash = base64.b64encode(b"\x00" * 32).decode()
        text = f"rekor.example - 123\n42\n{root_hash}\nTimestamp: 1\n"
        checkpoint = LogCheckpoint.from_text(text)
        assert checkpoint.origin == "rekor.example - 123"
        assert checkpoint.log_size == 42
        assert checkpoint.log_hash == (b"\x00" * 32).hex()
        assert checkpoint.other_content == ["Timestamp: 1"]

    def test_from_text_too_few_lines(self):
        with pytest.raises(VerificationError, match="too few items"):
            LogCheckpoint.from_text("rekor.example - 123\n42\n")

    def test_from_text_invalid_log_size(self):
        # A non-integer log size must surface as a VerificationError rather than
        # leaking a raw ValueError to callers that only expect VerificationError.
        root_hash = base64.b64encode(b"\x00" * 32).decode()
        with pytest.raises(VerificationError, match="invalid log size"):
            LogCheckpoint.from_text(f"rekor.example - 123\nNOTANINT\n{root_hash}\n")

    def test_from_text_invalid_root_hash(self):
        # An undecodable base64 root hash must also surface as a VerificationError.
        with pytest.raises(VerificationError, match="invalid root hash"):
            LogCheckpoint.from_text("rekor.example - 123\n42\n!!!notbase64!!!\n")
