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

import pretend
import pytest

from sigstore._internal.ctfe import CTKeyring, CTKeyringLookupError


class TestCTKeyring:
    def test_keyring_init(self):
        keybytes = (
            b"-----BEGIN PUBLIC KEY-----\n"
            b"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEbfwR+RJudXscgRBRpKX1XFDy3Pyu\n"
            b"dDxz/SfnRi1fT8ekpfBd2O1uoz7jr3Z8nKzxA69EUQ+eFCFI3zeubPWU7w==\n"
            b"-----END PUBLIC KEY-----"
        )
        ctkeyring = CTKeyring([keybytes])
        assert len(ctkeyring._keyring) == 1

    def test_keyring_add(self):
        # same as above but manually `add`ing key.
        keybytes = (
            b"-----BEGIN PUBLIC KEY-----\n"
            b"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEbfwR+RJudXscgRBRpKX1XFDy3Pyu\n"
            b"dDxz/SfnRi1fT8ekpfBd2O1uoz7jr3Z8nKzxA69EUQ+eFCFI3zeubPWU7w==\n"
            b"-----END PUBLIC KEY-----"
        )
        ctkeyring = CTKeyring()
        ctkeyring.add(keybytes)
        assert len(ctkeyring._keyring) == 1

    def test_verify_fail_empty_keyring(self):
        ctkeyring = CTKeyring()
        key_id = pretend.stub(hex=pretend.call_recorder(lambda: pretend.stub()))
        signature = pretend.stub()
        data = pretend.stub()

        with pytest.raises(CTKeyringLookupError, match="no known key for key ID?"):
            ctkeyring.verify(key_id=key_id, signature=signature, data=data)
