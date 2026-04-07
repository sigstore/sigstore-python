# Copyright 2026 The Sigstore Authors
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

import unittest.mock
import requests
import pytest

from sigstore._internal.rekor.client import RekorClient
from sigstore._internal.rekor.client_v2 import RekorV2Client
from sigstore._internal.timestamp import TimestampAuthorityClient, TimestampError
from sigstore._internal.rekor import RekorClientError, EntryRequestBody

def test_rekor_v1_session_reuse_public_api():
    """Verify that RekorClient v1 reuses its session per thread using public API."""
    client = RekorClient("http://fake")
    
    with unittest.mock.patch("requests.Session") as mock_session_cls:
        mock_session_inst = unittest.mock.MagicMock()
        mock_session_cls.return_value = mock_session_inst
        
        # Access log endpoint multiple times
        client.log
        client.log
        
        # Expect 1 session
        assert mock_session_cls.call_count == 1

def test_rekor_v2_session_reuse_public_api():
    """Verify that RekorV2Client reuses its session per thread using public API."""
    client = RekorV2Client("http://fake")
    
    with unittest.mock.patch("requests.Session") as mock_session_cls:
        mock_session_inst = unittest.mock.MagicMock()
        mock_session_cls.return_value = mock_session_inst
        
        
        # Call create_entry multiple times (hide exception: the client does not need to work)
        try:
            client.create_entry(EntryRequestBody({}))
        except Exception:
            pass
            
        try:
            client.create_entry(EntryRequestBody({}))
        except Exception:
            pass
            
        # Expect 1 session
        assert mock_session_cls.call_count == 1

def test_timestamp_client_session_reuse_public_api():
    """Verify that TimestampAuthorityClient reuses its session per thread using public API."""
    client = TimestampAuthorityClient("http://fake")
    
    with unittest.mock.patch("requests.Session") as mock_session_cls:
        mock_session_inst = unittest.mock.MagicMock()
        mock_session_cls.return_value = mock_session_inst
        
        # Call request_timestamp multiple times (hide exception: the client does not need to work)
        try:
            client.request_timestamp(b"sig")
        except Exception:
            pass
            
        try:
            client.request_timestamp(b"sig")
        except Exception:
            pass
            
        # Expect 1 session
        assert mock_session_cls.call_count == 1
