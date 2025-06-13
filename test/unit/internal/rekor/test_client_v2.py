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

import hashlib

import pytest

from sigstore import dsse
from sigstore._internal.rekor.client_v2 import (
    LogEntry,
    RekorV2Client,
)
from sigstore.models import rekor_v1

ALPHA_REKOR_V2_URL = "https://log2025-alpha1.rekor.sigstage.dev"


@pytest.mark.staging
@pytest.mark.ambient_oidc
def test_rekor_v2_create_entry_dsse(preprod):
    # This is not a real unit test: it requires not only staging rekor but also TUF
    # fulcio and oidc -- maybe useful only until we have real integration tests in place
    sign_ctx_cls, _, identity = preprod

    # Hack to run Signer.sign() with staging rekor v2
    sign_ctx = sign_ctx_cls()
    sign_ctx._rekor = RekorV2Client(ALPHA_REKOR_V2_URL)

    stmt = (
        dsse.StatementBuilder()
        .subjects(
            [
                dsse.Subject(
                    name="null", digest={"sha256": hashlib.sha256(b"").hexdigest()}
                )
            ]
        )
        .predicate_type("https://cosign.sigstore.dev/attestation/v1")
        .predicate(
            {
                "Data": "",
                "Timestamp": "2023-12-07T00:37:58Z",
            }
        )
    ).build()

    with sign_ctx.signer(identity) as signer:
        bundle = signer.sign_dsse(stmt)

    assert isinstance(bundle.log_entry, LogEntry)
    assert isinstance(bundle.log_entry._to_rekor(), rekor_v1.TransparencyLogEntry)


@pytest.mark.staging
@pytest.mark.ambient_oidc
def test_rekor_v2_create_entry_hashed_rekord(preprod):
    # This is not a real unit test: it requires not only staging rekor but also TUF
    # fulcio and oidc -- maybe useful only until we have real integration tests in place
    sign_ctx_cls, _, identity = preprod

    # Hack to run Signer.sign() with staging rekor v2
    sign_ctx = sign_ctx_cls()
    sign_ctx._rekor = RekorV2Client(ALPHA_REKOR_V2_URL)

    with sign_ctx.signer(identity) as signer:
        bundle = signer.sign_artifact(b"")

    assert isinstance(bundle.log_entry, LogEntry)
    assert isinstance(bundle.log_entry._to_rekor(), rekor_v1.TransparencyLogEntry)
