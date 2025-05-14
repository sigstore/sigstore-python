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

import json
from base64 import b64encode

import pytest
from pydantic import ValidationError

from sigstore.errors import VerificationError
from sigstore.models import (
    Bundle,
    InvalidBundle,
    LogEntry,
    LogInclusionProof,
    TimestampVerificationData,
    VerificationMaterial,
)


class TestLogEntry:
    def test_missing_inclusion_proof(self):
        with pytest.raises(ValueError, match=r"inclusion_proof"):
            LogEntry(
                uuid="fake",
                body=b64encode(b"fake"),
                integrated_time=0,
                log_id="1234",
                log_index=1,
                inclusion_proof=None,
                inclusion_promise=None,
            )

    def test_missing_inclusion_promise_and_integrated_time_round_trip(self, signing_bundle):
        """
        Ensures that LogEntry._to_rekor() succeeds even without an inclusion_promise and integrated_time.
        """
        bundle: Bundle
        _, bundle = signing_bundle("bundle.txt")
        _dict = bundle.log_entry._to_rekor().to_dict()
        print(_dict)
        del _dict["inclusionPromise"]
        del _dict["integratedTime"]
        entry = LogEntry._from_dict_rekor(_dict)
        assert entry.inclusion_promise is None
        assert entry._to_rekor() is not None
        assert LogEntry._from_dict_rekor(entry._to_rekor().to_dict()) == entry

    def test_logentry_roundtrip(self, signing_bundle):
        _, bundle = signing_bundle("bundle.txt")

        assert (
            LogEntry._from_dict_rekor(bundle.log_entry._to_rekor().to_dict())
            == bundle.log_entry
        )


class TestLogInclusionProof:
    def test_valid(self):
        proof = LogInclusionProof(
            log_index=1, root_hash="abcd", tree_size=2, hashes=[], checkpoint=""
        )
        assert proof is not None

    def test_negative_log_index(self):
        with pytest.raises(
            ValidationError, match="Inclusion proof has invalid log index"
        ):
            LogInclusionProof(
                log_index=-1, root_hash="abcd", tree_size=2, hashes=[], checkpoint=""
            )

    def test_negative_tree_size(self):
        with pytest.raises(
            ValidationError, match="Inclusion proof has invalid tree size"
        ):
            LogInclusionProof(
                log_index=1, root_hash="abcd", tree_size=-1, hashes=[], checkpoint=""
            )

    def test_log_index_outside_tree_size(self):
        with pytest.raises(
            ValidationError,
            match="Inclusion proof has log index greater than or equal to tree size",
        ):
            LogInclusionProof(
                log_index=2, root_hash="abcd", tree_size=1, hashes=[], checkpoint=""
            )

    def test_checkpoint_missing(self):
        with pytest.raises(ValidationError, match=r"should be a valid string"):
            (
                LogInclusionProof(
                    checkpoint=None,
                    hashes=["fake"],
                    log_index=0,
                    root_hash="fake",
                    tree_size=100,
                ),
            )


class TestTimestampVerificationData:
    """
    Tests for the `TimestampVerificationData` wrapper model.
    """

    def test_valid_timestamp(self, asset):
        timestamp = {
            "rfc3161Timestamps": [
                {
                    "signedTimestamp": "MIIEgTADAgEAMIIEeAYJKoZIhvcNAQcCoIIEaTCCBGUCAQMxDTALBglghkgBZQMEAgEwgc8GCyqGSIb3DQEJEAEEoIG/BIG8MIG5AgEBBgkrBgEEAYO/MAIwMTANBglghkgBZQMEAgEFAAQgyGobd7rprYIL0JTus5EpEb7jrrecS+cMbb42ftjtm+UCFBV/kwOOwt0tdtYXK1FGhXf7W4oFGA8yMDI0MTAyMjA3MzEwNVowAwIBAQIUTo190a2ixXglxLh7KJcwj6B4kf+gNKQyMDAxDjAMBgNVBAoTBWxvY2FsMR4wHAYDVQQDExVUZXN0IFRTQSBUaW1lc3RhbXBpbmegggHRMIIBzTCCAXKgAwIBAgIUIYzlmDAtGrQ5jmcZpeAN0Wyj8Q8wCgYIKoZIzj0EAwIwMDEOMAwGA1UEChMFbG9jYWwxHjAcBgNVBAMTFVRlc3QgVFNBIEludGVybWVkaWF0ZTAeFw0yNDEwMjIwNzIyNTNaFw0zMzEwMjIwNzI1NTNaMDAxDjAMBgNVBAoTBWxvY2FsMR4wHAYDVQQDExVUZXN0IFRTQSBUaW1lc3RhbXBpbmcwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQBhKWvDUj1+VFrWudnWIRzAug99WAydJuyF9pxneWppyXbjio3RSoNBvhg+91eeue7GpRQx5ZoxdeiHJD5p7Z0o2owaDAOBgNVHQ8BAf8EBAMCB4AwHQYDVR0OBBYEFD7JreyIuE9lHC9k+cFePRXIPdNaMB8GA1UdIwQYMBaAFJMEP2b7r8olhCtvCokuFyTMC0nOMBYGA1UdJQEB/wQMMAoGCCsGAQUFBwMIMAoGCCqGSM49BAMCA0kAMEYCIQC69iKNrM4N2/OHksX7zEJM7ImGR+Puq7ALM8l3+riChgIhAKbEWTmifAE6VaQwnL0NNTJskSgk6r8BzvbJtJEZpk6fMYIBqDCCAaQCAQEwSDAwMQ4wDAYDVQQKEwVsb2NhbDEeMBwGA1UEAxMVVGVzdCBUU0EgSW50ZXJtZWRpYXRlAhQhjOWYMC0atDmOZxml4A3RbKPxDzALBglghkgBZQMEAgGggfMwGgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEEMBwGCSqGSIb3DQEJBTEPFw0yNDEwMjIwNzMxMDVaMC8GCSqGSIb3DQEJBDEiBCBr9fx6gIRsipdGxMDIw1tpvHUv3y10SHUzEM+HHP15+DCBhQYLKoZIhvcNAQkQAi8xdjB0MHIwcAQg2PR1japGgjWt7Cd0jQJrSYlYTblz/UeoJw0LkbqIsSIwTDA0pDIwMDEOMAwGA1UEChMFbG9jYWwxHjAcBgNVBAMTFVRlc3QgVFNBIEludGVybWVkaWF0ZQIUIYzlmDAtGrQ5jmcZpeAN0Wyj8Q8wCgYIKoZIzj0EAwIERjBEAiBDfeCcnA1qIlHfMK/u3FZ1HtS9840NnXXaRdMD4R7MywIgZfoBiAMV3SFqO71+eo2kD9oBkW49Pb9eoQs00nOlvn8="
                }
            ]
        }

        timestamp_verification = TimestampVerificationData.from_json(
            json.dumps(timestamp)
        )

        assert timestamp_verification.rfc3161_timestamps

    def test_no_timestamp(self, asset):
        timestamp = {"rfc3161Timestamps": []}
        timestamp_verification = TimestampVerificationData.from_json(
            json.dumps(timestamp)
        )

        assert not timestamp_verification.rfc3161_timestamps

    def test_invalid_timestamp(self, asset):
        timestamp = {"rfc3161Timestamps": [{"signedTimestamp": "invalid-entry"}]}
        with pytest.raises(VerificationError, match="Invalid Timestamp"):
            TimestampVerificationData.from_json(json.dumps(timestamp))


class TestVerificationMaterial:
    """
    Tests for the `VerificationMaterial` wrapper model.
    """

    def test_valid_verification_material(self, asset):
        bundle = Bundle.from_json(asset("bundle.txt.sigstore").read_bytes())

        verification_material = VerificationMaterial(
            bundle._inner.verification_material
        )
        assert verification_material


class TestBundle:
    """
    Tests for the `Bundle` wrapper model.
    """

    def test_invalid_bundle_version(self, signing_bundle):
        with pytest.raises(InvalidBundle, match="unsupported bundle format"):
            signing_bundle("bundle_invalid_version.txt")

    def test_invalid_empty_cert_chain(self, signing_bundle):
        with pytest.raises(
            InvalidBundle, match="expected non-empty certificate chain in bundle"
        ):
            signing_bundle("bundle_no_cert_v1.txt")

    def test_invalid_no_log_entry(self, signing_bundle):
        with pytest.raises(
            InvalidBundle, match="expected exactly one log entry in bundle"
        ):
            signing_bundle("bundle_no_log_entry.txt")

    def test_verification_materials_offline_no_checkpoint(self, signing_bundle):
        with pytest.raises(
            InvalidBundle, match="entry must contain inclusion proof, with checkpoint"
        ):
            signing_bundle("bundle_no_checkpoint.txt")

    def test_bundle_roundtrip(self, signing_bundle):
        _, bundle = signing_bundle("bundle.txt")

        # Bundles are not directly comparable, but a round-trip preserves their
        # underlying object structure.
        assert json.loads(Bundle.from_json(bundle.to_json()).to_json()) == json.loads(
            bundle.to_json()
        )

    def test_bundle_missing_signed_time(self, signing_bundle):
        with pytest.raises(
            InvalidBundle,
            match=r"bundle must contain an inclusion promise or signed timestamp\(s\)",
        ):
            signing_bundle("bundle_v3_no_signed_time.txt")


class TestKnownBundleTypes:
    def test_str(self):
        for type_ in Bundle.BundleType:
            assert str(type_) == type_.value
            assert type_ in Bundle.BundleType
