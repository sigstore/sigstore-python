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
import os
from datetime import UTC, datetime, timedelta

import pytest
import urllib3
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import mldsa
from sigstore_models.common.v1 import (
    HashAlgorithm,
    LogId,
    PublicKey,
    PublicKeyDetails,
    TimeRange,
)
from sigstore_models.trustroot.v1 import (
    Service,
    ServiceConfiguration,
    ServiceSelector,
    TransparencyLogInstance,
)
from sigstore_models.trustroot.v1 import (
    SigningConfig as _SigningConfig,
)
from sigstore_models.trustroot.v1 import (
    TrustedRoot as _TrustedRoot,
)

from sigstore._internal.fulcio.client import FulcioClient
from sigstore._internal.rekor.client import RekorClient
from sigstore._internal.rekor.client_identity import IdentityRekorClient
from sigstore._internal.rekor.client_v2 import RekorV2Client
from sigstore._internal.timestamp import TimestampAuthorityClient
from sigstore._internal.trust import (
    CertificateAuthority,
    Key,
    Keyring,
    KeyringPurpose,
)
from sigstore._utils import is_timerange_valid
from sigstore.errors import Error, MetadataError, TUFError, VerificationError
from sigstore.models import (
    ClientTrustConfig,
    SigningConfig,
    TrustedRoot,
)

# Test data for TestSigningcconfig
_service_v1_op1 = Service(url="url1", major_api_version=1, operator="op1")
_service2_v1_op1 = Service(url="url2", major_api_version=1, operator="op1")
_service_v2_op1 = Service(url="url3", major_api_version=2, operator="op1")
_service_v1_op2 = Service(url="url4", major_api_version=1, operator="op2")
_service_v1_op3 = Service(url="url5", major_api_version=1, operator="op3")
_service_v1_op4 = Service(
    url="url6",
    major_api_version=1,
    operator="op4",
    valid_for=TimeRange(start=datetime(3000, 1, 1, tzinfo=UTC)),
)


class TestCertificateAuthority:
    def test_good(self, asset):
        path = asset("trusted_root/certificate_authority.json")
        authority = CertificateAuthority.from_json(path)

        assert len(authority.certificates(allow_expired=True)) == 3
        assert authority.validity_period_end is not None
        assert authority.validity_period_start < authority.validity_period_end

    def test_missing_root(self, asset):
        path = asset("trusted_root/certificate_authority.empty.json")
        with pytest.raises(Error, match="missing a certificate"):
            CertificateAuthority.from_json(path)


class TestSigningConfig:
    def test_good(self, asset):
        path = asset("signing_config/signingconfig.v2.json")
        signing_config = SigningConfig.from_file(path)

        assert (
            signing_config._inner.media_type
            == SigningConfig.SigningConfigType.SIGNING_CONFIG_0_2.value
        )

        fulcio = signing_config.get_fulcio()
        assert isinstance(fulcio, FulcioClient)
        assert fulcio.url == "https://fulcio.example.com"
        assert signing_config.get_oidc_url() == "https://oauth2.example.com/auth"

        # signing config contains v1 and v2, we pick v2
        tlogs = signing_config.get_tlogs()
        assert len(tlogs) == 1
        assert isinstance(tlogs[0], RekorV2Client)
        assert tlogs[0].url == "https://rekor-v2.example.com/api/v2"

        tsas = signing_config.get_tsas()
        assert len(tsas) == 1
        assert isinstance(tsas[0], TimestampAuthorityClient)
        assert tsas[0].url == "https://timestamp.example.com/api/v1/timestamp"

    def test_good_only_v1_rekor(self, asset):
        """Test case where a rekor 2 instance is not available"""
        path = asset("signing_config/signingconfig-only-v1-rekor.v2.json")
        signing_config = SigningConfig.from_file(path)

        tlogs = signing_config.get_tlogs()
        assert len(tlogs) == 1
        assert isinstance(tlogs[0], RekorClient)
        assert tlogs[0].url == "https://rekor.example.com/api/v1"

    @pytest.mark.parametrize(
        "services, versions, config, expected_result",
        [
            pytest.param(
                [_service_v1_op1],
                [1],
                ServiceConfiguration(selector=ServiceSelector.ALL),
                [_service_v1_op1],
                id="base case",
            ),
            pytest.param(
                [_service_v1_op1, _service2_v1_op1],
                [1],
                ServiceConfiguration(selector=ServiceSelector.ALL),
                [_service2_v1_op1],
                id="multiple services, same operator: expect 1 service in result",
            ),
            pytest.param(
                [_service_v1_op1, _service_v1_op2],
                [1],
                ServiceConfiguration(selector=ServiceSelector.ALL),
                [_service_v1_op1, _service_v1_op2],
                id="2 services, different operator: expect 2 services in result",
            ),
            pytest.param(
                [_service_v1_op1, _service_v1_op2, _service_v1_op4],
                [1],
                ServiceConfiguration(selector=ServiceSelector.ALL),
                [_service_v1_op1, _service_v1_op2],
                id="3 services, one is not yet valid: expect 2 services in result",
            ),
            pytest.param(
                [_service_v1_op1, _service_v1_op2],
                [1],
                ServiceConfiguration(selector=ServiceSelector.ANY),
                [_service_v1_op1],
                id="ANY selector: expect 1 service only in result",
            ),
            pytest.param(
                [_service_v1_op1, _service_v1_op2, _service_v1_op3],
                [1],
                ServiceConfiguration(selector=ServiceSelector.EXACT, count=2),
                [_service_v1_op1, _service_v1_op2],
                id="EXACT selector: expect configured number of services in result",
            ),
            pytest.param(
                [_service_v1_op1, _service_v2_op1],
                [1, 2],
                ServiceConfiguration(selector=ServiceSelector.ALL),
                [_service_v2_op1],
                id="services with different version: expect highest version",
            ),
            pytest.param(
                [_service_v1_op1, _service_v2_op1],
                [1],
                ServiceConfiguration(selector=ServiceSelector.ALL),
                [_service_v1_op1],
                id="services with different version: expect the supported version",
            ),
            pytest.param(
                [_service_v1_op1, _service_v1_op2],
                [2],
                ServiceConfiguration(selector=ServiceSelector.ALL),
                [],
                id="No supported versions: expect no results",
            ),
            pytest.param(
                [_service_v1_op1, _service_v2_op1, _service_v1_op2],
                [1],
                None,
                [_service_v1_op1, _service_v1_op2],
                id="services without ServiceConfiguration: expect all supported",
            ),
        ],
    )
    def test_get_valid_services(self, services, versions, config, expected_result):
        result = SigningConfig._get_valid_services(services, versions, config)

        assert result == expected_result

    @pytest.mark.parametrize(
        "services, versions, config",
        [
            (  # EXACT selector without enough services
                [_service_v1_op1],
                [1],
                ServiceConfiguration(selector=ServiceSelector.EXACT, count=2),
            ),
        ],
    )
    def test_get_valid_services_fail(self, services, versions, config):
        with pytest.raises(ValueError):
            SigningConfig._get_valid_services(services, versions, config)

    def test_get_identity_tlogs_v1_only_and_forced_v1_fail(self, asset):
        v1_only = SigningConfig.from_file(
            asset("signing_config/signingconfig-only-v1-rekor.v2.json")
        )
        with pytest.raises(
            Error,
            match="No valid Rekor v2 identity transparency log found in signing config",
        ):
            v1_only.get_identity_tlogs()

        mixed = SigningConfig(
            SigningConfig.from_file(
                asset("signing_config/signingconfig.v2.json")
            )._inner,
            tlog_version=1,
        )
        with pytest.raises(
            Error,
            match="No valid Rekor v2 identity transparency log found in signing config",
        ):
            mixed.get_identity_tlogs()

    def test_get_identity_tlogs_multi_operator_selectors(self):
        v1_op1 = Service(
            url="https://rekor-v1.op1.example.com",
            major_api_version=1,
            operator="op1",
        )
        v2_op2 = Service(
            url="https://rekor-v2.op2.example.com",
            major_api_version=2,
            operator="op2",
        )

        # ANY: even when op1 (v1-only) comes first, get_identity_tlogs selects op2 (v2)
        sc_any = SigningConfig(
            _SigningConfig(
                media_type=SigningConfig.SigningConfigType.SIGNING_CONFIG_0_2.value,
                rekor_tlog_urls=[v1_op1, v2_op2],
                rekor_tlog_config=ServiceConfiguration(selector=ServiceSelector.ANY),
            )
        )
        tlogs = sc_any.get_identity_tlogs()
        assert len(tlogs) == 1
        assert isinstance(tlogs[0], IdentityRekorClient)
        assert tlogs[0].url == "https://rekor-v2.op2.example.com/api/v2"

        # EXACT(count=2): fails closed when only 1 v2 operator exists
        sc_exact = SigningConfig(
            _SigningConfig(
                media_type=SigningConfig.SigningConfigType.SIGNING_CONFIG_0_2.value,
                rekor_tlog_urls=[v1_op1, v2_op2],
                rekor_tlog_config=ServiceConfiguration(
                    selector=ServiceSelector.EXACT, count=2
                ),
            )
        )
        with pytest.raises(ValueError, match="Expected 2 services"):
            sc_exact.get_identity_tlogs()


class TestTrustedRoot:
    @pytest.mark.parametrize(
        "file",
        [
            "trusted_root/trustedroot.v1.json",
            "trusted_root/trustedroot.v1.local_tlog_ed25519_rekor-tiles.json",
        ],
    )
    def test_good(self, asset, file):
        """
        Ensures that the trusted_roots are well-formed and that the expected embedded keys are supported.
        """
        path = asset(file)
        root = TrustedRoot.from_file(path)

        assert (
            root._inner.media_type == TrustedRoot.TrustedRootType.TRUSTED_ROOT_0_1.value
        )
        assert len(root._inner.tlogs) == 1
        assert len(root._inner.certificate_authorities) == 2
        assert len(root._inner.ctlogs) == 2
        assert len(root._inner.timestamp_authorities) == 1

        # only one of the two rekor keys is actually supported
        assert len(root.rekor_keyring(KeyringPurpose.VERIFY)._keyring) == 1
        assert len(root.ct_keyring(KeyringPurpose.VERIFY)._keyring) == 2
        assert root.get_fulcio_certs() is not None
        assert root.get_timestamp_authorities() is not None

    def test_bad_media_type(self, asset):
        path = asset("trusted_root/trustedroot.badtype.json")

        with pytest.raises(
            ValueError,
            match=r"Input should be 'application/vnd\.dev\.sigstore\.trustedroot\+json;version=0\.1' or 'application/vnd\.dev\.sigstore\.trustedroot\.v0\.2\+json'",
        ):
            TrustedRoot.from_file(path)

    def test_get_tlog_note_verifiers_filtering_and_origin_normalization(self):
        now = datetime.now(UTC)

        def _make_tlog(
            base_url: str,
            *,
            key_details: PublicKeyDetails = PublicKeyDetails.ML_DSA_44,
            hash_algorithm: HashAlgorithm = HashAlgorithm.SHA2_256,
            valid_for: TimeRange | None = None,
        ) -> TransparencyLogInstance:
            if key_details == PublicKeyDetails.ML_DSA_44:
                pub = mldsa.MLDSA44PrivateKey.generate().public_key()
            else:
                pub = mldsa.MLDSA65PrivateKey.generate().public_key()
            spki = pub.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            return TransparencyLogInstance(
                base_url=base_url,
                hash_algorithm=hash_algorithm,
                public_key=PublicKey(
                    raw_bytes=base64.b64encode(spki),
                    key_details=key_details,
                    valid_for=valid_for,
                ),
                log_id=LogId(key_id=base64.b64encode(b"\x00" * 32)),
            )

        active_http = _make_tlog("http://http-log.example.com/")
        active_upper = _make_tlog("HTTPS://MixedCase.Example.com/shard/")
        active_bare = _make_tlog("bare.example.com")
        expired = _make_tlog(
            "https://expired.example.com",
            valid_for=TimeRange(
                start=now - timedelta(days=2),
                end=now - timedelta(days=1),
            ),
        )
        future = _make_tlog(
            "https://future.example.com",
            valid_for=TimeRange(start=now + timedelta(days=1)),
        )
        unsupported_hash = _make_tlog(
            "https://sha384.example.com",
            hash_algorithm=HashAlgorithm.SHA2_384,
        )
        unsupported_key = _make_tlog(
            "https://mldsa65.example.com",
            key_details=PublicKeyDetails.ML_DSA_65,
        )

        root = TrustedRoot(
            _TrustedRoot(
                media_type=TrustedRoot.TrustedRootType.TRUSTED_ROOT_0_1.value,
                tlogs=[
                    active_http,
                    active_upper,
                    active_bare,
                    expired,
                    future,
                    unsupported_hash,
                    unsupported_key,
                ],
            )
        )

        sign_verifiers = root.get_tlog_note_verifiers(KeyringPurpose.SIGN)
        assert [v.origin for v in sign_verifiers] == [
            "http-log.example.com",
            "MixedCase.Example.com/shard",
            "bare.example.com",
        ]

        verify_verifiers = root.get_tlog_note_verifiers(KeyringPurpose.VERIFY)
        assert [v.origin for v in verify_verifiers] == [
            "http-log.example.com",
            "MixedCase.Example.com/shard",
            "bare.example.com",
            "expired.example.com",
        ]

        # When no valid tlog verifiers remain, raises MetadataError
        empty_root = TrustedRoot(
            _TrustedRoot(
                media_type=TrustedRoot.TrustedRootType.TRUSTED_ROOT_0_1.value,
                tlogs=[future, unsupported_hash, unsupported_key],
            )
        )
        with pytest.raises(MetadataError, match="Did not find any Rekor keys"):
            empty_root.get_tlog_note_verifiers(KeyringPurpose.VERIFY)


# TODO(ww): Move these into appropriate class-scoped tests.


def test_trust_root_tuf_offline(mock_staging_tuf, tuf_dirs):
    # start with empty target cache, empty local metadata dir
    data_dir, _cache_dir = tuf_dirs

    # keep track of requests the TrustUpdater invoked by TrustedRoot makes
    reqs, fail_reqs = mock_staging_tuf

    trust_config = ClientTrustConfig.staging(offline=True)

    # local TUF metadata is not initialized, nothing is downloaded
    assert not os.path.exists(data_dir)
    assert reqs == {}
    assert fail_reqs == {}

    trust_config.trusted_root.ct_keyring(purpose=KeyringPurpose.VERIFY)
    trust_config.trusted_root.rekor_keyring(purpose=KeyringPurpose.VERIFY)

    # Still no requests
    assert reqs == {}
    assert fail_reqs == {}


def test_is_timerange_valid():
    def range_from(offset_lower=0, offset_upper=0):
        base = datetime.now(UTC)
        return TimeRange(
            start=base + timedelta(minutes=offset_lower),
            end=base + timedelta(minutes=offset_upper),
        )

    # Test None should always be valid
    assert is_timerange_valid(None, allow_expired=False)
    assert is_timerange_valid(None, allow_expired=True)

    # Test lower bound conditions
    assert is_timerange_valid(
        range_from(-1, 1), allow_expired=False
    )  # Valid: 1 ago, 1 from now
    assert not is_timerange_valid(
        range_from(1, 1), allow_expired=False
    )  # Invalid: 1 from now, 1 from now

    # Test upper bound conditions
    assert not is_timerange_valid(
        range_from(-1, -1), allow_expired=False
    )  # Invalid: 1 ago, 1 ago
    assert is_timerange_valid(
        range_from(-1, -1), allow_expired=True
    )  # Valid: 1 ago, 1 ago


def test_trust_root_tuf_instance_error(tuf_dirs):
    # embedded root.json is not found and no local metadata is found
    with pytest.raises(TUFError) as excinfo:
        ClientTrustConfig.from_tuf("foo.bar")

    diagnostics = excinfo.value.diagnostics()
    assert diagnostics.startswith(
        "Failed to refresh TUF metadata.\n\n"
        "Please check any Sigstore instance related arguments and consider "
        "reporting the issue at <https://github.com/sigstore/sigstore-python/issues/new>.\n\n"
        "Additional context:\n\n"
        "[Errno 2] No such file or directory:"
    )


def test_trust_root_tuf_http_error(monkeypatch, tuf_dirs):
    monkeypatch.setattr(
        urllib3.PoolManager,
        "request",
        lambda self, method, url, **kw: urllib3.HTTPResponse(status=503),
    )

    with pytest.raises(TUFError) as excinfo:
        ClientTrustConfig.staging()

    assert excinfo.value.diagnostics() == (
        "A network issue occurred.\n\n"
        "Check your internet connection and try again.\n\n"
        "Additional context:\n\n"
        "Failed to refresh TUF metadata: HTTP error occurred with status 503"
    )


def test_trust_root_tuf_ctfe_keys_error(monkeypatch):
    trust_root = ClientTrustConfig.staging(offline=True).trusted_root
    monkeypatch.setattr(trust_root._inner, "ctlogs", [])
    with pytest.raises(Exception, match="CTFE keys not found in trusted root"):
        trust_root.ct_keyring(purpose=KeyringPurpose.VERIFY)


def test_trust_root_fulcio_certs_error(tuf_asset, monkeypatch):
    trust_root = ClientTrustConfig.staging(offline=True).trusted_root
    monkeypatch.setattr(trust_root._inner, "certificate_authorities", [])
    with pytest.raises(
        Exception, match="Fulcio certificates not found in trusted root"
    ):
        trust_root.get_fulcio_certs()


class TestClientTrustConfig:
    def test_good(self, asset):
        path = asset("trust_config/config.v1.json")
        config = ClientTrustConfig.from_json(path.read_text())

        assert isinstance(config.signing_config, SigningConfig)
        assert isinstance(config.trusted_root, TrustedRoot)

    def test_bad_media_type(self, asset):
        path = asset("trust_config/config.badtype.json")

        with pytest.raises(
            ValueError,
            match=r"Input should be 'application/vnd\.dev\.sigstore\.clienttrustconfig.v0.1\+json'",
        ):
            ClientTrustConfig.from_json(path.read_text())

    def test_staging_v2_offline(self, tuf_dirs):
        config = ClientTrustConfig.staging_v2(offline=True)
        assert isinstance(config.signing_config, SigningConfig)
        assert isinstance(config.trusted_root, TrustedRoot)

        verifiers = config.trusted_root.get_tlog_note_verifiers(
            purpose=KeyringPurpose.VERIFY
        )
        assert [v.origin for v in verifiers] == ["pqc27-a1.us-east4.rekor.sigstage.dev"]
        assert isinstance(verifiers[0].public_key, mldsa.MLDSA44PublicKey)
        assert verifiers[0].key_id == config.trusted_root._inner.tlogs[0].log_id.key_id
        tlogs = config.signing_config.get_identity_tlogs()
        assert len(tlogs) == 1
        assert tlogs[0].url == "https://global-pqc.rekor.sigstage.dev/api/v2"
        assert (
            config.signing_config.get_oidc_url() == "https://oauth2.sigstage.dev/auth"
        )
        with pytest.raises(Error, match="No valid Fulcio CA found in signing config"):
            config.signing_config.get_fulcio()


class TestKeyringMLDSA:
    @pytest.mark.parametrize(
        ("key_details", "priv_cls", "pub_cls", "wrong_priv_cls"),
        [
            (
                PublicKeyDetails.ML_DSA_44,
                mldsa.MLDSA44PrivateKey,
                mldsa.MLDSA44PublicKey,
                mldsa.MLDSA65PrivateKey,
            ),
            (
                PublicKeyDetails.ML_DSA_65,
                mldsa.MLDSA65PrivateKey,
                mldsa.MLDSA65PublicKey,
                mldsa.MLDSA87PrivateKey,
            ),
            (
                PublicKeyDetails.ML_DSA_87,
                mldsa.MLDSA87PrivateKey,
                mldsa.MLDSA87PublicKey,
                mldsa.MLDSA44PrivateKey,
            ),
        ],
    )
    def test_mldsa_key_and_keyring(
        self, key_details, priv_cls, pub_cls, wrong_priv_cls
    ):
        priv = priv_cls.generate()
        pub_der = priv.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        pub_model = PublicKey(
            raw_bytes=base64.b64encode(pub_der),
            key_details=key_details,
        )

        key = Key(pub_model)
        assert key.hash_algorithm is None
        assert isinstance(key.key, pub_cls)

        data = b"sigstore v2 mldsa test payload"
        sig = priv.sign(data)
        key.verify(sig, data)

        keyring = Keyring([pub_model])
        keyring.verify(key_id=key.key_id, signature=sig, data=data)

        with pytest.raises(VerificationError, match="keyring: invalid signature"):
            keyring.verify(key_id=key.key_id, signature=sig, data=b"tampered")

        wrong_der = (
            wrong_priv_cls.generate()
            .public_key()
            .public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
        mismatched_model = PublicKey(
            raw_bytes=base64.b64encode(wrong_der),
            key_details=key_details,
        )
        with pytest.raises(VerificationError, match="invalid key format"):
            Key(mismatched_model)
