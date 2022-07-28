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

from sigstore._verify import (
    CertificateVerificationFailure,
    VerificationFailure,
    VerificationSuccess,
    Verifier,
)


def test_verifier_production():
    verifier = Verifier.production()
    assert verifier is not None


def test_verifier_staging():
    verifier = Verifier.staging()
    assert verifier is not None


def test_verifier_one_verification(signed_asset):
    a_assets = signed_asset("a.txt")

    verifier = Verifier.staging()
    assert verifier.verify(a_assets[0], a_assets[1], a_assets[2])


def test_verifier_multiple_verifications(signed_asset):
    a_assets = signed_asset("a.txt")
    b_assets = signed_asset("b.txt")

    verifier = Verifier.staging()
    for assets in [a_assets, b_assets]:
        assert verifier.verify(assets[0], assets[1], assets[2])


def test_verify_result_boolish():
    assert not VerificationFailure(reason="foo")
    assert not CertificateVerificationFailure(reason="foo", exception=ValueError("bar"))
    assert VerificationSuccess()
