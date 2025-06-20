# Copyright 2024 The Sigstore Authors
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
import pytest


@pytest.mark.staging
def test_regression_verify_legacy_bundle(capsys, caplog, asset_integration, sigstore):
    # Check that verification continues to work when legacy bundle is present (*.sigstore) and
    # no cert, sig and normal bundle (*.sigstore.json) are present.
    artifact_filename = "bundle_v3.txt"
    artifact = asset_integration(artifact_filename)
    legacy_bundle = asset_integration(f"{artifact_filename}.sigstore")

    sig = asset_integration(f"{artifact_filename}.sig")
    cert = asset_integration(f"{artifact_filename}.crt")
    bundle = asset_integration(f"{artifact_filename}.sigstore.json")
    assert not cert.is_file()
    assert not sig.is_file()
    assert not bundle.is_file()

    sigstore(
        "--staging",
        "verify",
        "identity",
        str(artifact),
        "--cert-identity",
        "william@yossarian.net",
        "--cert-oidc-issuer",
        "https://github.com/login/oauth",
    )

    captures = capsys.readouterr()
    assert captures.err == f"OK: {artifact.absolute()}\n"

    assert (
        caplog.records[0].message
        == f"{artifact.absolute()}: {legacy_bundle.absolute()} should be named {bundle.absolute()}. Support for discovering 'bare' .sigstore inputs will be deprecated in a future release."
    )
