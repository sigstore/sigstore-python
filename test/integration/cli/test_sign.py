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
from pathlib import Path

import pytest

from sigstore.models import Bundle
from sigstore.verify import Verifier
from sigstore.verify.policy import UnsafeNoOp


def get_cli_params(
    artifact_paths: list[Path],
    overwrite: bool = False,
    no_default_files: bool = False,
    output_directory: Path | None = None,
    bundle_path: Path | None = None,
    signature_path: Path | None = None,
    certificate_path: Path | None = None,
    trust_config_path: Path | None = None,
) -> list[str]:
    if trust_config_path is not None:
        cli_params = ["--trust-config", str(trust_config_path), "sign"]
    else:
        cli_params = ["--staging", "sign"]

    if output_directory is not None:
        cli_params.extend(["--output-directory", str(output_directory)])
    if bundle_path is not None:
        cli_params.extend(["--bundle", str(bundle_path)])
    if signature_path is not None:
        cli_params.extend(["--signature", str(signature_path)])
    if certificate_path is not None:
        cli_params.extend(["--certificate", str(certificate_path)])
    if overwrite:
        cli_params.append("--overwrite")
    if no_default_files:
        cli_params.append("--no-default-files")

    cli_params.extend([str(p) for p in artifact_paths])

    return cli_params


@pytest.mark.staging
@pytest.mark.ambient_oidc
def test_sign_success_default_output_bundle(
    capsys, sigstore, asset_integration, tmp_path
):
    artifact = asset_integration("a.txt")
    expected_output_bundle = tmp_path / "a.txt.sigstore.json"

    sigstore(
        *get_cli_params(
            artifact_paths=[artifact],
            output_directory=tmp_path,
        )
    )

    assert expected_output_bundle.exists()
    verifier = Verifier.staging()
    with (
        open(expected_output_bundle, "r", encoding="utf-8") as bundle_file,
        open(artifact, "rb") as input_file,
    ):
        bundle = Bundle.from_json(bundle_file.read())
        verifier.verify_artifact(
            input_=input_file.read(), bundle=bundle, policy=UnsafeNoOp()
        )

    captures = capsys.readouterr()
    assert captures.out.endswith(
        f"Sigstore bundle written to {expected_output_bundle}\n"
    )


@pytest.mark.staging
@pytest.mark.ambient_oidc
def test_sign_success_multiple_artifacts(capsys, sigstore, asset_integration, tmp_path):
    artifacts: list[Path] = [
        asset_integration("a.txt"),
        asset_integration("b.txt"),
        asset_integration("c.txt"),
    ]

    sigstore(
        *get_cli_params(
            artifact_paths=artifacts,
            output_directory=tmp_path,
        )
    )

    captures = capsys.readouterr()

    for artifact in artifacts:
        expected_output_bundle = tmp_path / f"{artifact.name}.sigstore.json"

        assert f"Sigstore bundle written to {expected_output_bundle}\n" in captures.out

        assert expected_output_bundle.exists()
        verifier = Verifier.staging()
        with (
            open(expected_output_bundle, "r", encoding="utf-8") as bundle_file,
            open(artifact, "rb") as input_file,
        ):
            bundle = Bundle.from_json(bundle_file.read())
            verifier.verify_artifact(
                input_=input_file.read(), bundle=bundle, policy=UnsafeNoOp()
            )


@pytest.mark.staging
@pytest.mark.ambient_oidc
def test_sign_success_multiple_artifacts_rekor_v2(
    capsys, sigstore, asset_integration, asset, tmp_path
):
    """This is a copy of test_sign_success_multiple_artifacts that exists to ensure the
    multi-threaded signing works with rekor v2 as well: this test can be removed when v2
    is the default
    """

    artifacts: list[Path] = [
        asset_integration("a.txt"),
        asset_integration("b.txt"),
        asset_integration("c.txt"),
    ]

    sigstore(
        *get_cli_params(
            artifact_paths=artifacts,
            output_directory=tmp_path,
        )
    )

    captures = capsys.readouterr()

    for artifact in artifacts:
        expected_output_bundle = tmp_path / f"{artifact.name}.sigstore.json"

        assert f"Sigstore bundle written to {expected_output_bundle}\n" in captures.out

        assert expected_output_bundle.exists()
        verifier = Verifier.staging()
        with (
            open(expected_output_bundle, "r", encoding="utf-8") as bundle_file,
            open(artifact, "rb") as input_file,
        ):
            bundle = Bundle.from_json(bundle_file.read())
            verifier.verify_artifact(
                input_=input_file.read(), bundle=bundle, policy=UnsafeNoOp()
            )


@pytest.mark.staging
@pytest.mark.ambient_oidc
def test_sign_success_custom_outputs(capsys, sigstore, asset_integration, tmp_path):
    artifact = asset_integration("a.txt")
    output_bundle = tmp_path / "bundle.json"
    output_cert = tmp_path / "cert.cert"
    output_signature = tmp_path / "signature.sig"

    sigstore(
        *get_cli_params(
            artifact_paths=[artifact],
            bundle_path=output_bundle,
            certificate_path=output_cert,
            signature_path=output_signature,
        )
    )

    assert output_bundle.exists()
    assert output_cert.exists()
    assert output_signature.exists()

    captures = capsys.readouterr()
    assert captures.out.endswith(
        f"Signature written to {output_signature}\nCertificate written to {output_cert}\nSigstore bundle written to {output_bundle}\n"
    )


@pytest.mark.staging
@pytest.mark.ambient_oidc
def test_sign_success_custom_output_dir(capsys, sigstore, asset_integration, tmp_path):
    artifact = asset_integration("a.txt")
    expected_output_bundle = tmp_path / "a.txt.sigstore.json"

    sigstore(
        *get_cli_params(
            artifact_paths=[artifact],
            output_directory=tmp_path,
        )
    )

    assert expected_output_bundle.exists()

    captures = capsys.readouterr()
    assert captures.out.endswith(
        f"Sigstore bundle written to {expected_output_bundle}\n"
    )


@pytest.mark.staging
@pytest.mark.ambient_oidc
def test_sign_success_no_default_files(capsys, sigstore, asset_integration, tmp_path):
    artifact = asset_integration("a.txt")
    default_output_bundle = tmp_path / "a.txt.sigstore.json"
    output_cert = tmp_path / "cert.cert"
    output_signature = tmp_path / "sig.sig"

    sigstore(
        *get_cli_params(
            artifact_paths=[artifact],
            signature_path=output_signature,
            certificate_path=output_cert,
            no_default_files=True,
        )
    )
    assert output_cert.exists()
    assert output_signature.exists()
    assert not default_output_bundle.exists()

    captures = capsys.readouterr()
    assert captures.out.endswith(
        f"Signature written to {output_signature}\nCertificate written to {output_cert}\n"
    )


@pytest.mark.staging
@pytest.mark.ambient_oidc
def test_sign_overwrite_existing_bundle(capsys, sigstore, asset_integration, tmp_path):
    artifact = asset_integration("a.txt")
    expected_output_bundle = tmp_path / "a.txt.sigstore.json"

    sigstore(
        *get_cli_params(
            artifact_paths=[artifact],
            output_directory=tmp_path,
        )
    )

    assert expected_output_bundle.exists()

    sigstore(
        *get_cli_params(
            artifact_paths=[artifact],
            output_directory=tmp_path,
            overwrite=True,
        )
    )
    assert expected_output_bundle.exists()

    with pytest.raises(SystemExit) as e:
        sigstore(
            *get_cli_params(
                artifact_paths=[artifact],
                output_directory=tmp_path,
                overwrite=False,
            )
        )
    assert e.value.code == 2

    captures = capsys.readouterr()
    assert captures.err.endswith(
        f"Refusing to overwrite outputs without --overwrite: {expected_output_bundle}\n"
    )


def test_sign_fails_with_default_files_and_bundle_options(
    capsys, sigstore, asset_integration
):
    artifact = asset_integration("a.txt")
    output_bundle = artifact.with_name("a.txt.sigstore.json")

    with pytest.raises(SystemExit) as e:
        sigstore(
            *get_cli_params(
                artifact_paths=[artifact],
                bundle_path=output_bundle,
                no_default_files=True,
            )
        )
    assert e.value.code == 2

    captures = capsys.readouterr()
    assert captures.err.endswith(
        "--no-default-files may not be combined with --bundle.\n"
    )


def test_sign_fails_with_multiple_inputs_and_custom_output(
    capsys, sigstore, asset_integration
):
    artifact = asset_integration("a.txt")

    with pytest.raises(SystemExit) as e:
        sigstore(
            *get_cli_params(
                artifact_paths=[artifact, artifact],
                bundle_path=artifact.with_name("a.txt.sigstore.json"),
            )
        )
    assert e.value.code == 2
    captures = capsys.readouterr()
    assert captures.err.endswith(
        "Error: --signature, --certificate, and --bundle can't be used with explicit outputs for multiple inputs.\n"
    )

    with pytest.raises(SystemExit) as e:
        sigstore(
            *get_cli_params(
                artifact_paths=[artifact, artifact],
                certificate_path=artifact.with_name("a.txt.cert"),
            )
        )
    assert e.value.code == 2
    captures = capsys.readouterr()
    assert captures.err.endswith(
        "Error: --signature, --certificate, and --bundle can't be used with explicit outputs for multiple inputs.\n"
    )

    with pytest.raises(SystemExit) as e:
        sigstore(
            *get_cli_params(
                artifact_paths=[artifact, artifact],
                signature_path=artifact.with_name("a.txt.sig"),
            )
        )
    assert e.value.code == 2
    captures = capsys.readouterr()
    assert captures.err.endswith(
        "Error: --signature, --certificate, and --bundle can't be used with explicit outputs for multiple inputs.\n"
    )


def test_sign_fails_with_output_dir_and_custom_output_files(
    capsys, sigstore, asset_integration
):
    artifact = asset_integration("a.txt")

    with pytest.raises(SystemExit) as e:
        sigstore(
            *get_cli_params(
                artifact_paths=[artifact],
                bundle_path=artifact.with_name("a.txt.sigstore.json"),
                output_directory=artifact.parent,
            )
        )
    assert e.value.code == 2
    captures = capsys.readouterr()
    assert captures.err.endswith(
        "Error: --signature, --certificate, and --bundle can't be used with an explicit output directory.\n"
    )

    with pytest.raises(SystemExit) as e:
        sigstore(
            *get_cli_params(
                artifact_paths=[artifact],
                certificate_path=artifact.with_name("a.txt.cert"),
                output_directory=artifact.parent,
            )
        )
    assert e.value.code == 2
    captures = capsys.readouterr()
    assert captures.err.endswith(
        "Error: --signature, --certificate, and --bundle can't be used with an explicit output directory.\n"
    )

    with pytest.raises(SystemExit) as e:
        sigstore(
            *get_cli_params(
                artifact_paths=[artifact],
                signature_path=artifact.with_name("a.txt.sig"),
                output_directory=artifact.parent,
            )
        )
    assert e.value.code == 2
    captures = capsys.readouterr()
    assert captures.err.endswith(
        "Error: --signature, --certificate, and --bundle can't be used with an explicit output directory.\n"
    )


def test_sign_fails_without_both_output_cert_and_signature(
    capsys, sigstore, asset_integration
):
    artifact = asset_integration("a.txt")

    with pytest.raises(SystemExit) as e:
        sigstore(
            *get_cli_params(
                artifact_paths=[artifact],
                certificate_path=artifact.with_name("a.txt.cert"),
            )
        )
    assert e.value.code == 2
    captures = capsys.readouterr()
    assert captures.err.endswith(
        "Error: --signature and --certificate must be used together.\n"
    )

    with pytest.raises(SystemExit) as e:
        sigstore(
            *get_cli_params(
                artifact_paths=[artifact],
                signature_path=artifact.with_name("a.txt.sig"),
            )
        )
    assert e.value.code == 2
    captures = capsys.readouterr()
    assert captures.err.endswith(
        "Error: --signature and --certificate must be used together.\n"
    )
