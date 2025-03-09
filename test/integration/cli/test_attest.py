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
from typing import Optional

import pytest

from sigstore.dsse._predicate import PredicateType
from sigstore.models import Bundle
from sigstore.verify import Verifier
from sigstore.verify.policy import UnsafeNoOp


def get_cli_params(
    pred_type: str,
    pred_path: Path,
    artifact_path: Path,
    overwrite: bool = False,
    bundle_path: Optional[Path] = None,
) -> list[str]:
    cli_params = [
        "--staging",
        "attest",
        "--predicate-type",
        pred_type,
        "--predicate",
        str(pred_path),
    ]
    if bundle_path is not None:
        cli_params.extend(["--bundle", str(bundle_path)])
    if overwrite:
        cli_params.append("--overwrite")
    cli_params.append(str(artifact_path))

    return cli_params


@pytest.mark.staging
@pytest.mark.ambient_oidc
@pytest.mark.parametrize(
    ("predicate_type", "predicate_filename"),
    [
        (PredicateType.SLSA_v0_2, "slsa_predicate_v0_2.json"),
        (PredicateType.SLSA_v1_0, "slsa_predicate_v1_0.json"),
    ],
)
def test_attest_success_default_output_bundle(
    capsys, sigstore, asset_integration, predicate_type, predicate_filename
):
    predicate_path = asset_integration(f"attest/{predicate_filename}")
    artifact = asset_integration("a.txt")
    expected_output_bundle = artifact.with_name("a.txt.sigstore.json")

    assert not expected_output_bundle.exists()
    sigstore(
        *get_cli_params(
            pred_type=predicate_type,
            pred_path=predicate_path,
            artifact_path=artifact,
        )
    )

    assert expected_output_bundle.exists()
    verifier = Verifier.staging()
    with open(expected_output_bundle, "r") as bundle_file:
        bundle = Bundle.from_json(bundle_file.read())
        verifier.verify_dsse(bundle=bundle, policy=UnsafeNoOp())

    expected_output_bundle.unlink()

    captures = capsys.readouterr()
    assert captures.out.endswith(
        f"Sigstore bundle written to {str(expected_output_bundle)}\n"
    )


@pytest.mark.staging
@pytest.mark.ambient_oidc
def test_attest_success_custom_output_bundle(
    capsys, sigstore, asset_integration, tmp_path
):
    predicate_type = PredicateType.SLSA_v0_2
    predicate_filename = "slsa_predicate_v0_2.json"
    predicate_path = asset_integration(f"attest/{predicate_filename}")
    artifact = asset_integration("a.txt")

    output_bundle = tmp_path / "bundle.json"
    assert not output_bundle.exists()
    sigstore(
        *get_cli_params(
            pred_type=predicate_type,
            pred_path=predicate_path,
            artifact_path=artifact,
            bundle_path=output_bundle,
        )
    )

    assert output_bundle.exists()
    captures = capsys.readouterr()
    assert captures.out.endswith(f"Sigstore bundle written to {str(output_bundle)}\n")


@pytest.mark.staging
@pytest.mark.ambient_oidc
def test_attest_overwrite_existing_bundle(
    capsys, sigstore, asset_integration, tmp_path
):
    predicate_type = PredicateType.SLSA_v0_2
    predicate_filename = "slsa_predicate_v0_2.json"
    predicate_path = asset_integration(f"attest/{predicate_filename}")
    artifact = asset_integration("a.txt")

    output_bundle = tmp_path / "bundle.json"
    assert not output_bundle.exists()

    cli_params = get_cli_params(
        pred_type=predicate_type,
        pred_path=predicate_path,
        artifact_path=artifact,
        bundle_path=output_bundle,
    )
    sigstore(*cli_params)
    assert output_bundle.exists()

    # On invalid argument errors we call `Argumentparser.error`, which prints
    # a message and exits with code 2
    with pytest.raises(SystemExit) as e:
        sigstore(*cli_params)
    assert e.value.code == 2

    assert output_bundle.exists()
    captures = capsys.readouterr()
    assert captures.err.endswith(
        f"Refusing to overwrite outputs without --overwrite: {str(output_bundle)}\n"
    )

    cli_params.append("--overwrite")
    sigstore(*cli_params)
    assert output_bundle.exists()

    assert captures.out.endswith(f"Sigstore bundle written to {str(output_bundle)}\n")


def test_attest_invalid_predicate_type(capsys, sigstore, asset_integration, tmp_path):
    predicate_type = "invalid_type"
    predicate_filename = "slsa_predicate_v0_2.json"
    predicate_path = asset_integration(f"attest/{predicate_filename}")
    artifact = asset_integration("a.txt")

    output_bundle = tmp_path / "bundle.json"
    # On invalid argument errors we call `Argumentparser.error`, which prints
    # a message and exits with code 2
    with pytest.raises(SystemExit) as e:
        sigstore(
            *get_cli_params(
                pred_type=predicate_type,
                pred_path=predicate_path,
                artifact_path=artifact,
                bundle_path=output_bundle,
            )
        )
    assert e.value.code == 2

    captures = capsys.readouterr()
    assert captures.err.endswith(f"invalid PredicateType value: '{predicate_type}'\n")


def test_attest_mismatching_predicate(capsys, sigstore, asset_integration, tmp_path):
    predicate_type = PredicateType.SLSA_v0_2
    predicate_filename = "slsa_predicate_v1_0.json"
    predicate_path = asset_integration(f"attest/{predicate_filename}")
    artifact = asset_integration("a.txt")

    output_bundle = tmp_path / "bundle.json"
    # On invalid argument errors we call `Argumentparser.error`, which prints
    # a message and exits with code 2
    with pytest.raises(SystemExit) as e:
        sigstore(
            *get_cli_params(
                pred_type=predicate_type,
                pred_path=predicate_path,
                artifact_path=artifact,
                bundle_path=output_bundle,
            )
        )
    assert e.value.code == 2

    captures = capsys.readouterr()
    assert f'Unable to parse predicate of type "{predicate_type}":' in captures.err


def test_attest_missing_predicate(capsys, sigstore, asset_integration, tmp_path):
    predicate_type = PredicateType.SLSA_v0_2
    predicate_filename = "doesnt_exist.json"
    predicate_path = asset_integration(f"attest/{predicate_filename}")
    artifact = asset_integration("a.txt")

    output_bundle = tmp_path / "bundle.json"
    # On invalid argument errors we call `Argumentparser.error`, which prints
    # a message and exits with code 2
    with pytest.raises(SystemExit) as e:
        sigstore(
            *get_cli_params(
                pred_type=predicate_type,
                pred_path=predicate_path,
                artifact_path=artifact,
                bundle_path=output_bundle,
            )
        )
    assert e.value.code == 2

    captures = capsys.readouterr()
    assert captures.err.endswith(f"Predicate must be a file: {predicate_path}\n")


def test_attest_invalid_json_predicate(capsys, sigstore, asset_integration, tmp_path):
    predicate_type = PredicateType.SLSA_v0_2
    predicate_path = asset_integration("a.txt")
    artifact = asset_integration("a.txt")

    output_bundle = tmp_path / "bundle.json"
    # On invalid argument errors we call `Argumentparser.error`, which prints
    # a message and exits with code 2
    with pytest.raises(SystemExit) as e:
        sigstore(
            *get_cli_params(
                pred_type=predicate_type,
                pred_path=predicate_path,
                artifact_path=artifact,
                bundle_path=output_bundle,
            )
        )
    assert e.value.code == 2

    captures = capsys.readouterr()
    assert f'Unable to parse predicate of type "{predicate_type}":' in captures.err
