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
from collections.abc import Callable
from pathlib import Path

import pytest

from sigstore._cli import main


@pytest.fixture
def asset_integration(asset):
    def _asset(name: str) -> Path:
        return asset(f"integration/{name}")

    return _asset


@pytest.fixture(scope="function")
def sigstore() -> Callable:
    def _sigstore(*args: str):
        main(list(args))

    return _sigstore
