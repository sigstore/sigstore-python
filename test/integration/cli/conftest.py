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

from pathlib import Path
from typing import Callable

import pytest

from sigstore._cli import main

_ASSETS = (Path(__file__).parent.parent.parent / "assets/integration").resolve()
assert _ASSETS.is_dir()


@pytest.fixture
def asset():
    def _asset(name: str) -> Path:
        return _ASSETS / name

    return _asset


@pytest.fixture(scope="function")
def sigstore() -> Callable:
    def _sigstore(*args: str):
        main(list(args))

    return _sigstore
