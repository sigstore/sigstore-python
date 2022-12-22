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

"""
An empty module, used to assist Python's resource machinery in embedding
assets.
"""


# NOTE: This is arguably incorrect, since _store only contains non-Python files.
# However, due to how `importlib.resources` is designed, only top-level resources
# inside of packages or modules can be accessed, so this directory needs to be a
# module in order for us to programmatically access the keys and root certs in it.
#
# Why do we bother with `importlib` at all? Because we might be installed as a
# ZIP file or an Egg, which in turn means that our resource files don't actually
# exist separately on disk. `importlib` is the only reliable way to access them.
