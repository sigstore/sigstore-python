#!/usr/bin/env python3
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

import importlib

from setuptools import find_packages, setup

version = importlib.import_module("sigstore._version")

with open("./README.md") as f:
    long_description = f.read()

setup(
    name="sigstore",
    version=version.__version__,
    license="Apache-2.0",
    author="Sigstore Authors",
    author_email="sigstore-dev@googlegroups.com",
    description="A tool for signing Python package distributions",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/sigstore/sigstore-python",
    packages=find_packages(),
    package_data={"sigstore": ["_store/*"]},
    include_package_data=True,
    entry_points={
        "console_scripts": [
            "sigstore = sigstore._cli:main",
        ]
    },
    platforms="any",
    python_requires=">=3.7",
    install_requires=[
        "click>=8",
        "cryptography",
        "pem",
        "pydantic",
        "pyjwt",
        "pyOpenSSL",
        "requests",
        "securesystemslib",
    ],
    extras_require={
        "dev": [
            "build",
            "bump",
            "flake8",
            "black",
            "isort",
            "pytest",
            "pytest-cov",
            "pretend",
            "coverage[toml]",
            "interrogate",
            "pdoc3",
            "mypy",
            "types-cryptography",
            "types-requests",
            "types-pyOpenSSL",
            "types-pyjwt",
        ]
    },
    classifiers=[
        "License :: OSI Approved :: Apache Software License",
        "Programming Language :: Python :: 3 :: Only",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "Topic :: Security :: Cryptography",
    ],
)
