#!/usr/bin/env python3

from setuptools import find_packages, setup

version = {}
with open("./sigstore/_version.py") as f:
    exec(f.read(), version)

with open("./README.md") as f:
    long_description = f.read()

setup(
    name="sigstore",
    version=version["__version__"],
    license="Apache-2.0",
    author="William Woodruff",
    author_email="william@trailofbits.com",
    description="A tool for signing Python package distributions",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/trailofbits/sigstore-python",
    packages=find_packages(),
    entry_points={
        "console_scripts": [
            "sigstore = sigstore._cli:main",
        ]
    },
    platforms="any",
    python_requires=">=3.7",
    install_requires=["click>=8", "cryptography", "pem", "requests"],
    extras_require={
        "dev": [
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
        "Development Status :: 1 - Planning",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "Topic :: Security :: Cryptography",
    ],
)
