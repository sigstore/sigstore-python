#!/usr/bin/env python3

from setuptools import find_packages, setup

version = {}
with open("./pysign/_version.py") as f:
    exec(f.read(), version)

with open("./README.md") as f:
    long_description = f.read()

setup(
    name="pysign",
    version=version["__version__"],
    license="Apache-2.0",
    author="William Woodruff",
    author_email="william@trailofbits.com",
    description="A tool for signing Python package distributions",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/trailofbits/pysign",
    packages=find_packages(),
    entry_points={
        "console_scripts": [
            "pysign = pysign._cli:main",
        ]
    },
    platforms="any",
    python_requires=">=3.6",
    install_requires=[],
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
            # TODO: Remove this environment marker once 3.7 is our minimal version.
            "pdoc3; python_version >= '3.7'",
            "mypy",
        ]
    },
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: Apache Software License",
        "Intended Audience :: Developers",
        "Topic :: Security",
    ],
)
