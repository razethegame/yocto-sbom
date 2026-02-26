"""Fallback setup.py for older pip versions that don't support pyproject.toml."""
from setuptools import setup, find_packages

setup(
    name="yocto-sbom",
    version="0.1.0",
    description="Generate SPDX 2.3 and CycloneDX 1.5 SBOMs for pre-Kirkstone Yocto/PetaLinux projects",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    license="Apache-2.0",
    python_requires=">=3.6",
    packages=find_packages(),
    entry_points={
        "console_scripts": [
            "yocto-sbom=yocto_sbom.cli:main",
        ],
    },
    install_requires=[],
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: Apache Software License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
        "Programming Language :: Python :: 3 :: Only",
        "Topic :: Software Development :: Build Tools",
        "Topic :: Security",
        "Operating System :: OS Independent",
    ],
)
