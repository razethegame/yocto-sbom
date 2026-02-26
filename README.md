# yocto-sbom

[![Tests](https://github.com/yocto-sbom/yocto-sbom/actions/workflows/tests.yml/badge.svg)](https://github.com/yocto-sbom/yocto-sbom/actions/workflows/tests.yml)
[![PyPI version](https://img.shields.io/pypi/v/yocto-sbom)](https://pypi.org/project/yocto-sbom/)
[![Python versions](https://img.shields.io/pypi/pyversions/yocto-sbom)](https://pypi.org/project/yocto-sbom/)
[![License](https://img.shields.io/pypi/l/yocto-sbom)](https://github.com/yocto-sbom/yocto-sbom/blob/main/LICENSE)

Generate SPDX 2.3 and CycloneDX 1.5 SBOMs for pre-Kirkstone Yocto/PetaLinux firmware projects.

## Problem

Yocto added native SPDX support in Kirkstone (4.0, April 2022), and `meta-cyclonedx` also requires Kirkstone+. Many production firmware projects are stuck on older Yocto versions (Rocko, Sumo, Thud, Zeus, Dunfell) because upgrading BSPs for custom hardware is expensive. Meanwhile, regulations (EU Cyber Resilience Act, US EO 14028) require SBOMs now.

**yocto-sbom** fills this gap by parsing BitBake recipes, git submodules, and layer configurations to generate compliant SBOMs without requiring any Yocto version upgrade.

## Features

- **SPDX 2.3** and **CycloneDX 1.5** JSON output
- Parses `.bb` recipes for packages, versions, SRCREVs, licenses
- Tracks git submodules with commit SHAs
- Scans Yocto layers for third-party package metadata
- Yocto license normalization (GPLv2 -> GPL-2.0-only, etc.)
- CPE 2.3 and PURL generation for vulnerability correlation
- Built-in SBOM validation
- **Zero dependencies** — Python 3.6+ stdlib only (no pip packages required)
- Supports Python 3.6, 3.7, 3.8, 3.9, 3.10, 3.11, 3.12, 3.13

## Quick Start

```bash
pip install yocto-sbom

# Minimal usage
yocto-sbom --recipes-dir path/to/recipes --version 1.0.0

# With full configuration
yocto-sbom \
  --config yocto-sbom.conf \
  --version v1.2.3 \
  --validate
```

## Configuration

yocto-sbom uses INI config files (no YAML/TOML dependency). CLI arguments override config values.

```ini
[project]
product_name = My-Firmware

[vendor]
name = My Company
id = mycompany
supplier = Organization: My Company
namespace_uri = https://mycompany.com/spdx

[paths]
recipes_dir = recipes-myproject
gitmodules = .gitmodules
bblayers = build/conf/bblayers.conf
yocto_dir = yocto

[output]
spdx = sbom-spdx.json
cdx = sbom-cdx.json
```

See `examples/yocto-sbom.conf` for a fully commented example.

## CLI Reference

```
yocto-sbom [OPTIONS]

  -c, --config FILE        INI config file path
  --recipes-dir PATH       Directory with .bb recipe files (required)
  --version VERSION        Product version (required)
  --product-name NAME      Product name for SBOM document
  --vendor-id ID           Vendor ID for CPE/PURL
  --vendor-name NAME       Organization name for supplier fields
  --namespace-uri URI      Base URI for SPDX document namespace
  --gitmodules PATH        Path to .gitmodules
  --bblayers PATH          Path to bblayers.conf
  --yocto-dir PATH         Yocto directory for layer scanning
  --build-config NAME      Build configuration identifier
  --output-spdx PATH       Output SPDX JSON (default: sbom-spdx.json)
  --output-cdx PATH        Output CycloneDX JSON (default: sbom-cdx.json)
  --format {spdx,cdx,both} Which format(s) to generate (default: both)
  --validate               Validate after generation
  --quiet                  Suppress progress output
  -V                       Show version
```

Exit codes: 0 = success, 1 = error, 2 = validation failure.

## CI/CD Integration

See `examples/gitlab-ci.yml` and `examples/github-actions.yml` for ready-to-use CI templates.

## What It Parses

| Source | Information Extracted |
|--------|---------------------|
| `.bb` recipe files | Package name, version, license, SRCREV, SRC_URI, dependencies |
| `.gitmodules` | Submodule names, paths, URLs (credentials stripped) |
| `bblayers.conf` | Yocto layer names and paths |
| Yocto layer directories | Third-party package versions, licenses, homepages |

## Limitations

- Does not execute BitBake — parses recipe files statically
- Cannot resolve `${...}` variable expansions (except `${AUTOREV}`)
- SPDX document does not include file-level information
- License detection is best-effort based on the `LICENSE` field in recipes

## Development

```bash
git clone https://github.com/yocto-sbom/yocto-sbom.git
cd yocto-sbom
pip install -e .
python -m pytest tests/
```

## Publishing to PyPI

See [PUBLISHING.md](PUBLISHING.md) for instructions on building and uploading to PyPI, including CI/CD automation.

## License

Apache-2.0
