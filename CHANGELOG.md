# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
### Changed
### Deprecated
### Removed
### Fixed
### Security

## [0.1.0] - 2026-02-26

### Added
- Initial release of yocto-sbom
- SPDX 2.3 JSON SBOM generation
- CycloneDX 1.5 JSON SBOM generation
- BitBake recipe parser for .bb files
- Git submodule tracking with commit SHAs
- Yocto layer configuration parser (bblayers.conf)
- Third-party dependency resolution from DEPENDS/RDEPENDS
- Yocto license normalization to SPDX format (GPLv2 → GPL-2.0-only, etc.)
- CPE 2.3 identifier generation for vulnerability correlation
- PURL (Package URL) generation
- Built-in SBOM validation
- INI-based configuration with CLI override support
- Zero external dependencies (Python 3.6+ stdlib only)
- Support for Python 3.6, 3.7, 3.8, 3.9, 3.10, 3.11, 3.12, 3.13
- CI/CD workflows (GitHub Actions for tests and PyPI publishing)
- Example configuration files (minimal and full)
- GitLab CI and GitHub Actions integration examples

### Documentation
- Comprehensive README with quick start guide
- CLI reference documentation
- Configuration file examples
- Development setup instructions
- Publishing guide for PyPI

[Unreleased]: https://github.com/complira/yocto-sbom/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/complira/yocto-sbom/releases/tag/v0.1.0
