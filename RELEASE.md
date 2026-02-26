# Release Process

This document describes how to release a new version of yocto-sbom to PyPI.

## Semantic Versioning

We follow [Semantic Versioning](https://semver.org/): `MAJOR.MINOR.PATCH`

- **MAJOR** (1.0.0): Breaking changes (incompatible API changes)
- **MINOR** (0.2.0): New features (backward-compatible)
- **PATCH** (0.1.1): Bug fixes (backward-compatible)

## Release Checklist

### 1. Update Version Numbers

Edit these 3 files:
- `pyproject.toml` → `version = "0.2.0"`
- `setup.py` → `version="0.2.0"`
- `yocto_sbom/__init__.py` → `__version__ = "0.2.0"`

### 2. Update CHANGELOG.md

Move items from `[Unreleased]` to new version section:

```markdown
## [Unreleased]

## [0.2.0] - 2026-02-26

### Added
- New feature X

### Changed
- Changed behavior Y

### Fixed
- Bug fix Z
```

Update comparison links at bottom:
```markdown
[Unreleased]: https://github.com/complira/yocto-sbom/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/complira/yocto-sbom/compare/v0.1.0...v0.2.0
```

### 3. Commit and Tag

```bash
# Commit version bump
git add pyproject.toml setup.py yocto_sbom/__init__.py CHANGELOG.md
git commit -m "Release v0.2.0"

# Create annotated tag
git tag -a v0.2.0 -m "Release v0.2.0: Raise minimum Python to 3.8"

# Push commits and tags
git push origin main
git push origin v0.2.0
```

### 4. Create GitHub Release

This automatically triggers PyPI upload via GitHub Actions.

**Option A: Using gh CLI (recommended)**
```bash
gh release create v0.2.0 \
  --title "v0.2.0 - Python 3.8+ Required" \
  --notes-file RELEASE_NOTES.md
```

**Option B: Using web UI**
1. Go to https://github.com/complira/yocto-sbom/releases/new
2. Choose tag: `v0.2.0`
3. Release title: `v0.2.0 - Python 3.8+ Required`
4. Description: Copy from CHANGELOG.md
5. Click "Publish release"

**Option C: Auto-generate notes**
```bash
gh release create v0.2.0 --generate-notes
```

### 5. Verify PyPI Upload

After ~2 minutes, check:
- https://pypi.org/project/yocto-sbom/
- Verify new version appears
- Test install: `pip install yocto-sbom==0.2.0`

### 6. Post-Release

Update README badges if needed (they auto-update):
- PyPI version badge → shows latest version
- Python versions badge → shows supported versions

## Quick Reference

```bash
# Full release in one go:
vim pyproject.toml setup.py yocto_sbom/__init__.py CHANGELOG.md
git add pyproject.toml setup.py yocto_sbom/__init__.py CHANGELOG.md
git commit -m "Release v0.2.0"
git tag -a v0.2.0 -m "Release v0.2.0"
git push origin main && git push origin v0.2.0
gh release create v0.2.0 --generate-notes
```

## Troubleshooting

**PyPI upload failed?**
- Check GitHub Actions: https://github.com/complira/yocto-sbom/actions
- Verify `PYPI_API_TOKEN` secret is set
- Re-run failed workflow from GitHub UI

**Wrong version published?**
- You cannot overwrite a PyPI version
- Delete the release and tag locally
- Increment to next patch version (e.g., 0.2.1)
- PyPI does not allow deleting published versions

**Need to yank a bad release?**
```bash
# Mark version as yanked on PyPI (prevents new installs)
pip install twine
twine upload --repository pypi --skip-existing dist/*
# Then use PyPI web UI to yank the version
```

## Version History

- **v0.2.0** (2026-02-26): Raised minimum Python to 3.8
- **v0.1.0** (2026-02-26): Initial release
