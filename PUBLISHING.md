# Publishing to PyPI

## Prerequisites

1. Create a [PyPI account](https://pypi.org/account/register/)
2. Enable 2FA (required for new projects)
3. Create an [API token](https://pypi.org/manage/account/token/) (scope: entire account, or project-specific after first upload)
4. Install build tools:
   ```bash
   pip install build twine
   ```

## Build

```bash
python -m build
```

This creates two files in `dist/`:
- `yocto_sbom-<version>.tar.gz` (source distribution)
- `yocto_sbom-<version>-py3-none-any.whl` (wheel)

## Test on TestPyPI (Recommended)

Before publishing to the real PyPI, test on [TestPyPI](https://test.pypi.org/):

1. Create a [TestPyPI account](https://test.pypi.org/account/register/) and API token
2. Upload:
   ```bash
   twine upload --repository testpypi dist/*
   ```
3. Test installation:
   ```bash
   pip install --index-url https://test.pypi.org/simple/ yocto-sbom
   ```

## Publish to PyPI

```bash
twine upload dist/*
```

When prompted:
- **Username:** `__token__`
- **Password:** your API token (starts with `pypi-`)

Alternatively, configure `~/.pypirc` to avoid prompts:

```ini
[pypi]
username = __token__
password = pypi-YOUR-TOKEN-HERE
```

## Release Checklist

1. Update version in both files:
   - `yocto_sbom/__init__.py` (`__version__`)
   - `pyproject.toml` (`version`)
2. Run tests: `python -m pytest tests/`
3. Clean old builds: `rm -rf dist/ build/ *.egg-info`
4. Build: `python -m build`
5. Check the package: `twine check dist/*`
6. Upload: `twine upload dist/*`
7. Tag the release: `git tag v<version> && git push --tags`

## CI/CD Publishing

### GitHub Actions (automated on tag push)

Add this workflow to `.github/workflows/publish.yml`:

```yaml
name: Publish to PyPI

on:
  push:
    tags:
      - 'v*'

jobs:
  publish:
    runs-on: ubuntu-latest
    permissions:
      id-token: write  # for trusted publishing
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-python@v5
        with:
          python-version: '3.9'

      - name: Install build tools
        run: pip install build

      - name: Build package
        run: python -m build

      - name: Publish to PyPI
        uses: pypa/gh-action-pypi-publish@release/v1
```

This uses [PyPI trusted publishing](https://docs.pypi.org/trusted-publishers/) — no API tokens needed. Configure it at PyPI under your project's publishing settings.

### GitLab CI

Add this job to `.gitlab-ci.yml`:

```yaml
publish-pypi:
  stage: release
  image: python:3.9
  script:
    - pip install build twine
    - python -m build
    - twine upload dist/*
  variables:
    TWINE_USERNAME: __token__
    TWINE_PASSWORD: $PYPI_TOKEN  # set in CI/CD variables
  rules:
    - if: $CI_COMMIT_TAG =~ /^v\d+\.\d+\.\d+$/
```

## Versioning

This project follows [Semantic Versioning](https://semver.org/):
- **MAJOR** — breaking changes to CLI or config format
- **MINOR** — new features (new output formats, parser improvements)
- **PATCH** — bug fixes
