"""Command-line interface for yocto-sbom."""

import argparse
import json
import sys

from yocto_sbom import __version__
from yocto_sbom.config import SbomConfig
from yocto_sbom.generators.cyclonedx import generate_cyclonedx
from yocto_sbom.generators.spdx import generate_spdx
from yocto_sbom.parsers.bblayers import parse_bblayers
from yocto_sbom.parsers.bitbake import parse_all_recipes
from yocto_sbom.parsers.dependencies import collect_third_party_deps
from yocto_sbom.parsers.gitmodules import get_submodule_commits, parse_gitmodules
from yocto_sbom.validate import validate_cdx, validate_spdx


def main():
    parser = argparse.ArgumentParser(
        prog='yocto-sbom',
        description='Generate SPDX 2.3 and CycloneDX 1.5 SBOMs for Yocto/PetaLinux projects.',
    )
    parser.add_argument(
        '-c', '--config', dest='config_file', default=None,
        help='INI config file path',
    )
    parser.add_argument(
        '--recipes-dir', default=None,
        help='Directory with .bb recipe files (required)',
    )
    parser.add_argument(
        '--version', default=None,
        help='Product version (required)',
    )
    parser.add_argument(
        '--product-name', default=None,
        help='Product name for SBOM document',
    )
    parser.add_argument(
        '--vendor-id', default=None,
        help='Vendor ID for CPE/PURL (e.g., "mycompany")',
    )
    parser.add_argument(
        '--vendor-name', default=None,
        help='Organization name for supplier fields',
    )
    parser.add_argument(
        '--namespace-uri', default=None,
        help='Base URI for SPDX document namespace',
    )
    parser.add_argument(
        '--gitmodules', default=None,
        help='Path to .gitmodules',
    )
    parser.add_argument(
        '--bblayers', default=None,
        help='Path to bblayers.conf',
    )
    parser.add_argument(
        '--yocto-dir', default=None, nargs='+',
        help='Yocto directory/directories for layer scanning (multiple allowed)',
    )
    parser.add_argument(
        '--build-config', default=None,
        help='Build configuration identifier',
    )
    parser.add_argument(
        '--output-spdx', default=None,
        help='Output SPDX JSON path (default: sbom-spdx.json)',
    )
    parser.add_argument(
        '--output-cdx', default=None,
        help='Output CycloneDX JSON path (default: sbom-cdx.json)',
    )
    parser.add_argument(
        '--format', choices=['spdx', 'cdx', 'both'], default=None,
        help='Which format(s) to generate (default: both)',
    )
    parser.add_argument(
        '--validate', action='store_true', default=False,
        help='Validate after generation',
    )
    parser.add_argument(
        '--quiet', action='store_true', default=False,
        help='Suppress progress output',
    )
    parser.add_argument(
        '-V', action='version', version='yocto-sbom {}'.format(__version__),
    )
    args = parser.parse_args()

    # Build config: INI file first, then CLI overrides
    if args.config_file:
        try:
            config = SbomConfig.from_ini(args.config_file)
        except FileNotFoundError as e:
            print("Error: {}".format(e), file=sys.stderr)
            sys.exit(1)
    else:
        config = SbomConfig()

    config.apply_cli_args(args)

    # Validate required fields
    errors = config.validate_required()
    if errors:
        for err in errors:
            print("Error: {}".format(err), file=sys.stderr)
        sys.exit(1)

    quiet = config.quiet

    # Parse inputs
    if not quiet:
        print("Parsing recipes from: {}".format(config.recipes_dir))
    recipes = parse_all_recipes(config.recipes_dir, quiet=quiet)
    if not quiet:
        print("  -> {} recipes parsed".format(len(recipes)))

    submodules = []
    submodule_commits = {}
    if config.gitmodules:
        if not quiet:
            print("Parsing submodules from: {}".format(config.gitmodules))
        submodules = parse_gitmodules(config.gitmodules)
        if not quiet:
            print("  -> {} submodules found".format(len(submodules)))
        submodule_commits = get_submodule_commits()
        if not quiet:
            print("  -> {} submodule commits resolved".format(len(submodule_commits)))

    layers = []
    if config.bblayers:
        if not quiet:
            print("Parsing layers from: {}".format(config.bblayers))
        layers = parse_bblayers(config.bblayers)
        if not quiet:
            print("  -> {} layers found".format(len(layers)))

    if not quiet:
        print("Collecting third-party dependencies from DEPENDS/RDEPENDS...")
    third_party_deps, dep_graph = collect_third_party_deps(
        recipes, config.yocto_dirs, quiet=quiet,
    )
    if not quiet:
        print("  -> {} unique third-party dependencies found".format(len(third_party_deps)))

    fmt = config.output_format
    validation_ok = True

    # Generate SPDX
    if fmt in ('spdx', 'both'):
        spdx = generate_spdx(
            recipes, submodules, submodule_commits, layers,
            third_party_deps, dep_graph, config,
        )
        with open(config.output_spdx, 'w') as f:
            json.dump(spdx, f, indent=2)
        if not quiet:
            print("SPDX 2.3 written to: {}".format(config.output_spdx))

    # Generate CycloneDX
    if fmt in ('cdx', 'both'):
        cdx = generate_cyclonedx(
            recipes, submodules, submodule_commits, layers,
            third_party_deps, dep_graph, config,
        )
        with open(config.output_cdx, 'w') as f:
            json.dump(cdx, f, indent=2)
        if not quiet:
            print("CycloneDX 1.5 written to: {}".format(config.output_cdx))

    # Summary
    if not quiet:
        total = len(recipes) + len(submodules) + len(layers) + len(third_party_deps)
        print("\nSBOM Summary:")
        print("  Recipes:        {}".format(len(recipes)))
        print("  Submodules:     {}".format(len(submodules)))
        print("  Layers:         {}".format(len(layers)))
        print("  3rd-party deps: {}".format(len(third_party_deps)))
        print("  Total:          {} components".format(total))

    # Validate if requested
    if config.validate:
        print("")
        if fmt in ('spdx', 'both'):
            if not validate_spdx(config.output_spdx, quiet=quiet):
                validation_ok = False
        if fmt in ('cdx', 'both'):
            if not validate_cdx(config.output_cdx, quiet=quiet):
                validation_ok = False

        if validation_ok:
            print("\nAll validations PASSED")
        else:
            print("\nValidation FAILED")
            sys.exit(2)


if __name__ == '__main__':
    main()
