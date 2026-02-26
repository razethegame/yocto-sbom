"""Third-party dependency collection and Yocto layer scanning."""

import os
import re


def scan_yocto_layer_packages(yocto_dir):
    """Scan Yocto layer directories for .bb files to build a package metadata map.

    Parses each .bb file for LICENSE, HOMEPAGE, and extracts version from filename.
    The .bb filename format is <name>_<version>.bb (e.g. boost_1.66.0.bb).
    When multiple versions exist, the highest (last sorted) is kept.

    Args:
        yocto_dir: Path to yocto/ directory containing layers.

    Returns:
        Dict mapping package_name to {version, license, homepage}.
    """
    pkg_map = {}
    if not os.path.isdir(yocto_dir):
        return pkg_map

    for root, _, files in os.walk(yocto_dir):
        for fname in files:
            if not fname.endswith('.bb'):
                continue
            base = fname[:-3]  # strip .bb
            parts = base.split('_', 1)
            name = parts[0]
            ver = parts[1] if len(parts) == 2 else ''
            if ver and ver.startswith('%'):
                continue
            # Keep the highest version found (simple lexicographic)
            if name in pkg_map and ver <= pkg_map[name].get('version', ''):
                continue

            # Parse LICENSE and HOMEPAGE from the .bb file
            bb_path = os.path.join(root, fname)
            license_val = ''
            homepage_val = ''
            try:
                with open(bb_path, 'r', errors='ignore') as f:
                    for line in f:
                        if line.startswith('LICENSE') and '=' in line:
                            m = re.match(r'^LICENSE\s*=\s*"([^"]*)"', line)
                            if m:
                                license_val = m.group(1).strip()
                        elif line.startswith('HOMEPAGE') and '=' in line:
                            m = re.match(r'^HOMEPAGE\s*=\s*"([^"]*)"', line)
                            if m:
                                homepage_val = m.group(1).strip()
                        if license_val and homepage_val:
                            break
            except OSError:
                pass

            pkg_map[name] = {
                'version': ver,
                'license': license_val,
                'homepage': homepage_val,
            }

    return pkg_map


def guess_parent_recipe(dep_name):
    """Guess possible parent recipe names for a runtime/sub-package dependency.

    Returns candidate names to look up in the Yocto layer package map.
    E.g. 'libopencv-core' -> ['opencv-core', 'opencv', 'libopencv-core']
         'python3-flask'  -> ['python3', 'python3-flask']
         'protobuf-native' -> ['protobuf', 'protobuf-native']

    Args:
        dep_name: Dependency package name.

    Returns:
        List of candidate recipe names.
    """
    candidates = []
    # lib<name> -> <name>
    if dep_name.startswith('lib'):
        stripped = dep_name[3:]
        candidates.append(stripped)
        # lib<base>-<suffix> -> <base> (e.g. libopencv-core -> opencv)
        if '-' in stripped:
            candidates.append(stripped.split('-')[0])
    # <name>-native, <name>-lite, <name>-misc, etc. -> <name>
    for suffix in ('-native', '-lite', '-misc', '-ubifs', '-fw-utils'):
        if dep_name.endswith(suffix):
            candidates.append(dep_name[:-len(suffix)])
    # python3-<subpkg> -> python3
    if dep_name.startswith('python3-'):
        candidates.append('python3')
    # <base>-<suffix> generic (e.g. mtd-utils-misc -> mtd-utils)
    if '-' in dep_name:
        parts = dep_name.rsplit('-', 1)
        candidates.append(parts[0])
    return candidates


def collect_third_party_deps(recipes, yocto_dirs=None, quiet=False):
    """Collect unique third-party dependencies from DEPENDS and RDEPENDS.

    Args:
        recipes: Parsed recipe dicts from parse_all_recipes().
        yocto_dirs: Path(s) to yocto directory/directories to scan for package
            versions. Accepts a single string (backward compat) or a list of
            strings. Multiple directories are merged, preferring entries with
            real versions over NOASSERTION.
        quiet: Suppress progress output.

    Returns:
        Tuple of (deps, dep_graph) where:
            deps: {dep_name: {name, license, homepage, version}}
            dep_graph: {recipe_name: [dep_names]}
    """
    # Normalize yocto_dirs to a list
    if yocto_dirs is None:
        yocto_dirs = []
    elif isinstance(yocto_dirs, str):
        yocto_dirs = [yocto_dirs] if yocto_dirs else []

    # Scan Yocto layers for package metadata (version, license, homepage)
    # Merge results from all directories, preferring entries with real versions
    layer_packages = {}
    for ydir in yocto_dirs:
        for name, info in scan_yocto_layer_packages(ydir).items():
            existing = layer_packages.get(name)
            if not existing:
                layer_packages[name] = info
            elif (existing.get('version') in ('', 'NOASSERTION')
                  and info.get('version') not in ('', 'NOASSERTION')):
                layer_packages[name] = info
    if layer_packages and not quiet:
        print("  -> Scanned {} packages from Yocto layers".format(len(layer_packages)))

    recipe_names = set(r['_recipe_name'] for r in recipes)
    # Variables / internal tokens to skip
    skip = {'${PN}', '${AUTOREV}', 'os-release'}

    all_deps = {}       # dep_name -> metadata dict
    dep_graph = {}      # recipe_name -> [dep_name, ...]

    for recipe in recipes:
        rname = recipe['_recipe_name']
        raw_deps = (recipe.get('DEPENDS', '') + ' ' + recipe.get('RDEPENDS', '')).split()
        recipe_deps = []
        for dep in raw_deps:
            dep = dep.strip()
            if not dep or dep in skip:
                continue
            # Skip deps that are our own recipes (internal deps)
            if dep in recipe_names:
                continue
            # Also skip lib-prefixed versions of our recipes
            if dep.startswith('lib') and dep[3:] in recipe_names:
                continue

            recipe_deps.append(dep)
            if dep not in all_deps:
                # Look up metadata: try direct name, then guess parent recipe
                pkg_info = layer_packages.get(dep)
                if not pkg_info:
                    for candidate in guess_parent_recipe(dep):
                        pkg_info = layer_packages.get(candidate)
                        if pkg_info:
                            break
                pkg_info = pkg_info or {}

                all_deps[dep] = {
                    'name': dep,
                    'license': pkg_info.get('license') or 'NOASSERTION',
                    'homepage': pkg_info.get('homepage', ''),
                    'version': pkg_info.get('version') or 'NOASSERTION',
                }
        if recipe_deps:
            dep_graph[rname] = sorted(set(recipe_deps))

    return all_deps, dep_graph
