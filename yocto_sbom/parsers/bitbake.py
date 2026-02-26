"""BitBake .bb recipe parsing."""

import os
import re


def find_bb_files(start_path):
    """Find all .bb files recursively from the start path.

    Args:
        start_path: Directory to search.

    Returns:
        Set of absolute paths to .bb files.
    """
    if not os.path.exists(start_path):
        return set()
    if not os.path.isdir(start_path):
        return set()

    bb_files = set()
    for root, _, files in os.walk(start_path):
        for file in files:
            if file.endswith('.bb'):
                bb_files.add(os.path.join(root, file))
    return bb_files


def get_recipe_name_and_version(bb_file):
    """Extract recipe name and version from bb file path.

    Args:
        bb_file: Path to a .bb file.

    Returns:
        Tuple of (name, version).
    """
    base_name = os.path.basename(bb_file)[:-3]  # strip .bb
    parts = base_name.split('_', 1)
    if len(parts) == 2:
        return parts[0], parts[1]
    return base_name, ""


def parse_bb_file(bb_file_path):
    """Parse a .bb file and extract key metadata fields.

    Args:
        bb_file_path: Path to the .bb file.

    Returns:
        Dict with recipe metadata.
    """
    fields = {
        'SUMMARY': '',
        'DESCRIPTION': '',
        'LICENSE': '',
        'LIC_FILES_CHKSUM': '',
        'SRCREV': '',
        'SRCBRANCH': '',
        'SRC_URI': '',
        'PV': '',
        'DEPENDS': '',
    }

    recipe_name, version = get_recipe_name_and_version(bb_file_path)
    fields['_recipe_name'] = recipe_name
    fields['_version'] = version

    try:
        with open(bb_file_path, 'r') as f:
            content = f.read()
    except OSError:
        return fields

    for key in ['SUMMARY', 'DESCRIPTION', 'LICENSE', 'LIC_FILES_CHKSUM',
                'SRCREV', 'SRCBRANCH', 'DEPENDS']:
        match = re.search(
            r'^{}\s*=\s*"([^"]*)"'.format(key),
            content,
            re.MULTILINE,
        )
        if match:
            fields[key] = match.group(1).strip()

    # Parse RDEPENDS (runtime dependencies) - can have package-specific suffixes
    rdepends_parts = []
    for m in re.finditer(r'^RDEPENDS_\S+\s*[+=]*\s*"([^"]*)"', content, re.MULTILINE):
        rdepends_parts.append(m.group(1).strip())
    fields['RDEPENDS'] = ' '.join(rdepends_parts)

    # SRC_URI can span multiple lines with backslash continuation
    src_uri_match = re.search(
        r'^SRC_URI\s*=\s*"((?:[^"\\]|\\.)*)"',
        content,
        re.MULTILINE | re.DOTALL,
    )
    if src_uri_match:
        fields['SRC_URI'] = ' '.join(src_uri_match.group(1).split())

    # PV may be set explicitly or derived from filename
    pv_match = re.search(r'^PV\s*=\s*"([^"]*)"', content, re.MULTILINE)
    if pv_match:
        fields['PV'] = pv_match.group(1).strip()
    elif version:
        fields['PV'] = version

    return fields


def parse_all_recipes(recipes_dir, quiet=False):
    """Parse all .bb files in the recipes directory.

    Args:
        recipes_dir: Path to directory containing .bb files.
        quiet: Suppress progress output.

    Returns:
        List of recipe metadata dicts.
    """
    bb_files = find_bb_files(recipes_dir)
    if not bb_files:
        if not quiet:
            print("Warning: No .bb files found in {}".format(recipes_dir))
        return []

    if not quiet:
        print("Found {} .bb files in {}".format(len(bb_files), recipes_dir))
    recipes = []
    for bb_file in sorted(bb_files):
        recipe = parse_bb_file(bb_file)
        recipe['_file'] = bb_file
        recipes.append(recipe)
    return recipes
