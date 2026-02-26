"""Yocto bblayers.conf parsing."""

import os
import re


def parse_bblayers(bblayers_path):
    """Parse bblayers.conf and return list of layer dicts.

    Args:
        bblayers_path: Path to bblayers.conf file.

    Returns:
        List of dicts with 'name' and 'path' keys.
    """
    layers = []
    if not os.path.isfile(bblayers_path):
        return layers

    with open(bblayers_path, 'r') as f:
        content = f.read()

    match = re.search(r'BBLAYERS\s*\??=\s*"([^"]+)"', content, re.DOTALL)
    if not match:
        return layers

    for raw in match.group(1).split():
        raw = raw.strip().rstrip('\\')
        if not raw:
            continue
        # Normalise: use the last path component as layer name
        name = raw.split('/')[-1]
        layers.append({'name': name, 'path': raw})

    return layers
