"""CycloneDX 1.5 JSON SBOM generation."""

import uuid
from datetime import datetime, timezone

from yocto_sbom.generators.common import (
    clean_download_location,
    make_cpe,
    normalize_license,
    recipe_purl,
    spdx_id,
    third_party_cpe,
    third_party_purl,
)


def license_to_cdx(license_str):
    """Convert a license string to CycloneDX license array.

    Uses normalized SPDX expressions. If the expression contains AND/OR,
    it's returned as an expression. Otherwise individual license IDs.

    Args:
        license_str: Raw license string.

    Returns:
        List of CycloneDX license objects.
    """
    normalized = normalize_license(license_str)
    if not normalized or normalized == 'NOASSERTION':
        return []
    # If it's a compound expression, use CycloneDX expression field
    if ' AND ' in normalized or ' OR ' in normalized:
        return [{"expression": normalized}]
    # Single license: use "name" for LicenseRef-*, "id" for SPDX-list IDs
    if normalized.startswith('LicenseRef-'):
        return [{"license": {"name": normalized}}]
    return [{"license": {"id": normalized}}]


def generate_cyclonedx(recipes, submodules, submodule_commits, layers,
                        third_party_deps, dep_graph, config):
    """Generate a CycloneDX 1.5 JSON document.

    Args:
        recipes: Parsed recipe dicts.
        submodules: Parsed submodule dicts.
        submodule_commits: Dict mapping submodule path to commit SHA.
        layers: Parsed layer dicts.
        third_party_deps: Dict of third-party dependency metadata.
        dep_graph: Dict mapping recipe names to dependency lists.
        config: SbomConfig instance.

    Returns:
        Dict representing the CycloneDX 1.5 JSON document.
    """
    timestamp = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    components = []

    # Recipe components
    for recipe in recipes:
        name = recipe['_recipe_name']
        pv = recipe.get('PV') or recipe.get('_version') or 'unknown'
        srcrev = recipe.get('SRCREV', '')

        comp_version = pv
        if srcrev and srcrev != '${AUTOREV}':
            comp_version = "{}+{}".format(pv, srcrev[:12]) if pv else srcrev[:12]

        bom_ref = "{}-{}".format(name, pv)
        comp = {
            "type": "library",
            "bom-ref": bom_ref,
            "group": config.vendor_id,
            "name": name,
            "version": comp_version,
            "cpe": make_cpe(config.vendor_id, name, pv),
            "purl": recipe_purl(name, pv, config.vendor_id),
        }

        # Licenses
        licenses = license_to_cdx(recipe.get('LICENSE', ''))
        if licenses:
            comp["licenses"] = licenses

        # Description
        desc = recipe.get('SUMMARY') or recipe.get('DESCRIPTION')
        if desc:
            comp["description"] = desc

        # External references
        download_url = clean_download_location(recipe.get('SRC_URI', ''))
        if download_url != "NOASSERTION":
            comp["externalReferences"] = [
                {"type": "vcs", "url": download_url}
            ]

        components.append(comp)

    # Submodule components
    for sub in submodules:
        name = sub.get('name', 'unknown')
        path = sub.get('path', '')
        commit = submodule_commits.get(path, 'unknown')

        comp = {
            "type": "library",
            "bom-ref": "submodule-{}".format(spdx_id(name)),
            "name": name,
            "version": commit[:12] if commit != 'unknown' else 'unknown',
        }
        url = sub.get('url', '')
        if url:
            comp["externalReferences"] = [
                {"type": "vcs", "url": url}
            ]
        components.append(comp)

    # Third-party dependency components
    for dep_name, dep_info in sorted(third_party_deps.items()):
        dep_version = dep_info.get('version', 'NOASSERTION')
        comp = {
            "type": "library",
            "bom-ref": dep_name,
            "name": dep_name,
            "version": dep_version,
            "cpe": third_party_cpe(dep_name, dep_version),
            "purl": third_party_purl(dep_name, dep_version),
        }
        licenses = license_to_cdx(dep_info.get('license', ''))
        if licenses:
            comp["licenses"] = licenses
        if dep_info.get('homepage'):
            comp["externalReferences"] = [
                {"type": "website", "url": dep_info['homepage']}
            ]
        components.append(comp)

    # Layer components (deduplicate by name)
    seen_layers = set()
    for layer in layers:
        name = layer['name']
        if name in seen_layers:
            continue
        seen_layers.add(name)
        comp = {
            "type": "framework",
            "bom-ref": "layer-{}".format(spdx_id(name)),
            "name": "yocto-layer-{}".format(name),
        }
        components.append(comp)

    # CycloneDX dependency graph (using bom-refs)
    # Structure: root -> [recipes, submodules, layers]
    #            recipes -> [third-party deps]
    cdx_dependencies = []
    root_ref = "{}-{}".format(spdx_id(config.product_name), spdx_id(config.version))

    # Build recipe bom-ref map
    recipe_bom_refs = {}
    for recipe in recipes:
        rname = recipe['_recipe_name']
        rpv = recipe.get('PV') or recipe.get('_version') or 'unknown'
        recipe_bom_refs.setdefault(rname, []).append("{}-{}".format(rname, rpv))

    # Collect direct children of root (recipes, submodules, layers)
    direct_children = []
    for recipe in recipes:
        rname = recipe['_recipe_name']
        rpv = recipe.get('PV') or recipe.get('_version') or 'unknown'
        direct_children.append("{}-{}".format(rname, rpv))
    for sub in submodules:
        direct_children.append("submodule-{}".format(spdx_id(sub.get('name', 'unknown'))))
    seen_lr = set()
    for layer in layers:
        ln = layer['name']
        if ln not in seen_lr:
            seen_lr.add(ln)
            direct_children.append("layer-{}".format(spdx_id(ln)))

    # Root node depends on direct children
    cdx_dependencies.append({
        "ref": root_ref,
        "dependsOn": direct_children,
    })

    # Recipe nodes depend on their third-party deps
    refs_with_deps = {root_ref}
    for recipe_name, deps in dep_graph.items():
        dep_refs = [d for d in deps if d in third_party_deps]
        for bom_ref in recipe_bom_refs.get(recipe_name, []):
            cdx_dependencies.append({
                "ref": bom_ref,
                "dependsOn": dep_refs,
            })
            refs_with_deps.add(bom_ref)

    # Add empty entries for all remaining components (leaf nodes)
    all_component_refs = [c["bom-ref"] for c in components if "bom-ref" in c]
    for ref in all_component_refs:
        if ref not in refs_with_deps:
            cdx_dependencies.append({
                "ref": ref,
                "dependsOn": [],
            })

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": "urn:uuid:{}".format(uuid.uuid4()),
        "version": 1,
        "metadata": {
            "timestamp": timestamp,
            "tools": {
                "components": [
                    {"type": "application", "name": "yocto-sbom", "version": "0.1.0"}
                ],
            },
            "component": {
                "type": "firmware",
                "bom-ref": root_ref,
                "name": config.product_name,
                "version": config.version,
            },
        },
        "components": components,
        "dependencies": cdx_dependencies,
    }
