"""SPDX 2.3 JSON SBOM generation."""

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


def generate_spdx(recipes, submodules, submodule_commits, layers,
                   third_party_deps, dep_graph, config):
    """Generate an SPDX 2.3 JSON document.

    Args:
        recipes: Parsed recipe dicts.
        submodules: Parsed submodule dicts.
        submodule_commits: Dict mapping submodule path to commit SHA.
        layers: Parsed layer dicts.
        third_party_deps: Dict of third-party dependency metadata.
        dep_graph: Dict mapping recipe names to dependency lists.
        config: SbomConfig instance.

    Returns:
        Dict representing the SPDX 2.3 JSON document.
    """
    timestamp = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    doc_name = "{}-{}-{}".format(config.product_name, config.version, config.build_config)
    doc_namespace = "{}/{}/{}/{}/{}".format(
        config.namespace_uri, config.product_name.lower(),
        config.version, config.build_config, uuid.uuid4(),
    )

    packages = []
    relationships = []

    # Root package for the firmware itself
    root_id = "SPDXRef-firmware"
    packages.append({
        "SPDXID": root_id,
        "name": config.product_name,
        "versionInfo": config.version,
        "downloadLocation": "NOASSERTION",
        "supplier": config.supplier,
        "licenseDeclared": "LicenseRef-Proprietary",
        "licenseConcluded": "NOASSERTION",
        "copyrightText": "NOASSERTION",
        "primaryPackagePurpose": "FIRMWARE",
    })
    relationships.append({
        "spdxElementId": "SPDXRef-DOCUMENT",
        "relationshipType": "DESCRIBES",
        "relatedSpdxElement": root_id,
    })

    # Recipe packages
    for recipe in recipes:
        name = recipe['_recipe_name']
        pv = recipe.get('PV') or recipe.get('_version') or 'unknown'
        pkg_id = "SPDXRef-{}-{}".format(spdx_id(name), spdx_id(pv))
        srcrev = recipe.get('SRCREV', '')

        version_info = pv
        if srcrev and srcrev != '${AUTOREV}':
            version_info = "{}+{}".format(pv, srcrev[:12]) if pv else srcrev[:12]

        pkg = {
            "SPDXID": pkg_id,
            "name": name,
            "versionInfo": version_info,
            "downloadLocation": clean_download_location(recipe.get('SRC_URI', '')),
            "supplier": config.supplier,
            "licenseDeclared": normalize_license(recipe.get('LICENSE', '')),
            "licenseConcluded": "NOASSERTION",
            "copyrightText": "NOASSERTION",
            "externalRefs": [
                {
                    "referenceCategory": "SECURITY",
                    "referenceType": "cpe23Type",
                    "referenceLocator": make_cpe(config.vendor_id, name, pv),
                },
                {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": recipe_purl(name, pv, config.vendor_id),
                },
            ],
        }
        if recipe.get('SUMMARY'):
            pkg["summary"] = recipe['SUMMARY']
        if recipe.get('DESCRIPTION'):
            pkg["description"] = recipe['DESCRIPTION']

        packages.append(pkg)
        relationships.append({
            "spdxElementId": root_id,
            "relationshipType": "CONTAINS",
            "relatedSpdxElement": pkg_id,
        })

    # Submodule packages
    for sub in submodules:
        name = sub.get('name', 'unknown')
        path = sub.get('path', '')
        pkg_id = "SPDXRef-submodule-{}".format(spdx_id(name))
        commit = submodule_commits.get(path, 'unknown')

        pkg = {
            "SPDXID": pkg_id,
            "name": name,
            "versionInfo": commit[:12] if commit != 'unknown' else 'unknown',
            "downloadLocation": sub.get('url', 'NOASSERTION'),
            "supplier": "NOASSERTION",
            "licenseDeclared": "NOASSERTION",
            "licenseConcluded": "NOASSERTION",
            "copyrightText": "NOASSERTION",
        }
        packages.append(pkg)
        relationships.append({
            "spdxElementId": root_id,
            "relationshipType": "DEPENDS_ON",
            "relatedSpdxElement": pkg_id,
        })

    # Third-party dependency packages
    for dep_name, dep_info in sorted(third_party_deps.items()):
        dep_pkg_id = "SPDXRef-dep-{}".format(spdx_id(dep_name))
        dep_version = dep_info.get('version', 'NOASSERTION')
        pkg = {
            "SPDXID": dep_pkg_id,
            "name": dep_name,
            "versionInfo": dep_version,
            "downloadLocation": dep_info.get('homepage') or "NOASSERTION",
            "supplier": "NOASSERTION",
            "licenseDeclared": normalize_license(dep_info.get('license', '')),
            "licenseConcluded": "NOASSERTION",
            "copyrightText": "NOASSERTION",
            "externalRefs": [
                {
                    "referenceCategory": "SECURITY",
                    "referenceType": "cpe23Type",
                    "referenceLocator": third_party_cpe(dep_name, dep_version),
                },
                {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": third_party_purl(dep_name, dep_version),
                },
            ],
        }
        if dep_info.get('homepage'):
            pkg["homepage"] = dep_info['homepage']
        packages.append(pkg)

    # Dependency relationships: recipe -> third-party dep
    recipe_pkg_ids = {}
    for recipe in recipes:
        rname = recipe['_recipe_name']
        rpv = recipe.get('PV') or recipe.get('_version') or 'unknown'
        rid = "SPDXRef-{}-{}".format(spdx_id(rname), spdx_id(rpv))
        recipe_pkg_ids.setdefault(rname, []).append(rid)

    for recipe_name, deps in dep_graph.items():
        for rpkg_id in recipe_pkg_ids.get(recipe_name, []):
            for dep_name in deps:
                if dep_name in third_party_deps:
                    dep_pkg_id = "SPDXRef-dep-{}".format(spdx_id(dep_name))
                    relationships.append({
                        "spdxElementId": rpkg_id,
                        "relationshipType": "DEPENDS_ON",
                        "relatedSpdxElement": dep_pkg_id,
                    })

    # Layer packages (deduplicate by name)
    seen_layers = set()
    for layer in layers:
        name = layer['name']
        if name in seen_layers:
            continue
        seen_layers.add(name)
        pkg_id = "SPDXRef-layer-{}".format(spdx_id(name))
        pkg = {
            "SPDXID": pkg_id,
            "name": "yocto-layer-{}".format(name),
            "versionInfo": "NOASSERTION",
            "downloadLocation": "NOASSERTION",
            "supplier": "NOASSERTION",
            "licenseDeclared": "NOASSERTION",
            "licenseConcluded": "NOASSERTION",
            "copyrightText": "NOASSERTION",
        }
        packages.append(pkg)
        relationships.append({
            "spdxElementId": root_id,
            "relationshipType": "BUILD_TOOL_OF",
            "relatedSpdxElement": pkg_id,
        })

    # Collect all LicenseRef-* identifiers from packages for hasExtractedLicensingInfos
    import re as _re
    license_refs = set()
    for pkg in packages:
        lic = pkg.get('licenseDeclared', '')
        if lic:
            for ref in _re.findall(r'LicenseRef-[A-Za-z0-9._-]+', lic):
                license_refs.add(ref)

    license_ref_names = {
        'LicenseRef-Proprietary': 'Proprietary / CLOSED license',
        'LicenseRef-CLOSED': 'Yocto CLOSED (proprietary) license',
        'LicenseRef-PD': 'Public Domain',
    }
    extracted_licensing = []
    for ref in sorted(license_refs):
        extracted_licensing.append({
            "licenseId": ref,
            "extractedText": license_ref_names.get(
                ref, "See package for license details ({})".format(ref)),
            "name": ref.replace('LicenseRef-', ''),
        })

    doc = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": doc_name,
        "documentNamespace": doc_namespace,
        "creationInfo": {
            "created": timestamp,
            "creators": ["Tool: yocto-sbom"],
            "licenseListVersion": "3.19",
        },
        "packages": packages,
        "relationships": relationships,
    }
    if extracted_licensing:
        doc["hasExtractedLicensingInfos"] = extracted_licensing
    return doc
