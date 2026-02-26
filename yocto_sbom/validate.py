"""SBOM validation for SPDX 2.3 and CycloneDX 1.5 documents."""

import json
import re


def validate_spdx(path, quiet=False):
    """Validate an SPDX 2.3 JSON file.

    Args:
        path: Path to the SPDX JSON file.
        quiet: Suppress detailed output.

    Returns:
        True if validation passes, False otherwise.
    """
    if not quiet:
        print("=== SPDX 2.3 Validation: {} ===".format(path))
    with open(path) as f:
        spdx = json.load(f)

    errors = 0

    # Required top-level fields
    required = ['spdxVersion', 'dataLicense', 'SPDXID', 'name',
                'documentNamespace', 'creationInfo', 'packages', 'relationships']
    for field in required:
        ok = field in spdx
        if not quiet:
            print("  {}: {}".format(field, 'OK' if ok else 'MISSING'))
        if not ok:
            errors += 1

    if errors:
        return False

    # SPDXID uniqueness
    ids = [p['SPDXID'] for p in spdx['packages']]
    dupes = set(x for x in ids if ids.count(x) > 1)
    if not quiet:
        print("  SPDXID uniqueness: {}".format('DUPLICATES: ' + str(dupes) if dupes else 'OK'))
    errors += len(dupes)

    # Package required fields
    pkg_fields = ['SPDXID', 'name', 'versionInfo', 'downloadLocation',
                  'licenseDeclared', 'licenseConcluded', 'copyrightText']
    bad = []
    for pkg in spdx['packages']:
        for f in pkg_fields:
            if f not in pkg:
                bad.append("{}: missing {}".format(pkg.get('name', '?'), f))
    if not quiet:
        print("  Package fields: {} issues".format(len(bad)) if bad else "  Package fields: OK")
    errors += len(bad)

    # CPE check
    cpe_count = 0
    for pkg in spdx['packages']:
        refs = pkg.get('externalRefs', [])
        cpe_refs = [r for r in refs if r.get('referenceType') == 'cpe23Type']
        if cpe_refs:
            cpe_count += 1
            for r in cpe_refs:
                loc = r.get('referenceLocator', '')
                if not loc.startswith('cpe:2.3:'):
                    if not quiet:
                        print("    Bad CPE: {}: {}".format(pkg['name'], loc))
                    errors += 1
    if not quiet:
        print("  CPE references: {} packages have CPE".format(cpe_count))

    # PURL check
    purl_count = 0
    for pkg in spdx['packages']:
        refs = pkg.get('externalRefs', [])
        purl_refs = [r for r in refs if r.get('referenceType') == 'purl']
        if purl_refs:
            purl_count += 1
            for r in purl_refs:
                loc = r.get('referenceLocator', '')
                if not loc.startswith('pkg:'):
                    if not quiet:
                        print("    Bad PURL: {}: {}".format(pkg['name'], loc))
                    errors += 1
    if not quiet:
        print("  PURL references: {} packages have PURL".format(purl_count))

    # License normalization check
    bad_lics = []
    for pkg in spdx['packages']:
        lic = pkg.get('licenseDeclared', '')
        if lic and lic != 'NOASSERTION':
            if re.search(r'GPLv\d|LGPLv\d', lic):
                bad_lics.append("{}: {}".format(pkg['name'], lic))
    if not quiet:
        print("  License normalization: {}".format(bad_lics if bad_lics else 'OK'))
    errors += len(bad_lics)

    if not quiet:
        print("  Total packages: {}".format(len(spdx['packages'])))
        print("  Total relationships: {}".format(len(spdx['relationships'])))
    return errors == 0


def validate_cdx(path, quiet=False):
    """Validate a CycloneDX 1.5 JSON file.

    Args:
        path: Path to the CycloneDX JSON file.
        quiet: Suppress detailed output.

    Returns:
        True if validation passes, False otherwise.
    """
    if not quiet:
        print("=== CycloneDX 1.5 Validation: {} ===".format(path))
    with open(path) as f:
        cdx = json.load(f)

    errors = 0

    # Required top-level fields
    for field in ['bomFormat', 'specVersion', 'version', 'metadata', 'components']:
        ok = field in cdx
        if not quiet:
            print("  {}: {}".format(field, 'OK' if ok else 'MISSING'))
        if not ok:
            errors += 1

    if errors:
        return False

    if not quiet:
        print("  serialNumber: {}".format('OK' if cdx.get('serialNumber') else 'MISSING'))
        print("  metadata.component: {}".format('OK' if cdx['metadata'].get('component') else 'MISSING'))

    # Duplicate components (by bom-ref)
    seen = set()
    dupes = []
    for c in cdx['components']:
        key = c.get('bom-ref', "{}@{}".format(c['name'], c.get('version', 'unknown')))
        if key in seen:
            dupes.append(key)
        seen.add(key)
    if not quiet:
        print("  Duplicate components: {}".format(dupes if dupes else 'None'))
    errors += len(dupes)

    # Valid component types
    valid_types = {'application', 'framework', 'library', 'container', 'device',
                   'firmware', 'file', 'operating-system', 'platform',
                   'machine-learning-model', 'data'}
    bad_types = ["{}: {}".format(c['name'], c['type']) for c in cdx['components']
                 if c['type'] not in valid_types]
    if not quiet:
        print("  Invalid types: {}".format(bad_types if bad_types else 'None'))
    errors += len(bad_types)

    # License format
    bad_lics = []
    for c in cdx['components']:
        for lic in c.get('licenses', []):
            if 'license' not in lic and 'expression' not in lic:
                bad_lics.append(c['name'])
    if not quiet:
        print("  Invalid licenses: {}".format(bad_lics if bad_lics else 'None'))
    errors += len(bad_lics)

    # CPE check
    cpe_count = sum(1 for c in cdx['components'] if c.get('cpe'))
    bad_cpe = [c['name'] for c in cdx['components']
               if c.get('cpe') and not c['cpe'].startswith('cpe:2.3:')]
    if not quiet:
        msg = "  CPE: {} components have CPE".format(cpe_count)
        if bad_cpe:
            msg += ", bad: {}".format(bad_cpe)
        print(msg)
    errors += len(bad_cpe)

    # PURL check
    purl_count = sum(1 for c in cdx['components'] if c.get('purl'))
    bad_purl = [c['name'] for c in cdx['components']
                if c.get('purl') and not c['purl'].startswith('pkg:')]
    if not quiet:
        msg = "  PURL: {} components have PURL".format(purl_count)
        if bad_purl:
            msg += ", bad: {}".format(bad_purl)
        print(msg)
    errors += len(bad_purl)

    # External references - check for bad URLs
    bad_refs = []
    for c in cdx['components']:
        for ref in c.get('externalReferences', []):
            if 'type' not in ref or 'url' not in ref:
                bad_refs.append("{}: missing type/url".format(c['name']))
            elif not ref['url'] or ref['url'].strip() in ('\\', '/'):
                bad_refs.append("{}: bad url '{}'".format(c['name'], ref['url']))
    if not quiet:
        print("  Invalid externalReferences: {}".format(bad_refs if bad_refs else 'None'))
    errors += len(bad_refs)

    if not quiet:
        print("  Total components: {}".format(len(cdx['components'])))
        print("  Total dependencies: {}".format(len(cdx.get('dependencies', []))))
    return errors == 0
