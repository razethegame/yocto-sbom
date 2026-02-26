"""Common SBOM generation utilities: SPDX IDs, license normalization, CPE, PURL."""

import re


def spdx_id(name):
    """Create a valid SPDX identifier from a name.

    Args:
        name: Raw name string.

    Returns:
        Sanitized string safe for SPDX identifiers.
    """
    return re.sub(r'[^A-Za-z0-9._-]', '-', name)


def clean_download_location(src_uri):
    """Extract a clean download URL from SRC_URI, stripping credentials.

    Args:
        src_uri: Raw SRC_URI value from a .bb recipe.

    Returns:
        Clean URL string or "NOASSERTION".
    """
    if not src_uri:
        return "NOASSERTION"
    # Find the first real URI token (skip backslashes and whitespace)
    uri = None
    for token in src_uri.split():
        if token == '\\' or not token:
            continue
        uri = token
        break
    if not uri:
        return "NOASSERTION"
    # Handle file:// local sources
    if uri.startswith('file://'):
        return "NOASSERTION"
    # Strip bitbake parameters (;branch=..., ;protocol=..., ;user=...)
    uri = re.sub(r';[^;]+', '', uri)
    # Convert git:// with protocol=https to https://
    if uri.startswith('git://'):
        uri = 'https://' + uri[6:]
    # Strip deploy-token credentials
    uri = re.sub(r'https://[^@]+@', 'https://', uri)
    return uri or "NOASSERTION"


# Known SPDX license identifiers (subset covering what Yocto recipes use)
SPDX_LICENSE_IDS = {
    'MIT', 'Apache-2.0', 'GPL-2.0-only', 'GPL-2.0-or-later',
    'GPL-3.0-only', 'GPL-3.0-or-later', 'LGPL-2.0-only', 'LGPL-2.0-or-later',
    'LGPL-2.1-only', 'LGPL-2.1-or-later', 'LGPL-3.0-only', 'LGPL-3.0-or-later',
    'BSD-2-Clause', 'BSD-3-Clause', 'ISC', 'MPL-2.0', 'Zlib', 'BSL-1.0',
    'Artistic-2.0', 'PSF-2.0', 'Unlicense', 'CC0-1.0', 'CC-BY-4.0',
    'CC-BY-SA-4.0', 'OpenSSL', 'ICU', 'blessing',
    # Yocto-specific names that map to SPDX
    'GPLv2', 'GPLv2+', 'GPLv3', 'GPLv3+', 'LGPLv2', 'LGPLv2+',
    'LGPLv2.1', 'LGPLv2.1+', 'LGPLv3', 'LGPLv3+',
    'Proprietary', 'CLOSED',
}

# Yocto license names -> SPDX identifiers
YOCTO_TO_SPDX = {
    'GPLv2':     'GPL-2.0-only',
    'GPLv2+':    'GPL-2.0-or-later',
    'GPLv3':     'GPL-3.0-only',
    'GPLv3+':    'GPL-3.0-or-later',
    'LGPLv2':    'LGPL-2.0-only',
    'LGPLv2+':   'LGPL-2.0-or-later',
    'LGPLv2.1':  'LGPL-2.1-only',
    'LGPLv2.1+': 'LGPL-2.1-or-later',
    'LGPLv3':    'LGPL-3.0-only',
    'LGPLv3+':   'LGPL-3.0-or-later',
    'PD':        'LicenseRef-PD',
    'CLOSED':    'LicenseRef-CLOSED',
    'Proprietary': 'LicenseRef-Proprietary',
    # Short-form SPDX names (used by some recipes instead of Yocto names)
    'GPL-2.0':   'GPL-2.0-only',
    'GPL-3.0':   'GPL-3.0-only',
    'LGPL-2.0':  'LGPL-2.0-only',
    'LGPL-2.1':  'LGPL-2.1-only',
    'LGPL-3.0':  'LGPL-3.0-only',
}


def normalize_license(raw_license):
    """Convert a Yocto LICENSE string to a valid SPDX license expression.

    - Converts Yocto shorthand names (GPLv2, LGPLv2.1+) to SPDX IDs
    - Converts '&' to 'AND', '|' to 'OR'
    - Prefixes unknown licenses with 'LicenseRef-'

    Args:
        raw_license: Raw license string from a .bb recipe.

    Returns:
        Normalized SPDX license expression string.
    """
    if not raw_license or raw_license == 'NOASSERTION':
        return 'NOASSERTION'

    # Replace Yocto operators with SPDX operators
    expr = raw_license.replace('&', ' AND ').replace('|', ' OR ')

    # Tokenize and convert each license ID
    tokens = expr.split()
    result = []
    for token in tokens:
        if token in ('AND', 'OR', 'WITH', '(', ')'):
            result.append(token)
            continue
        # Map Yocto names to SPDX
        mapped = YOCTO_TO_SPDX.get(token)
        if mapped:
            result.append(mapped)
        elif token in SPDX_LICENSE_IDS:
            result.append(token)
        else:
            # Unknown license: prefix with LicenseRef-
            safe = re.sub(r'[^A-Za-z0-9._-]', '-', token)
            result.append('LicenseRef-{}'.format(safe))

    return ' '.join(result) if result else 'NOASSERTION'


def make_cpe(vendor, product, version):
    """Generate a CPE 2.3 identifier.

    Format: cpe:2.3:a:<vendor>:<product>:<version>:*:*:*:*:*:*:*

    Args:
        vendor: Vendor name.
        product: Product name.
        version: Version string.

    Returns:
        CPE 2.3 string.
    """
    v = vendor.lower().replace(' ', '_') if vendor else '*'
    p = product.lower().replace(' ', '_') if product else '*'
    ver = version if version and version != 'NOASSERTION' else '*'
    # Strip git revision suffixes for cleaner CPE matching
    ver = ver.split('+')[0] if '+' in ver else ver
    return "cpe:2.3:a:{}:{}:{}:*:*:*:*:*:*:*".format(v, p, ver)


def make_purl(pkg_type, name, version, namespace='', qualifiers=''):
    """Generate a Package URL (PURL).

    Format: pkg:<type>/<namespace>/<name>@<version>?<qualifiers>
    See: https://github.com/package-url/purl-spec

    Args:
        pkg_type: Package type (e.g. 'generic', 'pypi').
        name: Package name.
        version: Package version.
        namespace: Optional namespace.
        qualifiers: Optional qualifiers string.

    Returns:
        PURL string.
    """
    ver = version if version and version != 'NOASSERTION' else ''
    parts = ["pkg:{}/".format(pkg_type)]
    if namespace:
        parts.append("{}/".format(namespace))
    parts.append(name)
    if ver:
        parts.append("@{}".format(ver))
    if qualifiers:
        parts.append("?{}".format(qualifiers))
    return ''.join(parts)


def recipe_purl(name, version, vendor_id=''):
    """Generate PURL for a vendor recipe (proprietary, use generic type).

    Args:
        name: Recipe name.
        version: Recipe version.
        vendor_id: Vendor namespace for PURL.

    Returns:
        PURL string.
    """
    return make_purl('generic', name, version, namespace=vendor_id)


def third_party_purl(name, version):
    """Generate PURL for a third-party Yocto/OE package.

    Args:
        name: Package name.
        version: Package version.

    Returns:
        PURL string.
    """
    # Python packages -> pypi type
    if name.startswith('python3-'):
        pypi_name = name[len('python3-'):]
        return make_purl('pypi', pypi_name, version)
    # Default to generic with yocto namespace
    return make_purl('generic', name, version, namespace='yocto')


# Override map: Yocto name -> NVD vendor
# Only needed where vendor differs from product or the heuristic can't guess.
CPE_VENDOR_OVERRIDES = {
    'protobuf':     'google',
    'glog':         'google',
    'tensorflow':   'google',
    'ceres-solver': 'google',
    'edgetpu':      'google',
    'zeromq':       'zeromq',
    'rsync':        'samba',
    'tar':          'gnu',
    'u-boot':       'denx',
    'mtd-utils':    'infradead',
    'flask':        'palletsprojects',
    'werkzeug':     'palletsprojects',
    'raven':        'sentry',
    'pyzmq':        'zeromq',
}

# Product name overrides where NVD product differs from upstream name
CPE_PRODUCT_OVERRIDES = {
    'zeromq':       'libzmq',
    'edgetpu':      'coral_edgetpu',
    'ceres-solver': 'ceres_solver',
    'u-boot':       'u-boot',
}


def _normalize_cpe_name(name):
    """Derive the upstream project name from a Yocto package name.

    Strips common Yocto prefixes/suffixes to recover the upstream name:
      libopencv-core -> opencv    python3-flask -> flask
      libsqlite3     -> sqlite    protobuf-lite -> protobuf
      mtd-utils-misc -> mtd-utils tensorflow-lite -> tensorflow
      u-boot-fw-utils -> u-boot   python3-core -> python
    """
    n = name
    # python3-<pkg>: the upstream project is <pkg>, except python3 itself
    # and python3-core/python3-misc/python3-sqlite3 which are CPython sub-packages
    if n.startswith('python3-'):
        sub = n[len('python3-'):]
        if sub in ('core', 'misc', 'sqlite3', 'dev', 'idle', 'tests'):
            return 'python'
        return sub
    # Strip lib prefix: libsqlite3 -> sqlite3, libeigen -> eigen
    if n.startswith('lib'):
        n = n[3:]
    # Strip known Yocto suffixes (order matters: longer first)
    for suffix in ('-fw-utils', '-native', '-lite', '-misc', '-ubifs',
                   '-core', '-imgproc', '-imgcodecs', '-calib3d',
                   '-ml', '-objdetect', '-dev'):
        if n.endswith(suffix):
            n = n[:-len(suffix)]
            break
    # sqlite3 -> sqlite (NVD product name)
    if n.endswith('3') and n[:-1].isalpha():
        candidate = n[:-1]
        if candidate in ('sqlite', 'python'):
            n = candidate
    return n


def third_party_cpe(name, version):
    """Generate a CPE for a third-party package using heuristics + overrides.

    1. Derives the upstream project name from the Yocto package name
    2. Looks up vendor override (falls back to product name as vendor)
    3. Looks up product override (falls back to derived name)
    """
    upstream = _normalize_cpe_name(name)
    vendor = CPE_VENDOR_OVERRIDES.get(upstream, upstream)
    product = CPE_PRODUCT_OVERRIDES.get(upstream, upstream)
    return make_cpe(vendor, product, version)
