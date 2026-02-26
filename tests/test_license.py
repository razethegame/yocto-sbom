"""Tests for license normalization."""

import unittest

from yocto_sbom.generators.common import normalize_license


class TestNormalizeLicense(unittest.TestCase):

    def test_empty(self):
        self.assertEqual(normalize_license(''), 'NOASSERTION')

    def test_noassertion(self):
        self.assertEqual(normalize_license('NOASSERTION'), 'NOASSERTION')

    def test_spdx_passthrough(self):
        self.assertEqual(normalize_license('MIT'), 'MIT')
        self.assertEqual(normalize_license('Apache-2.0'), 'Apache-2.0')
        self.assertEqual(normalize_license('BSD-3-Clause'), 'BSD-3-Clause')

    def test_yocto_gpl_conversion(self):
        self.assertEqual(normalize_license('GPLv2'), 'GPL-2.0-only')
        self.assertEqual(normalize_license('GPLv2+'), 'GPL-2.0-or-later')
        self.assertEqual(normalize_license('GPLv3'), 'GPL-3.0-only')
        self.assertEqual(normalize_license('GPLv3+'), 'GPL-3.0-or-later')

    def test_yocto_lgpl_conversion(self):
        self.assertEqual(normalize_license('LGPLv2'), 'LGPL-2.0-only')
        self.assertEqual(normalize_license('LGPLv2+'), 'LGPL-2.0-or-later')
        self.assertEqual(normalize_license('LGPLv2.1'), 'LGPL-2.1-only')
        self.assertEqual(normalize_license('LGPLv2.1+'), 'LGPL-2.1-or-later')
        self.assertEqual(normalize_license('LGPLv3'), 'LGPL-3.0-only')
        self.assertEqual(normalize_license('LGPLv3+'), 'LGPL-3.0-or-later')

    def test_yocto_operators(self):
        result = normalize_license('MIT & GPLv2')
        self.assertEqual(result, 'MIT AND GPL-2.0-only')

    def test_yocto_or_operator(self):
        result = normalize_license('MIT | BSD-3-Clause')
        self.assertEqual(result, 'MIT OR BSD-3-Clause')

    def test_compound_expression(self):
        result = normalize_license('GPLv2+ & LGPLv2.1+')
        self.assertEqual(result, 'GPL-2.0-or-later AND LGPL-2.1-or-later')

    def test_unknown_license(self):
        result = normalize_license('CustomLicense')
        self.assertEqual(result, 'LicenseRef-CustomLicense')

    def test_closed(self):
        self.assertEqual(normalize_license('CLOSED'), 'LicenseRef-CLOSED')

    def test_proprietary(self):
        self.assertEqual(normalize_license('Proprietary'), 'LicenseRef-Proprietary')

    def test_pd(self):
        self.assertEqual(normalize_license('PD'), 'LicenseRef-PD')

    def test_gpl_short_form(self):
        """GPL-2.0/3.0 short forms should map to -only variants."""
        self.assertEqual(normalize_license('GPL-2.0'), 'GPL-2.0-only')
        self.assertEqual(normalize_license('GPL-3.0'), 'GPL-3.0-only')

    def test_lgpl_short_form(self):
        """LGPL short forms should map to -only variants."""
        self.assertEqual(normalize_license('LGPL-2.0'), 'LGPL-2.0-only')
        self.assertEqual(normalize_license('LGPL-2.1'), 'LGPL-2.1-only')
        self.assertEqual(normalize_license('LGPL-3.0'), 'LGPL-3.0-only')


if __name__ == '__main__':
    unittest.main()
