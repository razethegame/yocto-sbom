"""Tests for generator modules."""

import json
import os
import tempfile
import unittest

from yocto_sbom.config import SbomConfig
from yocto_sbom.generators.common import (
    _normalize_cpe_name,
    clean_download_location,
    make_cpe,
    make_purl,
    recipe_purl,
    spdx_id,
    third_party_cpe,
    third_party_purl,
)
from yocto_sbom.generators.cyclonedx import generate_cyclonedx, license_to_cdx
from yocto_sbom.generators.spdx import generate_spdx
from yocto_sbom.validate import validate_cdx, validate_spdx


class TestSpdxId(unittest.TestCase):

    def test_simple(self):
        self.assertEqual(spdx_id('my-package'), 'my-package')

    def test_special_chars(self):
        self.assertEqual(spdx_id('my package@1.0'), 'my-package-1.0')


class TestCleanDownloadLocation(unittest.TestCase):

    def test_empty(self):
        self.assertEqual(clean_download_location(''), 'NOASSERTION')

    def test_file_uri(self):
        self.assertEqual(clean_download_location('file://local/path'), 'NOASSERTION')

    def test_git_uri(self):
        result = clean_download_location('git://github.com/foo/bar.git;branch=main')
        self.assertEqual(result, 'https://github.com/foo/bar.git')

    def test_strips_credentials(self):
        result = clean_download_location('https://token:secret@github.com/foo/bar.git')
        self.assertEqual(result, 'https://github.com/foo/bar.git')


class TestCpePurl(unittest.TestCase):

    def test_make_cpe(self):
        cpe = make_cpe('myvendor', 'myproduct', '1.0')
        self.assertTrue(cpe.startswith('cpe:2.3:a:'))
        self.assertIn('myvendor', cpe)
        self.assertIn('myproduct', cpe)
        self.assertIn('1.0', cpe)

    def test_make_cpe_strips_git_suffix(self):
        cpe = make_cpe('v', 'p', '1.0+abc123')
        self.assertIn('1.0', cpe)
        self.assertNotIn('abc123', cpe)

    def test_make_purl(self):
        purl = make_purl('generic', 'foo', '1.0', namespace='bar')
        self.assertEqual(purl, 'pkg:generic/bar/foo@1.0')

    def test_recipe_purl(self):
        purl = recipe_purl('myrecipe', '1.0', vendor_id='myco')
        self.assertEqual(purl, 'pkg:generic/myco/myrecipe@1.0')

    def test_third_party_purl_python(self):
        purl = third_party_purl('python3-flask', '2.0')
        self.assertEqual(purl, 'pkg:pypi/flask@2.0')

    def test_third_party_purl_generic(self):
        purl = third_party_purl('boost', '1.66.0')
        self.assertEqual(purl, 'pkg:generic/yocto/boost@1.66.0')


class TestNormalizeCpeName(unittest.TestCase):

    def test_python3_package(self):
        self.assertEqual(_normalize_cpe_name('python3-flask'), 'flask')

    def test_python3_core(self):
        self.assertEqual(_normalize_cpe_name('python3-core'), 'python')

    def test_lib_prefix(self):
        self.assertEqual(_normalize_cpe_name('libsqlite3'), 'sqlite')

    def test_native_suffix(self):
        self.assertEqual(_normalize_cpe_name('protobuf-native'), 'protobuf')

    def test_lib_prefix_with_suffix(self):
        self.assertEqual(_normalize_cpe_name('libopencv-core'), 'opencv')

    def test_fw_utils_suffix(self):
        self.assertEqual(_normalize_cpe_name('u-boot-fw-utils'), 'u-boot')

    def test_plain_name(self):
        self.assertEqual(_normalize_cpe_name('boost'), 'boost')


class TestThirdPartyCpe(unittest.TestCase):

    def test_vendor_override(self):
        cpe = third_party_cpe('protobuf', '3.6.1')
        self.assertIn(':google:', cpe)
        self.assertIn(':protobuf:', cpe)

    def test_product_override(self):
        cpe = third_party_cpe('zeromq', '4.3.4')
        self.assertIn(':zeromq:', cpe)
        self.assertIn(':libzmq:', cpe)

    def test_heuristic_lib_prefix(self):
        cpe = third_party_cpe('libeigen', '3.3.7')
        self.assertIn(':eigen:', cpe)

    def test_heuristic_python3(self):
        cpe = third_party_cpe('python3-flask', '2.0')
        self.assertIn(':palletsprojects:', cpe)
        self.assertIn(':flask:', cpe)

    def test_plain_package(self):
        cpe = third_party_cpe('boost', '1.66.0')
        self.assertIn(':boost:boost:', cpe)


class TestLicenseToCdx(unittest.TestCase):

    def test_empty(self):
        self.assertEqual(license_to_cdx(''), [])

    def test_noassertion(self):
        self.assertEqual(license_to_cdx('NOASSERTION'), [])

    def test_single(self):
        result = license_to_cdx('MIT')
        self.assertEqual(result, [{"license": {"id": "MIT"}}])

    def test_license_ref(self):
        """LicenseRef-* values use 'name' not 'id' in CycloneDX."""
        result = license_to_cdx('CLOSED')
        self.assertEqual(result, [{"license": {"name": "LicenseRef-CLOSED"}}])

    def test_license_ref_proprietary(self):
        result = license_to_cdx('Proprietary')
        self.assertEqual(result, [{"license": {"name": "LicenseRef-Proprietary"}}])

    def test_compound(self):
        result = license_to_cdx('MIT & BSD-3-Clause')
        self.assertEqual(len(result), 1)
        self.assertIn('expression', result[0])


class TestGenerateSpdx(unittest.TestCase):

    def _make_config(self):
        config = SbomConfig()
        config.product_name = 'TestProduct'
        config.version = '1.0.0'
        config.vendor_id = 'testvendor'
        config.supplier = 'Organization: TestVendor'
        config.namespace_uri = 'https://test.com/spdx'
        config.build_config = 'default'
        return config

    def test_generates_valid_spdx(self):
        config = self._make_config()
        recipes = [{
            '_recipe_name': 'myapp',
            '_version': '1.0',
            'PV': '1.0',
            'LICENSE': 'MIT',
            'SRC_URI': 'git://github.com/test/myapp.git;branch=main',
            'SRCREV': 'abc123def456',
            'SUMMARY': 'Test app',
        }]
        spdx = generate_spdx(recipes, [], {}, [], {}, {}, config)

        self.assertEqual(spdx['spdxVersion'], 'SPDX-2.3')
        self.assertIn('TestProduct', spdx['name'])
        self.assertEqual(len(spdx['packages']), 2)  # root + 1 recipe
        # Root package uses config values
        root = spdx['packages'][0]
        self.assertEqual(root['name'], 'TestProduct')
        self.assertEqual(root['supplier'], 'Organization: TestVendor')

    def test_spdx_validates(self):
        config = self._make_config()
        recipes = [{
            '_recipe_name': 'myapp', '_version': '1.0', 'PV': '1.0',
            'LICENSE': 'MIT', 'SRC_URI': '', 'SRCREV': '', 'SUMMARY': '',
        }]
        spdx = generate_spdx(recipes, [], {}, [], {}, {}, config)

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(spdx, f, indent=2)
            tmppath = f.name
        try:
            self.assertTrue(validate_spdx(tmppath, quiet=True))
        finally:
            os.unlink(tmppath)


class TestGenerateCycloneDx(unittest.TestCase):

    def _make_config(self):
        config = SbomConfig()
        config.product_name = 'TestProduct'
        config.version = '1.0.0'
        config.vendor_id = 'testvendor'
        config.build_config = 'default'
        return config

    def test_generates_valid_cdx(self):
        config = self._make_config()
        recipes = [{
            '_recipe_name': 'myapp',
            '_version': '1.0',
            'PV': '1.0',
            'LICENSE': 'MIT',
            'SRC_URI': 'git://github.com/test/myapp.git;branch=main',
            'SRCREV': 'abc123def456',
            'SUMMARY': 'Test app',
        }]
        cdx = generate_cyclonedx(recipes, [], {}, [], {}, {}, config)

        self.assertEqual(cdx['bomFormat'], 'CycloneDX')
        self.assertEqual(cdx['specVersion'], '1.5')
        self.assertEqual(cdx['metadata']['component']['name'], 'TestProduct')
        self.assertEqual(len(cdx['components']), 1)
        # Recipe uses config vendor_id as group
        self.assertEqual(cdx['components'][0]['group'], 'testvendor')

    def test_cdx_tools_format(self):
        """Tools should use CDX 1.5 object format, not legacy array."""
        config = self._make_config()
        cdx = generate_cyclonedx([], [], {}, [], {}, {}, config)
        tools = cdx['metadata']['tools']
        self.assertIsInstance(tools, dict)
        self.assertIn('components', tools)
        self.assertEqual(tools['components'][0]['name'], 'yocto-sbom')

    def test_cdx_metadata_bom_ref(self):
        """metadata.component should have a bom-ref."""
        config = self._make_config()
        cdx = generate_cyclonedx([], [], {}, [], {}, {}, config)
        self.assertIn('bom-ref', cdx['metadata']['component'])

    def test_cdx_dependency_graph_root(self):
        """Dependency graph should have a root node entry."""
        config = self._make_config()
        recipes = [{
            '_recipe_name': 'myapp', '_version': '1.0', 'PV': '1.0',
            'LICENSE': 'MIT', 'SRC_URI': '', 'SRCREV': '', 'SUMMARY': '',
        }]
        cdx = generate_cyclonedx(recipes, [], {}, [], {}, {}, config)
        root_ref = cdx['metadata']['component']['bom-ref']
        root_deps = [d for d in cdx['dependencies'] if d['ref'] == root_ref]
        self.assertEqual(len(root_deps), 1)
        self.assertIn('myapp-1.0', root_deps[0]['dependsOn'])

    def test_cdx_validates(self):
        config = self._make_config()
        recipes = [{
            '_recipe_name': 'myapp', '_version': '1.0', 'PV': '1.0',
            'LICENSE': 'MIT', 'SRC_URI': '', 'SRCREV': '', 'SUMMARY': '',
        }]
        cdx = generate_cyclonedx(recipes, [], {}, [], {}, {}, config)

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(cdx, f, indent=2)
            tmppath = f.name
        try:
            self.assertTrue(validate_cdx(tmppath, quiet=True))
        finally:
            os.unlink(tmppath)


if __name__ == '__main__':
    unittest.main()
