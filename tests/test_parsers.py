"""Tests for parser modules."""

import os
import tempfile
import unittest

from yocto_sbom.parsers.bitbake import (
    find_bb_files,
    get_recipe_name_and_version,
    parse_all_recipes,
    parse_bb_file,
)
from yocto_sbom.parsers.bblayers import parse_bblayers
from yocto_sbom.parsers.dependencies import collect_third_party_deps, guess_parent_recipe
from yocto_sbom.parsers.gitmodules import parse_gitmodules

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), 'fixtures')


class TestBitbakeParsing(unittest.TestCase):

    def test_get_recipe_name_and_version(self):
        self.assertEqual(
            get_recipe_name_and_version('/path/to/sample_1.2.3.bb'),
            ('sample', '1.2.3'),
        )

    def test_get_recipe_name_no_version(self):
        self.assertEqual(
            get_recipe_name_and_version('/path/to/sample.bb'),
            ('sample', ''),
        )

    def test_parse_bb_file(self):
        bb_path = os.path.join(FIXTURES_DIR, 'sample.bb')
        result = parse_bb_file(bb_path)
        self.assertEqual(result['SUMMARY'], 'Sample application for testing')
        self.assertEqual(result['LICENSE'], 'MIT')
        self.assertEqual(result['PV'], '1.2.3')
        self.assertEqual(result['SRCREV'], 'a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2')
        self.assertEqual(result['DEPENDS'], 'boost openssl')
        self.assertIn('python3-flask', result['RDEPENDS'])
        self.assertEqual(result['_recipe_name'], 'sample')

    def test_find_bb_files(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create some .bb files
            open(os.path.join(tmpdir, 'foo_1.0.bb'), 'w').close()
            open(os.path.join(tmpdir, 'bar_2.0.bb'), 'w').close()
            open(os.path.join(tmpdir, 'notbb.txt'), 'w').close()
            result = find_bb_files(tmpdir)
            self.assertEqual(len(result), 2)

    def test_find_bb_files_nonexistent(self):
        result = find_bb_files('/nonexistent/path')
        self.assertEqual(result, set())

    def test_parse_all_recipes(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            bb_content = 'SUMMARY = "Test"\nLICENSE = "MIT"\n'
            with open(os.path.join(tmpdir, 'test_1.0.bb'), 'w') as f:
                f.write(bb_content)
            recipes = parse_all_recipes(tmpdir, quiet=True)
            self.assertEqual(len(recipes), 1)
            self.assertEqual(recipes[0]['_recipe_name'], 'test')
            self.assertEqual(recipes[0]['PV'], '1.0')


class TestGitmodulesParsing(unittest.TestCase):

    def test_parse_gitmodules(self):
        path = os.path.join(FIXTURES_DIR, 'sample_gitmodules')
        result = parse_gitmodules(path)
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0]['name'], 'libs/libfoo')
        self.assertEqual(result[0]['url'], 'https://gitlab.com/example/libfoo.git')
        # Credentials should be stripped
        self.assertEqual(result[1]['url'], 'https://gitlab.com/example/libbar.git')

    def test_parse_gitmodules_nonexistent(self):
        result = parse_gitmodules('/nonexistent/.gitmodules')
        self.assertEqual(result, [])


class TestBblayersParsing(unittest.TestCase):

    def test_parse_bblayers(self):
        path = os.path.join(FIXTURES_DIR, 'sample_bblayers.conf')
        result = parse_bblayers(path)
        self.assertEqual(len(result), 5)
        names = [l['name'] for l in result]
        self.assertIn('meta', names)
        self.assertIn('meta-poky', names)
        self.assertIn('meta-custom', names)

    def test_parse_bblayers_nonexistent(self):
        result = parse_bblayers('/nonexistent/bblayers.conf')
        self.assertEqual(result, [])


class TestDependencies(unittest.TestCase):

    def test_guess_parent_recipe_lib(self):
        candidates = guess_parent_recipe('libopencv-core')
        self.assertIn('opencv-core', candidates)
        self.assertIn('opencv', candidates)

    def test_guess_parent_recipe_native(self):
        candidates = guess_parent_recipe('protobuf-native')
        self.assertIn('protobuf', candidates)

    def test_guess_parent_recipe_python(self):
        candidates = guess_parent_recipe('python3-flask')
        self.assertIn('python3', candidates)

    def test_collect_third_party_deps(self):
        recipes = [
            {
                '_recipe_name': 'myapp',
                '_version': '1.0',
                'PV': '1.0',
                'DEPENDS': 'boost openssl',
                'RDEPENDS': '',
            },
        ]
        deps, graph = collect_third_party_deps(recipes, quiet=True)
        self.assertIn('boost', deps)
        self.assertIn('openssl', deps)
        self.assertIn('myapp', graph)

    def test_collect_third_party_deps_multi_dir(self):
        """Multi-dir scanning should merge results from multiple directories."""
        recipes = [
            {
                '_recipe_name': 'myapp',
                '_version': '1.0',
                'PV': '1.0',
                'DEPENDS': 'boost openssl',
                'RDEPENDS': '',
            },
        ]
        # Two non-existent dirs: should still work (empty layer_packages)
        deps, graph = collect_third_party_deps(
            recipes, yocto_dirs=['/nonexistent1', '/nonexistent2'], quiet=True)
        self.assertIn('boost', deps)
        self.assertIn('openssl', deps)

    def test_collect_third_party_deps_backward_compat(self):
        """Single string argument should still work (backward compat)."""
        recipes = [
            {
                '_recipe_name': 'myapp',
                '_version': '1.0',
                'PV': '1.0',
                'DEPENDS': 'boost',
                'RDEPENDS': '',
            },
        ]
        deps, _ = collect_third_party_deps(recipes, yocto_dirs='', quiet=True)
        self.assertIn('boost', deps)

    def test_collect_skips_internal_deps(self):
        recipes = [
            {'_recipe_name': 'myapp', '_version': '1.0', 'PV': '1.0',
             'DEPENDS': 'mylib', 'RDEPENDS': ''},
            {'_recipe_name': 'mylib', '_version': '1.0', 'PV': '1.0',
             'DEPENDS': '', 'RDEPENDS': ''},
        ]
        deps, _ = collect_third_party_deps(recipes, quiet=True)
        self.assertNotIn('mylib', deps)


if __name__ == '__main__':
    unittest.main()
