"""Exercise input verification without SDK downloads or a phone."""
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class NativeInputTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.data = b'#pragma once\n'

    def acquire(self, digest=None, symlink=False, name='headers/fixture.h'):
        archive = self.root / 'headers.tar.gz'
        with tarfile.open(archive, 'w:gz') as tar:
            info = tarfile.TarInfo('fixture.h')
            if symlink:
                info.type = tarfile.SYMTYPE
                info.linkname = '/etc/passwd'
                tar.addfile(info)
            else:
                info.size = len(self.data)
                tar.addfile(info, io.BytesIO(self.data))
        entry = dict(archive_url=archive.as_uri(), member='fixture.h',
                     bytes=len(self.data), sha256=digest or hashlib.sha256(self.data).hexdigest())
        manifest = self.root / 'sources.json'
        manifest.write_text(json.dumps({'headers': {name: entry}}))
        return subprocess.run([sys.executable, str(ROOT / 'tools/acquire_native_headers.py'),
                               '--manifest', str(manifest), '--output', str(self.root / 'output'),
                               '--aidl', 'not-needed-for-this-fixture'], capture_output=True, text=True)

    def test_verified_archive_member_and_inventory(self):
        result = self.acquire()
        self.assertEqual(result.returncode, 0, result.stderr)
        output = self.root / 'output'
        self.assertEqual((output / 'headers/fixture.h').read_bytes(), self.data)
        self.assertEqual(output.stat().st_mode & 0o777, 0o700)
        self.assertEqual(json.loads((output / 'header-manifest.json').read_text())['headers/fixture.h']['sha256'],
                         hashlib.sha256(self.data).hexdigest())

    def test_existing_acquisition_output_is_preserved(self):
        output = self.root / 'output'
        output.mkdir()
        marker = output / 'keep'
        marker.write_bytes(b'keep')
        result = self.acquire()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(marker.read_bytes(), b'keep')
        self.assertEqual(list(output.iterdir()), [marker])

    def test_manifest_path_escape_is_rejected_before_output(self):
        for name in ['../outside.h', '/tmp/outside.h', 'headers/../../outside.h', 'headers/./outside.h']:
            with self.subTest(name=name):
                result = self.acquire(name=name)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('Unsafe relative header path', result.stderr)
                self.assertFalse((self.root / 'output').exists())
        self.assertFalse((self.root / 'outside.h').exists())

    def test_wrong_header_hash_not_written(self):
        result = self.acquire(digest='0' * 64)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Header checksum mismatch', result.stderr)
        self.assertFalse((self.root / 'output/headers/fixture.h').exists())
        self.assertFalse((self.root / 'output/header-manifest.json').exists())

    def test_symlink_archive_member_rejected(self):
        result = self.acquire(symlink=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Expected ordinary header', result.stderr)
        self.assertFalse((self.root / 'output/headers/fixture.h').exists())

    def test_fresh_output_is_private_and_never_overwrites(self):
        spec = importlib.util.spec_from_file_location('prepare_native', ROOT / 'tools/prepare_native_inputs.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        output = module.fresh_output(self.root / 'link')
        self.assertEqual(output.stat().st_mode & 0o777, 0o700)
        valuable = output / 'libc.so'
        valuable.write_bytes(b'keep')
        with self.assertRaises(FileExistsError):
            module.fresh_output(output)
        self.assertEqual(valuable.read_bytes(), b'keep')

    def test_bad_headers_prevent_image_extraction(self):
        kit = self.root / 'kit'
        kit.mkdir()
        (kit / 'header-manifest.json').write_text(json.dumps({'missing.h': {'sha256': '0' * 64}}))
        result = subprocess.run([sys.executable, str(ROOT / 'tools/prepare_native_inputs.py'),
                                 '--headers', str(kit), '--system', str(self.root / 'missing.img'),
                                 '--output', str(self.root / 'link'), '--debugfs', 'must-not-run'],
                                capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Header inventory differs from pinned public sources', result.stderr)
        self.assertFalse((self.root / 'link').exists())


if __name__ == '__main__':
    unittest.main()
