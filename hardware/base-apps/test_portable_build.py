"""Portable signing and metadata regression checks; no firmware or device needed."""
import hashlib
import importlib.util
from pathlib import Path
import struct
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
import build as b


class PortableBuildTests(unittest.TestCase):
    def test_generated_prefix_matches_installed_layout(self):
        blob = b.metadata.build_prefix()
        self.assertEqual(len(blob), 274432)
        self.assertEqual(hashlib.sha256(blob).hexdigest(), b.PREFIX_SHA)
        parsed = b.metadata.validate_minimal(blob)
        self.assertEqual(parsed['partitions'], b.metadata.PARTITIONS)
        self.assertEqual(parsed['groups'], b.metadata.GROUPS)
        self.assertEqual(parsed['block_devices'], b.metadata.DEVICES)

    def test_geometry_corruption_rejected(self):
        data = bytearray(b.metadata.build_prefix())
        data[4096 + 40] ^= 1
        with self.assertRaises(ValueError):
            b.metadata.validate_minimal(data)

    def test_metadata_copy_corruption_rejected(self):
        data = bytearray(b.metadata.build_prefix())
        data[b.metadata.METADATA_START + 128] ^= 1
        with self.assertRaises(ValueError):
            b.metadata.validate_minimal(data)

    def test_new_key_requires_explicit_opt_in(self):
        public = 'test public key fixture'
        with self.assertRaises(ValueError):
            b.signing_policy(public)
        self.assertEqual(b.signing_policy(public, True), hashlib.sha256(public.encode()).hexdigest())

    def test_optimization_rejected(self):
        result = subprocess.run([sys.executable, '-O', str(ROOT / 'build.py'), '--help'], capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Run without Python optimization', result.stderr)


if __name__ == '__main__':
    unittest.main()
