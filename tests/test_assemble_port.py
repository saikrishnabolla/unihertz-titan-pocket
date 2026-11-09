"""Reject bad image inputs before AVB tools or output creation."""
import importlib.util
import hashlib
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import assemble_port as port


class PayloadTests(unittest.TestCase):
    def test_exact_raw_bytes_are_bound_to_partition_geometry(self):
        with tempfile.TemporaryDirectory() as directory:
            image = Path(directory).resolve() / 'image'
            image.write_bytes(b'fixture')
            item = port.payload('vendor', image, hashlib.sha256(b'fixture').hexdigest(), 7, 4096)
            self.assertEqual((item.offset, item.size, item.name), (4096, 7, 'vendor'))

    def test_wrong_size_hash_and_symlink_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            image = Path(directory).resolve() / 'image'
            image.write_bytes(b'fixture')
            link = Path(directory).resolve() / 'link'
            link.symlink_to(image)
            for path, digest, size in [(image, '0' * 64, 7),
                                      (image, hashlib.sha256(b'fixture').hexdigest(), 8),
                                      (link, hashlib.sha256(b'fixture').hexdigest(), 7)]:
                with self.subTest(path=path, size=size), self.assertRaises((ValueError, OSError, port.assembler.AssemblyError)):
                    port.payload('vendor', path, digest, size, 4096)


if __name__ == '__main__':
    unittest.main()
