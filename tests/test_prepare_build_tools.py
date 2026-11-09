#!/usr/bin/env python3
import base64
import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import prepare_build_tools as tools


class ExtractionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.archive = self.root / 'tools.zip'
        self.avb = self.root / 'source.txt'
        self.avb.write_bytes(base64.b64encode(b'test source'))
        with zipfile.ZipFile(self.archive, 'w') as archive:
            archive.writestr('aapt2', b'executable')
            archive.writestr('NOTICE', b'license')
            archive.writestr('../outside', b'must not extract')

    def test_only_named_files_are_extracted_and_not_executed(self):
        import hashlib
        with patch.object(tools, 'AVB_SHA', hashlib.sha256(b'test source').hexdigest()):
            out = tools.unpack(self.archive, self.avb, self.root / 'out')
        self.assertEqual({p.name for p in out.iterdir()}, {'aapt2', 'NOTICE.aapt2', 'avbtool.py'})
        self.assertFalse((self.root / 'outside').exists())
        self.assertEqual((out / 'avbtool.py').read_bytes(), b'test source')

    def test_wrong_decoded_hash_leaves_no_output(self):
        with self.assertRaises(ValueError):
            tools.unpack(self.archive, self.avb, self.root / 'out')
        self.assertFalse((self.root / 'out').exists())

    def test_refuses_existing_output(self):
        out = self.root / 'out'
        out.mkdir()
        with self.assertRaises(ValueError):
            tools.unpack(self.archive, self.avb, out)

    def test_duplicate_member_rejected(self):
        import warnings
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            with zipfile.ZipFile(self.archive, 'a') as archive:
                archive.writestr('aapt2', b'different')
        with self.assertRaises(ValueError):
            tools.unpack(self.archive, self.avb, self.root / 'out')


if __name__ == '__main__':
    unittest.main()
