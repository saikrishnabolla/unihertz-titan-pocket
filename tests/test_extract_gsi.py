# SPDX-License-Identifier: Apache-2.0
import hashlib
import importlib.util
import json
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch
import warnings
import zipfile

SPEC = importlib.util.spec_from_file_location('extract_gsi', Path(__file__).parents[1] / 'tools/extract_gsi.py')
x = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(x)


class ExtractGsiTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        (self.root / 'release').mkdir()
        self.source, self.output = self.root / 'source.zip', self.root / 'out'
        for name, value in [('ROOT', self.root),
                            ('IMAGES', {'google-gsi': dict(bytes=6, sha256=hashlib.sha256(b'system').hexdigest())})]:
            mocked = patch.object(x, name, value)
            mocked.start()
            self.addCleanup(mocked.stop)

    def archive(self, entries):
        with warnings.catch_warnings():
            warnings.simplefilter('ignore', UserWarning)
            with zipfile.ZipFile(self.source, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
                for name, raw in entries:
                    archive.writestr(name, raw)
        raw = self.source.read_bytes()
        (self.root / 'release/sources.json').write_text(json.dumps(dict(sources={
            'google-gsi': dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())})))

    def test_extracts_only_exact_system_member(self):
        self.archive([('system.img', b'system'), ('vbmeta.img', b'ignore'), ('build.prop', b'ignore')])
        report = x.extract('google-gsi', self.source, self.output)
        self.assertEqual((self.output / 'system.img').read_bytes(), b'system')
        self.assertEqual({p.name for p in self.output.iterdir()}, {'system.img', 'report.json'})
        self.assertEqual(report['extracted_members'], ['system.img'])

    def test_rejects_modified_archive(self):
        self.archive([('system.img', b'system')])
        with self.source.open('ab') as stream:
            stream.write(b'changed')
        with self.assertRaisesRegex(ValueError, 'ZIP size or SHA'):
            x.extract('google-gsi', self.source, self.output)
        self.assertFalse(self.output.exists())

    def test_rejects_wrong_raw_image_hash(self):
        self.archive([('system.img', b'wrong!')])
        with self.assertRaisesRegex(ValueError, 'Extracted system.img'):
            x.extract('google-gsi', self.source, self.output)
        self.assertFalse((self.output / 'report.json').exists())

    def test_rejects_missing_duplicate_malformed_or_wrong_size_member(self):
        cases = [[('vbmeta.img', b'other')], [('system.img', b'system'), ('system.img', b'system')],
                 [('folder/system.img', b'system')], [('../system.img', b'system')],
                 [('./system.img', b'system')], [('system.img', b'short')],
                 [('system.img', b'system'), ('../other', b'other')]]
        for entries in cases:
            self.archive(entries)
            with self.assertRaises(ValueError):
                x.extract('google-gsi', self.source, self.output)
            self.assertFalse(self.output.exists())

    def test_rejects_archive_symlink_member(self):
        member = zipfile.ZipInfo('system.img')
        member.create_system = 3
        member.external_attr = (stat.S_IFLNK | 0o777) << 16
        self.archive([(member, b'system')])
        with self.assertRaisesRegex(ValueError, 'Symlink ZIP'):
            x.extract('google-gsi', self.source, self.output)

    def test_rejects_existing_and_symlink_paths(self):
        self.archive([('system.img', b'system')])
        self.output.mkdir()
        with self.assertRaisesRegex(ValueError, 'already exists'):
            x.extract('google-gsi', self.source, self.output)
        link = self.root / 'source-link'
        link.symlink_to(self.source)
        with self.assertRaisesRegex(ValueError, 'Symlink'):
            x.extract('google-gsi', link, self.root / 'new-output')
        output_link = self.root / 'output-link'
        output_link.symlink_to(self.root / 'absent')
        with self.assertRaisesRegex(ValueError, 'Symlink'):
            x.extract('google-gsi', self.source, output_link)

    def test_rejects_unsupported_source_name(self):
        with self.assertRaisesRegex(ValueError, 'Unsupported'):
            x.extract('other', self.source, self.output)


if __name__ == '__main__':
    unittest.main()
