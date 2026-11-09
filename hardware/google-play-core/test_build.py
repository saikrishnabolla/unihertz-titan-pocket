# SPDX-License-Identifier: Apache-2.0
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile

HERE = Path(__file__).parent

def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

b = load('google_play_core_build', 'build.py')
x = load('google_play_core_extract', 'extract_source.py')

def digest(raw):
    return hashlib.sha256(raw).hexdigest()


class PlayCoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.source, self.output = self.root / 'source', self.root / 'out'
        self.source.write_bytes(b'raw-system')
        (self.root / 'templates').mkdir()
        (self.root / 'templates/module.prop').write_bytes(b'module')
        (self.root / 'templates/service.sh').write_bytes(b'service')
        self.files = {'system/product/priv-app/Phonesky/Phonesky.apk': b'apk',
                      'module.prop': b'module', 'service.sh': b'service'}
        (self.root / 'recipe.json').write_text(json.dumps(dict(files={name:dict(bytes=len(raw), sha256=digest(raw)) for name,raw in self.files.items()})))
        for name, value in [('HERE', self.root), ('SOURCE_BYTES', 10), ('SOURCE_SHA256', digest(b'raw-system'))]:
            mock = patch.object(b, name, value)
            mock.start(); self.addCleanup(mock.stop)

    def test_builds_exact_local_module_without_installing(self):
        with patch.object(b, 'read_image', return_value=b'apk'):
            report = b.build(self.source, self.output, 'debugfs')
        for name, raw in self.files.items():
            self.assertEqual((self.output / 'module' / name).read_bytes(), raw)
        self.assertEqual((self.output / 'module/service.sh').stat().st_mode & 0o777, 0o755)
        self.assertFalse(report['installed_on_device'])

    def test_rejects_modified_source_before_extraction(self):
        self.source.write_bytes(b'not-system')
        with patch.object(b, 'read_image') as read:
            with self.assertRaisesRegex(ValueError, 'pinned source'):
                b.build(self.source, self.output, 'debugfs')
            read.assert_not_called()

    def test_rejects_wrong_extracted_apk(self):
        with patch.object(b, 'read_image', return_value=b'changed'):
            with self.assertRaisesRegex(ValueError, 'verified original'):
                b.build(self.source, self.output, 'debugfs')
        self.assertFalse(self.output.exists())

    def test_rejects_modified_template(self):
        (self.root / 'templates/module.prop').write_bytes(b'changed')
        with patch.object(b, 'read_image', return_value=b'apk'):
            with self.assertRaisesRegex(ValueError, 'verified original'):
                b.build(self.source, self.output, 'debugfs')

    def test_rejects_existing_output_and_symlink_source(self):
        self.output.mkdir()
        with self.assertRaisesRegex(ValueError, 'already exists'):
            b.build(self.source, self.output, 'debugfs')
        link = self.root / 'link'; link.symlink_to(self.source)
        with self.assertRaisesRegex(ValueError, 'Symlink'):
            b.build(link, self.root / 'new-output', 'debugfs')

    def test_filters_unrelated_google_packages_and_broadcasts(self):
        raw = b'<config><!--notice--><app-link package="com.android.vending"/><app-link package="unrelated"/><allow-implicit-broadcast action="com.google.android.c2dm.intent.RECEIVE"/><allow-implicit-broadcast action="unrelated"/></config>'
        result = b.filtered_xml(raw)
        self.assertIn(b'com.android.vending', result)
        self.assertIn(b'com.google.android.c2dm.intent.RECEIVE', result)
        self.assertNotIn(b'unrelated', result)

    def test_rejects_unsafe_module_path(self):
        for name in ['../other', '/system/file', 'system/../other', 'system\\file']:
            with self.assertRaises(ValueError):
                b.checked_path(name)


class ExtractSourceTests(unittest.TestCase):
    def test_extracts_only_pinned_system(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(); source, output = root/'source.zip', root/'out'
            with zipfile.ZipFile(source,'w') as archive:
                archive.writestr('system.img',b'system')
                archive.writestr('vbmeta.img',b'ignored')
            with patch.object(x,'ARCHIVE_BYTES',source.stat().st_size), patch.object(x,'ARCHIVE_SHA256',digest(source.read_bytes())), patch.object(x,'SOURCE_BYTES',6), patch.object(x,'SOURCE_SHA256',digest(b'system')):
                x.extract(source,output)
            self.assertEqual((output/'system.img').read_bytes(),b'system')
            self.assertEqual({p.name for p in output.iterdir()},{'system.img','report.json'})

    def test_rejects_wrong_archive(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory).resolve(); source=root/'source.zip'; source.write_bytes(b'changed')
            with self.assertRaisesRegex(ValueError,'pinned archive'):
                x.extract(source,root/'out')


if __name__ == '__main__':
    unittest.main()
