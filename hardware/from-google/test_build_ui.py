"""Fail-closed tests and optional full Google-to-APK reconstruction."""
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
import zipfile

import build_ui as ui

REPO = Path(__file__).resolve().parents[2]


class UiBuildTests(unittest.TestCase):
    def test_wrong_google_image_rejected_without_creating_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / 'wrong.img'
            source.write_bytes(b'not Google')
            output = root / 'output'
            with self.assertRaisesRegex(ValueError, 'Wrong Google GSI'):
                ui.build(source, REPO, REPO / 'services/DexTool.java', root, root, root, output)
            self.assertFalse(output.exists())

    def test_symlink_google_image_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'real').write_bytes(b'not Google')
            source = root / 'link'
            source.symlink_to(root / 'real')
            with self.assertRaisesRegex(ValueError, 'regular file'):
                ui.build(source, REPO, REPO / 'services/DexTool.java', root, root, root, root / 'out')

    def test_all_public_seals_pin_known_final_hashes(self):
        for name, expected in ui.FINAL.items():
            seal = json.loads(ui.seal_for(REPO, name).read_text())
            self.assertEqual(seal['sha256'], expected)
            for entry in seal['entries']:
                if 'public_bytes_b64' in entry:
                    self.assertTrue(ui.public_entry(entry['name']))

    def test_replaced_seal_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            seals = root / 'hardware/from-google/seals'
            seals.mkdir(parents=True)
            (seals / 'system__product__overlay__TitanPocketFingerprint.apk.zip-seal.json').write_text(
                json.dumps({'sha256': '0' * 64}))
            with self.assertRaisesRegex(ValueError, 'Wrong final APK seal'):
                ui.seal_for(root, 'TitanPocketFingerprint.apk')

    def test_strip_signatures_preserves_androidx_metadata_and_payloads(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, output = root / 'source.apk', root / 'unsigned.apk'
            payloads = {'classes.dex': b'dex', 'META-INF/androidx.foo.version': b'1.2.3', 'res/foo.xml': b'xml'}
            with zipfile.ZipFile(source, 'x') as archive:
                for name, value in {**payloads, 'META-INF/CERT.SF': b'signature',
                                    'META-INF/CERT.RSA': b'certificate', 'META-INF/MANIFEST.MF': b'manifest'}.items():
                    archive.writestr(name, value)
            ui.strip_signatures(source, output)
            with zipfile.ZipFile(output) as archive:
                self.assertEqual({name: archive.read(name) for name in archive.namelist()}, payloads)
            with self.assertRaises(FileExistsError):
                ui.strip_signatures(source, output)

    def test_strip_signatures_rejects_duplicate_names(self):
        import warnings
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with warnings.catch_warnings():
                warnings.simplefilter('ignore', UserWarning)
                with zipfile.ZipFile(root / 'bad.apk', 'x') as archive:
                    archive.writestr('classes.dex', b'one')
                    archive.writestr('classes.dex', b'two')
            with self.assertRaisesRegex(ValueError, 'Invalid original APK'):
                ui.strip_signatures(root / 'bad.apk', root / 'out.apk')

    @unittest.skipUnless(os.environ.get('TITAN_UI_SOURCE'), 'Set TITAN_UI_SOURCE and tool paths for full reconstruction')
    def test_full_rebuild_from_google_matches_every_sealed_entry(self):
        source = Path(os.environ['TITAN_UI_SOURCE'])
        dex_tools = Path(os.environ['TITAN_UI_DEX_TOOLS'])
        java_home = Path(os.environ['TITAN_UI_JAVA_HOME'])
        debugfs = Path(os.environ['TITAN_UI_DEBUGFS'])
        aapt2 = Path(os.environ['TITAN_UI_AAPT2'])
        with tempfile.TemporaryDirectory(prefix='titan-ui-test-') as temporary:
            output = Path(temporary) / 'build with spaces'
            report = ui.build(source, REPO, dex_tools, java_home, debugfs, aapt2, output)
            self.assertFalse(report['private_key_used'])
            payloads = json.loads((output / 'payloads.json').read_text())
            self.assertEqual(set(payloads), set(ui.FINAL.values()))
            for name, expected in ui.FINAL.items():
                self.assertEqual(ui.digest(output / name), expected)
                seal = json.loads(ui.seal_for(REPO, name).read_text())
                unsigned = output / ('SystemUI-unsigned.apk' if name == 'SystemUI.apk' else name[:-4] + '/unsigned.apk')
                with zipfile.ZipFile(unsigned) as src, zipfile.ZipFile(output / name) as final:
                    for entry in seal['entries']:
                        self.assertEqual(hashlib.sha256(final.read(entry['name'])).hexdigest(), entry['sha256'])
                        if name != 'SystemUI.apk' and not ui.public_entry(entry['name']):
                            self.assertEqual(src.read(entry['name']), final.read(entry['name']))
            with zipfile.ZipFile(output / 'SystemUI-google.apk') as google, zipfile.ZipFile(output / 'SystemUI.apk') as final:
                changed = [name for name in google.namelist()
                           if not ui.public_entry(name) and google.read(name) != final.read(name)]
                self.assertEqual(changed, ['classes.dex', 'classes2.dex'])
            with self.assertRaisesRegex(ValueError, 'Output must be new'):
                ui.build(source, REPO, dex_tools, java_home, debugfs, aapt2, output)


if __name__ == '__main__':
    unittest.main()
