"""Tiny real EXT4/AVB fixtures only; never reads a production image or key."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import check_google_dsu_pair_avb as checker
import sign_google_dsu_pair as signer

AVBTOOL = Path('/tmp/opencode/titan-pocket-stock-2023010520/verify-tools/avbtool-android13.py')


class ProductionContractTests(unittest.TestCase):
    def test_literal_production_pins(self):
        self.assertEqual(signer.PUBLIC_KEY_PEM_SHA, '4b942e8aa74a0ace264cca09d78bcc5e1c09b87412d05402c9775db3e64a1fe9')
        self.assertEqual(signer.AVBTOOL_SHA, '69783733ce5e198317b02a5567cc356e898c891de872f58a963e9d5c082973c6')
        self.assertEqual(signer.SPECS, {
            'system': (3221225472, 3288334336, '9de56e44a4dcade6386a225f1366bdab29dc814fb85418563d40b0f154c912fa'),
            'vendor': (503316480, 536870912, 'a3d0d55f547faf10a466861fe63ca1e8485b1c56cd7e5627bd75a1dcbf0c6c6f'),
        })


class PairTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='google-pair-test-', )
        cls.root = Path(cls.temp.name)
        cls.root.chmod(0o700)
        cls.key = cls.root / 'fixture.pem'
        subprocess.run(['openssl', 'genpkey', '-algorithm', 'RSA', '-pkeyopt',
                        'rsa_keygen_bits:2048', '-out', str(cls.key)],
                       check=True, capture_output=True)
        cls.key.chmod(0o600)
        public = subprocess.run(['openssl', 'pkey', '-in', str(cls.key), '-pubout'],
                                check=True, capture_output=True).stdout
        cls.public_sha = hashlib.sha256(public).hexdigest()
        cls.sources = {}
        cls.specs = {}
        for name, size in [('system', 4 * 1024**2), ('vendor', 2 * 1024**2)]:
            image = cls.root / (name + '.ext4')
            with image.open('wb') as stream:
                stream.truncate(size)
            subprocess.run(['/usr/sbin/mkfs.ext4', '-q', '-F', '-b', '4096', '-O',
                            '^has_journal', str(image)], check=True, capture_output=True)
            cls.sources[name] = image
            cls.specs[name] = (size, 8 * 1024**2, signer.sha(image))
        if signer.sha(AVBTOOL) != signer.AVBTOOL_SHA:
            raise AssertionError('Fixture requires the literal pinned avbtool')

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def setUp(self):
        self.case = self.root / self._testMethodName
        self.case.mkdir(mode=0o700)
        self.output = self.case / 'pair'
        self.spec_patch = patch.object(signer, 'SPECS', self.specs)
        self.spec_patch.start()
        self.addCleanup(self.spec_patch.stop)
        self.key_pin_patch = patch.object(signer, 'PUBLIC_KEY_PEM_SHA', self.public_sha)
        self.key_pin_patch.start()
        self.addCleanup(self.key_pin_patch.stop)

    def build(self, **changes):
        args = dict(system=self.sources['system'], vendor=self.sources['vendor'],
                    key=self.key, avbtool=AVBTOOL, output=self.output)
        args.update(changes)
        return signer.build(**args)

    def absent(self):
        self.assertFalse(self.output.exists())
        self.assertFalse(self.output.with_name('pair.partial').exists())

    def test_real_pair_crypto_and_prefix(self):
        result = self.build()
        self.assertEqual(set(p.name for p in self.output.iterdir()),
                         {'system.img', 'vendor.img', 'public.pem', 'report.json'})
        self.assertEqual(json.loads((self.output / 'report.json').read_text()), result)
        for name in ('system', 'vendor'):
            image = self.output / (name + '.img')
            fs, partition, digest = self.specs[name]
            self.assertEqual(signer.sha(image, fs), digest)
            self.assertEqual(signer.sha(self.sources[name]), digest)
            self.assertEqual(image.stat().st_size, partition)
            self.assertEqual(image.stat().st_mode & 0o777, 0o600)
            self.assertEqual(result['artifacts'][name]['structure']['descriptor_count'],
                             4 if name == 'system' else 1)
            signer.run(['python3', AVBTOOL, 'verify_image', '--image', image,
                        '--key', self.output / 'public.pem'])
        self.assertEqual(self.output.stat().st_mode & 0o777, 0o700)

    def test_wrong_input_hash_before_output(self):
        bad = {**self.specs, 'system': (*self.specs['system'][:2], '00' * 32)}
        with patch.object(signer, 'SPECS', bad), self.assertRaises(ValueError):
            self.build()
        self.absent()

    def test_capacity_before_copy(self):
        bad = {name: (fs, fs, digest) for name, (fs, _, digest) in self.specs.items()}
        with patch.object(signer, 'SPECS', bad), patch.object(signer.shutil, 'copyfile') as copy:
            with self.assertRaisesRegex(ValueError, 'capacity'):
                self.build()
            copy.assert_not_called()
        self.absent()

    def test_key_modes(self):
        self.key.chmod(0o640)
        try:
            with self.assertRaisesRegex(ValueError, '0600'):
                self.build()
        finally:
            self.key.chmod(0o600)
        self.absent()
        self.root.chmod(0o750)
        try:
            with self.assertRaisesRegex(ValueError, '0700'):
                self.build()
        finally:
            self.root.chmod(0o700)
        self.absent()

    def test_wrong_rsa_size(self):
        other = self.case / 'wrong.pem'
        subprocess.run(['openssl', 'genpkey', '-algorithm', 'RSA', '-pkeyopt',
                        'rsa_keygen_bits:1024', '-out', str(other)], check=True, capture_output=True)
        other.chmod(0o600)
        with self.assertRaisesRegex(ValueError, 'RSA2048'):
            self.build(key=other)
        self.absent()

    def test_different_rsa2048_key_refused_before_copy(self):
        other = self.case / 'other-rsa2048.pem'
        subprocess.run(['openssl', 'genpkey', '-algorithm', 'RSA', '-pkeyopt',
                        'rsa_keygen_bits:2048', '-out', str(other)], check=True, capture_output=True)
        other.chmod(0o600)
        with patch.object(signer.shutil, 'copyfile') as copying:
            with self.assertRaisesRegex(ValueError, 'retained guest-image key'):
                self.build(key=other)
            copying.assert_not_called()
        self.absent()

    def test_symlink_and_same_inode_rejected(self):
        link = self.case / 'link'
        link.symlink_to(self.sources['system'])
        with self.assertRaisesRegex(ValueError, 'non-symlink'):
            self.build(system=link)
        with self.assertRaisesRegex(ValueError, 'distinct'):
            self.build(vendor=self.sources['system'])
        self.absent()

    def test_disk_budget_before_copy(self):
        usage = shutil.disk_usage(self.case)
        with patch.object(signer.shutil, 'disk_usage', return_value=usage._replace(free=0)):
            with self.assertRaisesRegex(ValueError, 'disk budget'):
                self.build()
        self.absent()

    def test_publication_failure_has_no_final_output(self):
        with patch.object(signer, 'publish', side_effect=OSError('fixture publication failure')):
            with self.assertRaises(OSError):
                self.build()
        self.absent()

    def test_source_rehash_after_signing(self):
        source = self.case / 'mutable-system.ext4'
        shutil.copyfile(self.sources['system'], source)
        real_check = signer.check
        def checked(*args):
            result = real_check(*args)
            if args[1] == 'vendor':
                with source.open('r+b') as stream:
                    stream.seek(4096)
                    value = stream.read(1)
                    stream.seek(4096)
                    stream.write(bytes([value[0] ^ 1]))
            return result
        with patch.object(signer, 'check', side_effect=checked):
            with self.assertRaisesRegex(ValueError, 'literal pin'):
                self.build(system=source)
        self.absent()

    def test_wrong_tool_pin_before_copy(self):
        tool = self.case / 'bad-avbtool.py'
        tool.write_text('raise RuntimeError("must not run")\n')
        with self.assertRaisesRegex(ValueError, 'avbtool'):
            self.build(avbtool=tool)
        self.absent()

    def test_existing_staging_preserved(self):
        stage = self.output.with_name('pair.partial')
        stage.mkdir(mode=0o700)
        sentinel = stage / 'owned-elsewhere'
        sentinel.write_text('preserve')
        with self.assertRaises(FileExistsError):
            self.build()
        self.assertFalse(self.output.exists())
        self.assertEqual(sentinel.read_text(), 'preserve')

    def test_atomic_publish_rejects_existing_empty_directory(self):
        stage = self.case / 'stage'
        stage.mkdir(mode=0o700)
        self.output.mkdir(mode=0o700)
        with self.assertRaises(FileExistsError):
            signer.publish(stage, self.output)
        self.assertTrue(stage.is_dir())
        self.assertTrue(self.output.is_dir())

    def test_footer_header_properties_and_descriptor_rejections(self):
        self.build()
        image = self.output / 'system.img'
        original = image.read_bytes()
        vbmeta = struct.unpack_from('>Q', original, len(original) - 64 + 20)[0]
        auth = struct.unpack_from('>Q', original, vbmeta + 12)[0]
        desc_offset = struct.unpack_from('>Q', original, vbmeta + 96)[0]
        desc = vbmeta + 256 + auth + desc_offset
        mutations = [(len(original) - 64, b'FAIL'),
                     (len(original) - 64 + 20, struct.pack('>Q', len(original))),
                     (vbmeta + 28, struct.pack('>I', 2)),
                     (vbmeta + 112, struct.pack('>Q', 1)),
                     (vbmeta + 120, struct.pack('>I', 2)),
                     (vbmeta + 124, struct.pack('>I', 1)),
                     (desc, struct.pack('>Q', 99))]
        fingerprint_at = original.index(b'Android/generic_system')
        mutations.append((fingerprint_at, b'X'))
        # Find the hashtree descriptor rather than assuming property ordering.
        cursor = desc
        while struct.unpack_from('>Q', original, cursor)[0] != 1:
            cursor += 16 + struct.unpack_from('>Q', original, cursor + 8)[0]
        mutations += [(cursor + 44, struct.pack('>I', 2048)),
                      (cursor + 48, struct.pack('>I', 2048)),
                      (cursor + 52, struct.pack('>I', 2)),
                      (cursor + 56, struct.pack('>I', 2048)),
                      (cursor + 64, struct.pack('>I', 2)),
                      (cursor + 116, struct.pack('>I', 1))]
        try:
            for offset, value in mutations:
                with self.subTest(offset=offset):
                    changed = bytearray(original)
                    changed[offset:offset + len(value)] = value
                    image.write_bytes(changed)
                    with self.assertRaises(ValueError):
                        checker.check(image, 'system', *self.specs['system'])
        finally:
            image.write_bytes(original)
        # A filesystem-byte mutation must also fail actual avbtool crypto/tree verification.
        changed = bytearray(original)
        changed[4096] ^= 1
        image.write_bytes(changed)
        with self.assertRaises(ValueError):
            signer.run(['python3', AVBTOOL, 'verify_image', '--image', image,
                        '--key', self.output / 'public.pem'])


if __name__ == '__main__':
    unittest.main()
