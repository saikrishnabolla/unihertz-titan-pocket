import unittest
import hashlib
from pathlib import Path
import subprocess
import tempfile
import sys
from unittest.mock import patch

from compare_vendor_trees import directory_entries, inventory


class VendorDirectoryTests(unittest.TestCase):
    def test_streamed_inventory_matches_default_without_retaining_payloads(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            image = root / 'test.img'
            with image.open('wb') as stream:
                stream.truncate(8 * 1024**2)
            subprocess.run(['/usr/sbin/mke2fs', '-q', '-t', 'ext4', '-F', str(image)],
                           check=True, capture_output=True)
            payload = b'\x00debugfs: cat /fake\n\xff' * 70000
            (root / 'payload').write_bytes(payload)
            (root / 'empty').write_bytes(b'')
            target = '/a/' + 'long-target-' * 9
            commands = [f'write {root / "payload"} /payload',
                        f'write {root / "empty"} /empty',
                        'ln /payload /alias', 'set_inode_field /payload links_count 2',
                        'ea_set /payload user.test attribute-value',
                        'symlink /short payload', f'symlink /long {target}']
            subprocess.run(['/usr/sbin/debugfs', '-w', '-f', '/dev/stdin', str(image)],
                           input='\n'.join(commands) + '\n', text=True,
                           check=True, capture_output=True)
            default = inventory(image, root / 'default', allow_external_symlinks=True)
            explicit_default = inventory(image, root / 'explicit-default',
                                         allow_external_symlinks=True, retain_payloads=True)
            popen = subprocess.Popen
            read_sizes = []

            class BoundedReader:
                def __init__(self, stream):
                    self.stream = stream

                def read(self, size=-1):
                    if not 0 < size <= 1024 * 1024:
                        raise AssertionError('Unbounded payload read')
                    read_sizes.append(size)
                    return self.stream.read(size)

                def close(self):
                    self.stream.close()

            def bounded_cat(argv, **kwargs):
                process = popen(argv, **kwargs)
                if argv[:2] == ['/usr/sbin/debugfs', '-R'] and argv[2].startswith('cat '):
                    process.stdout = BoundedReader(process.stdout)
                return process

            before = image.stat()
            with patch('compare_vendor_trees.subprocess.Popen', side_effect=bounded_cat):
                streamed = inventory(image, root / 'streamed', allow_external_symlinks=True,
                                     retain_payloads=False)
            self.assertGreater(len(read_sizes), 2)
            self.assertEqual(image.stat().st_mtime_ns, before.st_mtime_ns)
            self.assertEqual(image.stat().st_size, before.st_size)
            self.assertEqual(default, explicit_default)
            self.assertEqual(streamed, default)
            self.assertEqual(streamed['/payload']['sha256'], hashlib.sha256(payload).hexdigest())
            self.assertEqual(streamed['/empty']['sha256'], hashlib.sha256(b'').hexdigest())
            self.assertEqual(streamed['/payload']['same_inode_paths'], ['/alias', '/payload'])
            self.assertEqual(streamed['/payload']['xattrs'], {'user.test': b'attribute-value'.hex()})
            self.assertEqual(streamed['/long']['symlink_target'], target)
            self.assertEqual(sorted(p.read_bytes() for p in (root / 'default').glob('data-*')),
                             [b'', payload])
            self.assertEqual(sorted(p.read_bytes() for p in (root / 'explicit-default').glob('data-*')),
                             [b'', payload])
            self.assertFalse(list((root / 'streamed').glob('data-*')))
            self.assertTrue(list((root / 'streamed').glob('batch-*.stderr')))

    def test_stream_rejects_debugfs_errors_and_wrong_lengths(self):
        cases = [
            ('stderr-error', b'abc', b'debugfs 1.47.0 (5-Feb-2023)\ncat: read failed\n', 0, 'debugfs failed'),
            ('short', b'ab', b'debugfs 1.47.0 (5-Feb-2023)\n', 0, 'Payload length mismatch'),
            ('long', b'abcd', b'', 0, 'Payload length mismatch'),
            ('nonzero', b'abc', b'', 1, 'debugfs failed'),
        ]
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            image = root / 'test.img'
            with image.open('wb') as stream:
                stream.truncate(8 * 1024**2)
            subprocess.run(['/usr/sbin/mke2fs', '-q', '-t', 'ext4', '-F', str(image)],
                           check=True, capture_output=True)
            (root / 'payload').write_bytes(b'abc')
            subprocess.run(['/usr/sbin/debugfs', '-w', '-R',
                            f'write {root / "payload"} /payload', str(image)],
                           check=True, capture_output=True)
            popen = subprocess.Popen
            for name, payload, stderr, returncode, message in cases:
                with self.subTest(name=name):
                    def substituted_cat(argv, **kwargs):
                        if argv[:2] == ['/usr/sbin/debugfs', '-R'] and argv[2].startswith('cat '):
                            code = (f'import os; os.write(1, {payload!r}); '
                                    f'os.write(2, {stderr!r}); raise SystemExit({returncode})')
                            return popen([sys.executable, '-c', code], **kwargs)
                        return popen(argv, **kwargs)
                    output = root / name
                    with patch('compare_vendor_trees.subprocess.Popen', side_effect=substituted_cat):
                        with self.assertRaisesRegex(ValueError, message):
                            inventory(image, output, retain_payloads=False)
                    self.assertFalse((output / 'inventory.json').exists())
                    self.assertFalse(list(output.glob('data-*')))
                    self.assertEqual(next(output.glob('cat-*.stderr')).read_bytes(), stderr)

    def test_exact_empty_slot_is_ignored(self):
        text = "/2/040755/0/0/.//\n/2/040755/0/0/..//\n/0/000000/0/0//0/\n/12/100644/0/0/build.prop/120/\n"
        self.assertEqual(directory_entries(text), [{"inode": 12, "mode": "100644", "uid": 0, "gid": 0, "name": "build.prop", "listed_size": 120}])

    def test_named_deleted_entry_is_not_silently_ignored(self):
        with self.assertRaises(ValueError):
            directory_entries("/0/100644/0/0/build.prop/120/\n")

    def test_external_symlink_is_read_exactly_only_when_enabled(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            image = root / 'test.img'
            with image.open('wb') as stream:
                stream.truncate(8 * 1024**2)
            subprocess.run(['/usr/sbin/mke2fs', '-q', '-t', 'ext4', '-F', str(image)], check=True, capture_output=True)
            target = '/a/' + 'long-target-' * 9
            subprocess.run(['/usr/sbin/debugfs', '-w', '-R', f'symlink /long {target}', str(image)],
                           check=True, capture_output=True)
            with self.assertRaisesRegex(ValueError, 'Non-inline symlink'):
                inventory(image, root / 'rejected')
            with self.assertRaisesRegex(ValueError, 'Non-inline symlink'):
                inventory(image, root / 'rejected-stream', retain_payloads=False)
            info = inventory(image, root / 'accepted', allow_external_symlinks=True)
            self.assertEqual(info['/long']['symlink_target'], target)
            self.assertEqual(info['/long']['size'], len(target))


if __name__ == "__main__":
    unittest.main()
