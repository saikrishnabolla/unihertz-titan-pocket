import copy
from pathlib import Path
import subprocess
import tempfile
import unittest

from prepare_google_legacy_guest import audit_vendor_configs, expected_inventory


class RepairDeltaTests(unittest.TestCase):
    def test_only_declared_content_and_size_change(self):
        before = {'/config': {'type': 'regular', 'links': 1, 'size': 99,
                              'sha256': 'old', 'uid': 0, 'gid': 2000,
                              'permissions': '0644', 'xattrs': {'security.selinux': '00'}},
                  '/other': {'sha256': 'unrelated'}}
        original = copy.deepcopy(before)
        self.assertEqual(expected_inventory(before, {'/config': b'abc'}),
                         {'/config': {'type': 'regular', 'links': 1, 'size': 3,
                                      'sha256': 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
                                      'uid': 0, 'gid': 2000, 'permissions': '0644',
                                      'xattrs': {'security.selinux': '00'}},
                          '/other': {'sha256': 'unrelated'}})
        self.assertEqual(before, original)

    def test_shared_or_nonregular_target_is_rejected(self):
        for kind, links in [('symlink', 1), ('directory', 1), ('regular', 2)]:
            with self.subTest(kind=kind, links=links), self.assertRaises(ValueError):
                expected_inventory({'/config': {'type': kind, 'links': links}}, {'/config': b'abc'})

    def test_config_audit_accepts_files_without_terminal_newline(self):
        with tempfile.TemporaryDirectory(prefix='legacy-audit-test-') as temporary:
            root = Path(temporary)
            tree = root / 'tree'
            tree.mkdir()
            (tree / 'a.rc').write_bytes(b'on boot\n    setprop example value')
            (tree / 'fstab.test').write_bytes(b'/dev/block/by-name/userdata /data ext4 defaults wait,formattable\n')
            image = root / 'fixture.ext4'
            subprocess.run(['/usr/sbin/mke2fs', '-q', '-F', '-t', 'ext4', '-b', '4096',
                            '-d', str(tree), str(image), '2048'], check=True, capture_output=True)
            result = audit_vendor_configs(image, {'/a.rc': {'type': 'regular'},
                                                  '/fstab.test': {'type': 'regular'}})
            self.assertEqual(result['scanned_regular_rc_fstab_files'], 2)
            self.assertEqual(result['apd_mentions'], [])
            self.assertEqual(result['formattable_entries'],
                             [{'path': '/fstab.test', 'line': 1, 'source': '/dev/block/by-name/userdata'}])


if __name__ == '__main__':
    unittest.main()
