import unittest
import os
from pathlib import Path
import build_vendor as b

LINE = '/dev/block/by-name/userdata /data ext4 noatime,nosuid,nodev,noauto_da_alloc,errors=panic,inlinecrypt wait,check,formattable,quota,latemount,resize,reservedsize=128m,checkpoint=block,fileencryption=aes-256-xts:aes-256-cts:v2,keydirectory=/metadata/vold/metadata_encryption\n'
OTHER = '/dev/block/by-name/md_udc /metadata ext4 noatime,nosuid,nodev,discard wait,check,first_stage_mount\n'

class FstabTests(unittest.TestCase):
    def test_only_data_semantics_change_and_size_held(self):
        source = ('# preserve comment\n' + OTHER + '\n'*8 + LINE).encode()
        result = b.transform_fstab(source)
        self.assertEqual(len(source), len(result))
        self.assertEqual(result.splitlines()[:2], source.splitlines()[:2])
        old = LINE.split(); new = result.decode().splitlines()[-1].split()
        self.assertEqual(old[:4], new[:4])
        self.assertEqual(new[4].split(','), [b.NEW_KEY if x == b.OLD_KEY else x for x in old[4].split(',')])
    def rejected(self, line):
        with self.assertRaises(ValueError): b.transform_fstab(line.encode())
    def test_duplicate_data(self): self.rejected(LINE + LINE)
    def test_missing_data(self): self.rejected(OTHER)
    def test_wrong_device(self): self.rejected(LINE.replace('/dev/block/by-name/userdata', '/dev/block/dm-0'))
    def test_wrong_keydir(self): self.rejected(LINE.replace(b.OLD_KEY, b.NEW_KEY))
    def test_duplicate_keydir(self): self.rejected(LINE.replace(b.OLD_KEY, b.OLD_KEY + ',' + b.OLD_KEY))
    def test_absent_formattable(self): self.rejected(LINE.replace('formattable,', ''))
    def test_absent_resize(self): self.rejected(LINE.replace('resize,', ''))
    def test_changed_cipher(self): self.rejected(LINE.replace('aes-256-cts:v2', 'aes-256-cts:v1'))
    def test_missing_inlinecrypt(self): self.rejected(LINE.replace(',inlinecrypt', ''))
    def test_duplicate_flag(self): self.rejected(LINE.replace('check,', 'check,check,'))
    def test_extra_column(self): self.rejected(LINE.rstrip() + ' surprise\n')
    def test_scope_rejects_outside_change(self):
        with self.assertRaises(ValueError): b.validate_scope(b'abcdef', b'xbcdyf', [(4,5)])
    def test_scope_accepts_only_expected_byte(self):
        self.assertEqual(b.validate_scope(b'abcdef', b'abcdyf', [(4,5)]), 1)
    def test_scope_rejects_length_change(self):
        with self.assertRaises(ValueError): b.validate_scope(b'abcdef', b'abcdefg', [(0,7)])
    def test_wrong_signing_public_key(self):
        with self.assertRaises(ValueError): b.verify_public_key(b'wrong', b'expected')
    def test_matching_signing_public_key(self):
        b.verify_public_key(b'expected', b'expected')
    def test_target_uses_relocated_titan17_directory(self):
        self.assertEqual(b.NEW_KEY, 'keydirectory=/metadata/vold/metadata_encryption/titan17')
        fields = b.transform_fstab(('\n'*8 + LINE).encode()).decode().split()
        self.assertIn('keydirectory=/metadata/vold/metadata_encryption/titan17', fields[4].split(','))
        self.assertNotIn('keydirectory=/metadata/vold/metadata_encryption/dsu/dsu', fields[4].split(','))
    def test_dsu_directory_source_rejected(self):
        self.rejected(LINE.replace(b.OLD_KEY, b.OLD_KEY + '/dsu/dsu'))
    def test_gsi_directory_source_rejected(self):
        self.rejected(LINE.replace(b.OLD_KEY, b.OLD_KEY + '/gsi'))
    def test_insufficient_blank_lines_rejected(self):
        self.rejected('\n'*7 + LINE)
    def test_whitespace_only_lines_not_reclaimed(self):
        self.rejected(' \n'*8 + LINE)
    def test_formattable_and_resize_preserved(self):
        fields = b.transform_fstab(('\n'*8 + LINE).encode()).decode().split()
        self.assertIn('formattable', fields[4].split(','))
        self.assertIn('resize', fields[4].split(','))
    @unittest.skipUnless(os.environ.get('TITAN_VENDOR_SOURCE'), 'Set TITAN_VENDOR_SOURCE for private-image integration check')
    def test_real_pinned_vendor_header(self):
        source = Path(os.environ['TITAN_VENDOR_SOURCE'])
        info = b.parse_avb(source)
        self.assertEqual(info['properties'], {})
        self.assertEqual(info['rollback_index'], 0)
        self.assertEqual(len(info['public_key']), 520)

class RekeyTests(unittest.TestCase):
    def test_key_change_requires_explicit_opt_in(self):
        with self.assertRaisesRegex(ValueError, '--new-signing-key'):
            b.verify_public_key(b'new', b'old')
        self.assertTrue(b.verify_public_key(b'new', b'old', True))
        self.assertFalse(b.verify_public_key(b'old', b'old', True))

    def test_rekey_changes_only_key(self):
        before = {'public_key': b'old', 'properties': {'build': 'pinned'},
                  'rollback_index': 0, 'flags': 0, 'location': 0, 'salt': 'a', 'tree_bytes': 4096}
        after = {**before, 'public_key': b'new'}
        b.verify_avb_settings(before, after, True)
        with self.assertRaises(ValueError):
            b.verify_avb_settings(before, after)
        for field, changed in [('flags', 3), ('rollback_index', 1), ('location', 1),
                               ('properties', {}), ('salt', 'b'), ('tree_bytes', 8192)]:
            with self.subTest(field=field), self.assertRaises(ValueError):
                b.verify_avb_settings(before, {**after, field: changed}, True)

    def test_same_key_requires_all_settings_unchanged(self):
        before = {'public_key': b'old', 'flags': 0}
        b.verify_avb_settings(before, dict(before))
        with self.assertRaises(ValueError):
            b.verify_avb_settings(before, {**before, 'flags': 3})

if __name__ == '__main__': unittest.main()
