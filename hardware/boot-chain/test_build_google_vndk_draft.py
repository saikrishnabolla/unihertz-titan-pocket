import copy
import unittest
from pathlib import Path
import tempfile
import hashlib
from types import SimpleNamespace
from unittest.mock import patch

import build_google_vndk_draft as tool
from build_google_vndk_draft import TARGET, TEMPLATE, build, compare_added_vndk


class GoogleVndkDeltaTests(unittest.TestCase):
    def baseline(self):
        return {
            '/': {'type': 'directory', 'links': 2},
            TEMPLATE: {'type': 'regular', 'links': 1, 'same_inode_paths': [TEMPLATE],
                       'size': 4, 'sha256': 'original', 'uid': 0, 'gid': 0,
                       'permissions': '0644', 'xattrs': {'security.selinux': '00'}},
        }

    def after(self, before):
        after = copy.deepcopy(before)
        after[TARGET] = {**copy.deepcopy(before[TEMPLATE]), 'same_inode_paths': [TARGET],
                         'size': 12, 'sha256': 'donor'}
        return after

    def test_accepts_exactly_one_signed_donor_payload(self):
        before = self.baseline()
        self.assertEqual(compare_added_vndk(before, self.after(before), 'donor', 12), [TARGET])

    def test_rejects_unrelated_metadata_or_extra_path(self):
        before = self.baseline()
        after = self.after(before)
        after['/']['links'] = 3
        with self.assertRaisesRegex(ValueError, 'Unexpected'):
            compare_added_vndk(before, after, 'donor', 12)
        after = self.after(before)
        after['/extra'] = {'type': 'regular'}
        with self.assertRaisesRegex(ValueError, 'Unexpected'):
            compare_added_vndk(before, after, 'donor', 12)

    def test_rejects_changed_donor_or_weakened_label(self):
        before = self.baseline()
        after = self.after(before)
        after[TARGET]['sha256'] = 'tampered'
        with self.assertRaisesRegex(ValueError, 'Unexpected'):
            compare_added_vndk(before, after, 'donor', 12)

    def test_rejects_original_payload_corruption_and_deletion(self):
        before = self.baseline()
        after = self.after(before)
        after[TEMPLATE]['sha256'] = 'CORRUPTED ORIGINAL'
        with self.assertRaisesRegex(ValueError, 'Unexpected'):
            compare_added_vndk(before, after, 'donor', 12)
        after = self.after(before)
        del after[TEMPLATE]
        with self.assertRaisesRegex(ValueError, 'Unexpected'):
            compare_added_vndk(before, after, 'donor', 12)

    def test_rejects_original_hardlink_symlink_and_metadata_changes(self):
        before = self.baseline()
        before['/system/vendor'] = {'type': 'symlink', 'symlink_target': '/vendor'}
        before['/system/linked'] = {'type': 'regular', 'same_inode_paths': ['/system/linked', '/system/alias'], 'links': 2}
        for path, field, value in [(TEMPLATE, 'uid', 2000),
                                   ('/system/vendor', 'symlink_target', '/wrong'),
                                   ('/system/linked', 'same_inode_paths', ['/system/linked'])]:
            after = self.after(before)
            after[path][field] = value
            with self.subTest(path=path, field=field), self.assertRaisesRegex(ValueError, 'Unexpected'):
                compare_added_vndk(before, after, 'donor', 12)
        after = self.after(before)
        after[TARGET]['xattrs'] = {}
        with self.assertRaisesRegex(ValueError, 'Unexpected'):
            compare_added_vndk(before, after, 'donor', 12)

    def test_changed_source_refused_before_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / 'source.img'
            source.write_bytes(b'not the Google image')
            with self.assertRaisesRegex(ValueError, 'pinned original'):
                build(source, root / 'donor', root / 'avbtool', root / 'output')
            self.assertFalse((root / 'output').exists())

    def test_symlink_source_is_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / 'original.img'
            source.write_bytes(b'owner bytes')
            link = root / 'link.img'
            link.symlink_to(source)
            with self.assertRaisesRegex(ValueError, 'regular, non-symlink'):
                build(link, root / 'donor', root / 'avbtool', root / 'output')
            self.assertEqual(source.read_bytes(), b'owner bytes')


class GoogleVndkBuildTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / 'source.img'
        self.donor = self.root / 'donor.apex'
        self.source.write_bytes(b'original system')
        self.donor.write_bytes(b'signed donor')
        self.output = self.root / 'output'
        self.enterContext(patch.object(tool, 'SOURCE_SHA', hashlib.sha256(self.source.read_bytes()).hexdigest()))
        self.enterContext(patch.object(tool, 'DONOR_SHA', hashlib.sha256(self.donor.read_bytes()).hexdigest()))
        self.enterContext(patch.object(tool, 'FS_BYTES', 4096))

    def inventories(self):
        before = GoogleVndkDeltaTests().baseline()
        stamp = [f'{key}: 0x495c0780:00000000 -- Thu Jan  1 00:00:00 2009'
                 for key in ('ctime', 'atime', 'mtime', 'crtime')]
        before[TEMPLATE].update(timestamps_debugfs=stamp, flags=0x80000, generation=0, project_id=0)
        before[tool.PARENT] = {'type': 'directory', 'timestamps_debugfs': stamp}
        after = copy.deepcopy(before)
        after[TARGET] = copy.deepcopy(before[TEMPLATE])
        after[TARGET].update(same_inode_paths=[TARGET], sha256=tool.DONOR_SHA, size=self.donor.stat().st_size)
        return before, after

    def test_donor_mismatch_refuses_output_and_tool_use(self):
        self.donor.write_bytes(b'changed donor')
        with patch.object(tool, 'tool_check') as check:
            with self.assertRaisesRegex(ValueError, 'pinned original'):
                build(self.source, self.donor, self.root / 'tool', self.output)
        check.assert_not_called()
        self.assertFalse(self.output.exists())

    def test_tool_mismatch_refuses_output(self):
        fake_tool = self.root / 'tool.py'
        fake_tool.write_text('not the pinned AVB tool')
        with self.assertRaisesRegex(ValueError, 'Unexpected avbtool'):
            build(self.source, self.donor, fake_tool, self.output)
        self.assertFalse(self.output.exists())

    def test_success_writes_only_new_image_and_publishes_after_checks(self):
        before, after = self.inventories()
        commands = []
        def run(args, **kwargs):
            commands.append([str(arg) for arg in args])
            self.assertFalse((self.output / 'system-vndk30-draft.ext4').exists())
            return SimpleNamespace(stdout='', stderr='', returncode=0)
        with patch.object(tool, 'tool_check') as check, patch.object(tool, 'runner', return_value=run), \
             patch.object(tool, 'full_inventory', side_effect=[before, before, after]), \
             patch.object(tool, 'unshare'), patch.object(tool, 'split_batch'):
            report = build(self.source, self.donor, self.root / 'tool', self.output)
        check.assert_called_once()
        image = str(self.output / 'system-vndk30-draft.partial.ext4')
        self.assertTrue(all(image in command for command in commands))
        self.assertEqual(self.source.read_bytes(), b'original system')
        self.assertEqual(self.donor.read_bytes(), b'signed donor')
        self.assertEqual(report['added_paths'], [TARGET])
        self.assertTrue((self.output / 'report.json').exists())
        self.assertTrue((self.output / 'system-vndk30-draft.ext4').exists())
        self.assertFalse(Path(image).exists())

    def test_fsck_failure_keeps_partial_without_success_report(self):
        before, _ = self.inventories()
        def run(args, **kwargs):
            if str(args[0]).endswith('e2fsck'):
                raise ValueError('filesystem check failed')
            return SimpleNamespace(stdout='', stderr='', returncode=0)
        with patch.object(tool, 'tool_check'), patch.object(tool, 'runner', return_value=run), \
             patch.object(tool, 'full_inventory', side_effect=[before, before]), \
             patch.object(tool, 'unshare'), patch.object(tool, 'split_batch'):
            with self.assertRaisesRegex(ValueError, 'filesystem check failed'):
                build(self.source, self.donor, self.root / 'tool', self.output)
        self.assertFalse((self.output / 'report.json').exists())
        self.assertFalse((self.output / 'system-vndk30-draft.ext4').exists())
        self.assertTrue((self.output / 'system-vndk30-draft.partial.ext4').exists())

    def test_final_inventory_corruption_is_not_published(self):
        before, after = self.inventories()
        after[TEMPLATE]['sha256'] = 'corrupted original'
        run = lambda *args, **kwargs: SimpleNamespace(stdout='', stderr='', returncode=0)
        with patch.object(tool, 'tool_check'), patch.object(tool, 'runner', return_value=run), \
             patch.object(tool, 'full_inventory', side_effect=[before, before, after]), \
             patch.object(tool, 'unshare'), patch.object(tool, 'split_batch'):
            with self.assertRaisesRegex(ValueError, 'Unexpected filesystem delta'):
                build(self.source, self.donor, self.root / 'tool', self.output)
        self.assertFalse((self.output / 'report.json').exists())
        self.assertFalse((self.output / 'system-vndk30-draft.ext4').exists())

    def test_input_change_during_build_is_not_published(self):
        before, after = self.inventories()
        def inventory(image, destination):
            if destination.name == 'after':
                self.source.write_bytes(b'concurrent source change')
                return after
            return before
        run = lambda *args, **kwargs: SimpleNamespace(stdout='', stderr='', returncode=0)
        with patch.object(tool, 'tool_check'), patch.object(tool, 'runner', return_value=run), \
             patch.object(tool, 'full_inventory', side_effect=inventory), \
             patch.object(tool, 'unshare'), patch.object(tool, 'split_batch'):
            with self.assertRaisesRegex(ValueError, 'Original input changed'):
                build(self.source, self.donor, self.root / 'tool', self.output)
        self.assertFalse((self.output / 'report.json').exists())
        self.assertFalse((self.output / 'system-vndk30-draft.ext4').exists())


if __name__ == '__main__':
    unittest.main()
