import copy
from pathlib import Path
import tempfile
import unittest
import hashlib
from types import SimpleNamespace
from unittest.mock import patch

import integrate_google_connectivity as tool


class GoogleIntegrationTests(unittest.TestCase):
    def entries(self):
        before = {tool.PARENT: {'type': 'directory', 'links': 2},
                  tool.OLD: {'type': 'regular', 'links': 1, 'sha256': tool.ORIGINAL_SHA,
                             'size': 4, 'same_inode_paths': [tool.OLD], 'uid': 0,
                             'xattrs': {'security.selinux': 'label'}}}
        after = copy.deepcopy(before)
        after[tool.NEW] = after.pop(tool.OLD)
        after[tool.NEW].update(sha256='replacement', size=8, same_inode_paths=[tool.NEW])
        return before, after

    def test_exact_compressed_to_uncompressed_replacement(self):
        before, after = self.entries()
        self.assertEqual(tool.compare(before, after, 'replacement', 8),
                         {'removed': [tool.OLD], 'added': [tool.NEW], 'all_unrelated_entries_equal': True})

    def test_duplicate_original_corruption_or_metadata_loss_refused(self):
        for mutation in ('duplicate', 'corrupt', 'metadata'):
            before, after = self.entries()
            if mutation == 'duplicate':
                after[tool.OLD] = before[tool.OLD]
            elif mutation == 'corrupt':
                after[tool.NEW]['sha256'] = 'corrupted'
            else:
                after[tool.NEW]['xattrs'] = {}
            with self.subTest(mutation=mutation), self.assertRaisesRegex(ValueError, 'filesystem delta'):
                tool.compare(before, after, 'replacement', 8)

    def test_wrong_source_refused_before_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / 'source'
            source.write_bytes(b'not the pinned base')
            with self.assertRaisesRegex(ValueError, 'pinned draft'):
                tool.build(source, root / 'unused-apex', root / 'output')
            self.assertFalse((root / 'output').exists())

    def test_build_rejects_final_corruption_without_publishing(self):
        before, after = self.entries()
        stamp = [f'{key}: 0x00000000:00000000 -- Thu Jan 1 00:00:00 1970'
                 for key in ('ctime', 'atime', 'mtime', 'crtime')]
        before[tool.OLD].update(permissions='0644', gid=0, flags=0x80000,
                                generation=0, project_id=0, timestamps_debugfs=stamp,
                                xattrs={'security.selinux': '00'})
        before[tool.PARENT]['timestamps_debugfs'] = stamp
        after = copy.deepcopy(before)
        after[tool.NEW] = after.pop(tool.OLD)
        after[tool.NEW].update(size=8, sha256='corrupted', same_inode_paths=[tool.NEW])
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, apex = root / 'source', root / 'apex'
            source.write_bytes(b'system'); apex.write_bytes(b'apexfile')
            run = lambda *args, **kwargs: SimpleNamespace(stdout='', stderr='', returncode=0)
            with patch.object(tool, 'SOURCE_SHA', hashlib.sha256(b'system').hexdigest()), \
                 patch.object(tool, 'APEX_SHA', hashlib.sha256(b'apexfile').hexdigest()), \
                 patch.object(tool, 'full_inventory', side_effect=[before, after]), \
                 patch.object(tool, 'runner', return_value=run), patch.object(tool, 'split_batch'):
                with self.assertRaisesRegex(ValueError, 'filesystem delta'):
                    tool.build(source, apex, root / 'output')
            self.assertFalse((root / 'output/report.json').exists())
            self.assertFalse((root / 'output/system.ext4').exists())
            self.assertEqual(source.read_bytes(), b'system')


if __name__ == '__main__':
    unittest.main()
