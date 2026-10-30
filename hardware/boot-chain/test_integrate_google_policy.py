import copy
import hashlib
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import integrate_google_policy as tool


class GoogleVendorPolicyTests(unittest.TestCase):
    def entries(self):
        replacements = {tool.PREFIX: b'policy'}
        replacements.update({tool.PREFIX + '.' + name + '_sepolicy_and_mapping.sha256':
                             (value + '\n').encode() for name, value in tool.IDENTIFIERS.items()})
        before = {path: {'type': 'regular', 'links': 1, 'same_inode_paths': [path],
                         'size': 3, 'sha256': 'old', 'uid': 0, 'xattrs': {'label': '00'}}
                  for path in replacements}
        before['/etc/unrelated'] = {'type': 'regular', 'sha256': 'original'}
        after = copy.deepcopy(before)
        for path, data in replacements.items():
            after[path].update(sha256=hashlib.sha256(data).hexdigest(), size=len(data))
        return before, after, replacements

    def test_only_four_exact_payloads_change(self):
        before, after, replacements = self.entries()
        self.assertEqual(tool.compare(before, after, replacements), sorted(replacements))

    def test_unrelated_corruption_and_label_loss_are_refused(self):
        for path, key, value in [('/etc/unrelated', 'sha256', 'bad'),
                                 (tool.PREFIX, 'xattrs', {})]:
            before, after, replacements = self.entries()
            after[path][key] = value
            with self.subTest(path=path), self.assertRaisesRegex(ValueError, 'metadata delta'):
                tool.compare(before, after, replacements)

    def test_extra_replacement_is_refused(self):
        before, after, replacements = self.entries()
        replacements['/etc/unrelated'] = b'not permitted'
        with self.assertRaisesRegex(ValueError, 'replacement set'):
            tool.compare(before, after, replacements)

    def test_wrong_source_refused_before_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / 'source'
            source.write_bytes(b'not vendor')
            with self.assertRaisesRegex(ValueError, 'pinned candidate'):
                tool.build(source, root / 'unused', root / 'output')
            self.assertFalse((root / 'output').exists())

    def test_final_comparison_is_enforced_before_publishing(self):
        before, after, replacements = self.entries()
        stamp = [f'{key}: 0x00000000:00000000 -- Thu Jan 1 00:00:00 1970'
                 for key in ('ctime', 'atime', 'mtime', 'crtime')]
        for path in replacements:
            before[path].update(permissions='0644', gid=0, flags=0x80000,
                                generation=0, project_id=0, timestamps_debugfs=stamp)
        before['/etc/selinux'] = {'type': 'directory', 'timestamps_debugfs': stamp}
        after = copy.deepcopy(before)
        for path, data in replacements.items():
            after[path].update(sha256=hashlib.sha256(data).hexdigest(), size=len(data))
        after['/etc/unrelated']['sha256'] = 'corrupted original'
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, policy = root / 'source', root / 'policy'
            source.write_bytes(b'vendor'); policy.write_bytes(b'policy')
            run = lambda *args, **kwargs: SimpleNamespace(stdout='', stderr='', returncode=0)
            with patch.object(tool, 'SOURCE_SHA', hashlib.sha256(b'vendor').hexdigest()), \
                 patch.object(tool, 'POLICY_SHA', hashlib.sha256(b'policy').hexdigest()), \
                 patch.object(tool, 'full_inventory', side_effect=[before, after]), \
                 patch.object(tool, 'runner', return_value=run), patch.object(tool, 'split_batch'):
                with self.assertRaisesRegex(ValueError, 'metadata delta'):
                    tool.build(source, policy, root / 'output')
            self.assertFalse((root / 'output/report.json').exists())
            self.assertFalse((root / 'output/vendor.ext4').exists())
            self.assertEqual(source.read_bytes(), b'vendor')
