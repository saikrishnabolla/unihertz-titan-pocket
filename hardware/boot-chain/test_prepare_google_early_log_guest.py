import copy
import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import prepare_google_early_log_guest as guest


class EarlyLogGuestTests(unittest.TestCase):
    def test_contexts_preserve_existing_rules(self):
        original = b'/existing u:object_r:system_file:s0\n'
        with patch.object(guest, 'OLD_CONTEXTS_SHA', hashlib.sha256(original).hexdigest()):
            result = guest.add_contexts(original)
        self.assertEqual(result, original + guest.CONTEXTS)
        self.assertEqual(len(guest.CONTEXTS.splitlines()), 2)

    def test_contexts_reject_unreviewed_baseline(self):
        with self.assertRaisesRegex(ValueError, 'Unexpected'):
            guest.add_contexts(b'unknown\n')

    def test_added_helper_metadata_is_private_and_does_not_mutate_template(self):
        template = {'type': 'regular', 'permissions': '0644', 'uid': 1, 'gid': 2,
                    'links': 1, 'size': 9, 'sha256': 'old', 'same_inode_paths': ['/old'],
                    'xattrs': {'security.selinux': 'old'}, 'flags': 524288, 'generation': 0}
        saved = copy.deepcopy(template)
        result = guest.added_item(template, '/system/bin/titan-diag', b'literal', executable=True)
        self.assertEqual(template, saved)
        self.assertEqual((result['uid'], result['gid'], result['permissions']), (0, 0, '0755'))
        self.assertEqual(result['same_inode_paths'], ['/system/bin/titan-diag'])
        self.assertEqual(result['sha256'], hashlib.sha256(b'literal').hexdigest())
        self.assertEqual(bytes.fromhex(result['xattrs']['security.selinux']), b'u:object_r:titan_diag_exec:s0\0')

    def test_new_file_refuses_shared_template(self):
        with self.assertRaisesRegex(ValueError, 'unique'):
            guest.added_item({'type': 'regular', 'links': 2}, '/new', b'payload')

    def test_deployment_requires_exact_payload_pins(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'platform').write_bytes(b'literal platform')
            (root / 'vendor').write_bytes(b'literal vendor')
            entries = (('system', '/platform', 'platform', 'old', hashlib.sha256(b'literal platform').hexdigest()),
                       ('vendor', '/vendor', 'vendor', 'old', hashlib.sha256(b'literal vendor').hexdigest()))
            with patch.object(guest, 'DEPLOYMENT', entries):
                self.assertEqual(guest.policy_payloads(root), {'system': {'/platform': b'literal platform'},
                                                             'vendor': {'/vendor': b'literal vendor'}})
                (root / 'vendor').write_bytes(b'changed')
                with self.assertRaisesRegex(ValueError, 'reviewed pin'):
                    guest.policy_payloads(root)


if __name__ == '__main__':
    unittest.main()
