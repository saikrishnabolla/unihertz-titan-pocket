import copy
import unittest
from unittest.mock import patch

import sign_google_early_log_guest as signer


class EarlyLogSigningTests(unittest.TestCase):
    def fixture(self):
        report = {'policy_sha256': signer.POLICY_SHA, 'artifacts': {},
                  'vendor_config_audit': {'formattable_entries': [{'source': '/dev/block/by-name/userdata'}]}}
        for name, spec in signer.SPECS.items():
            changed = [path for partition, path, *_ in signer.DEPLOYMENT if partition == name]
            added = []
            if name == 'system':
                changed += ['/system/etc/init/hw/init.rc', '/system/etc/selinux/plat_file_contexts']
                added = ['/system/bin/titan-diag', '/system/etc/init/titan-diag.rc']
            report['artifacts'][name] = {'filesystem_sha256': 'a' * 64, 'filesystem_bytes': spec[1],
                                         'partition_bytes': spec[0], 'source_sha256': spec[2],
                                         'changed_paths': sorted(changed), 'added_paths': sorted(added),
                                         'all_other_inventoried_contents_metadata_unchanged': True}
        return report

    def test_unreviewed_pins_stop_before_signing(self):
        with patch.object(signer, 'FILESYSTEM_SHAS', {'system': None, 'vendor': None}):
            with self.assertRaisesRegex(ValueError, 'review'):
                signer.validate(self.fixture())

    def test_literal_artifact_scope(self):
        report = self.fixture()
        with patch.object(signer, 'FILESYSTEM_SHAS', {'system': 'a' * 64, 'vendor': 'a' * 64}):
            signer.validate(report)
            changed = copy.deepcopy(report)
            changed['artifacts']['system']['changed_paths'].append('/system/bin/vold')
            with self.assertRaisesRegex(ValueError, 'recorder delta'):
                signer.validate(changed)

    def test_format_guard_required(self):
        report = self.fixture()
        report['vendor_config_audit']['formattable_entries'] = []
        with patch.object(signer, 'FILESYSTEM_SHAS', {'system': 'a' * 64, 'vendor': 'a' * 64}):
            with self.assertRaisesRegex(ValueError, 'formatting guards'):
                signer.validate(report)


if __name__ == '__main__':
    unittest.main()
