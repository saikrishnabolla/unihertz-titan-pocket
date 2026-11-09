# SPDX-License-Identifier: Apache-2.0
"""Host-only safety tests. Fake executable tools cannot contact a phone."""
from pathlib import Path
import gzip
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import plan_install as subject


class PlannerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.manifest = self.root / 'inputs.json'
        self.data = {
            'schema_version': 1, 'model': 'Titan_pocket', 'build': 'CP3A.260905.010',
            'mode': 'update', 'super': self.artifact('candidate.img', b'new-super'),
            'rollback_super': self.artifact('rollback.img.gz', b'old-super', 'gzip'),
            'expected_partitions': {}, 'protected_backups': {},
        }
        for name in subject.PROTECTED:
            self.data['protected_backups'][name] = self.artifact(name + '.bin', (name + '-backup').encode())
        self.data['expected_partitions'] = {name: self.data['protected_backups'][name]['sha256']
                                            for name in ('boot', 'recovery', 'vbmeta')}
        self.save()

    def artifact(self, name, data, compression='raw'):
        (self.root / name).write_bytes(gzip.compress(data) if compression == 'gzip' else data)
        return {'path': name, 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest(),
                'compression': compression}

    def save(self):
        self.manifest.write_text(json.dumps(self.data))

    def plan(self, **kwargs):
        self.save()
        return subject.validate_manifest(self.manifest, _super_bytes=9,
                                         _backup_sizes={name: len((name + '-backup').encode())
                                                        for name in subject.PROTECTED}, **kwargs)

    def assert_rejected(self, message):
        with self.assertRaisesRegex(subject.ValidationError, message):
            self.plan()

    def fake_tool(self, kind, overrides=None):
        responses = {'devices': ['BOUND device\n', '']} if kind == 'adb' else {'devices': ['BOUND fastboot\n', '']}
        if kind == 'adb':
            properties = {'ro.product.vendor.device': 'Titan_pocket', 'ro.board.platform': 'mt6771',
                          'ro.boot.flash.locked': '0', 'ro.boot.vbmeta.device_state': 'unlocked',
                          'sys.boot_completed': '1', 'ro.build.id': 'CP3A.260905.010',
                          'ro.gsid.image_running': '0'}
            responses.update({'-s BOUND shell getprop ' + k: [v + '\n', ''] for k, v in properties.items()})
            live_hashes = {name: entry['sha256'] for name, entry in self.data['protected_backups'].items()}
            live_hashes['super'] = self.data['rollback_super']['sha256']
            for name, value in live_hashes.items():
                responses['-s BOUND shell sha256sum /dev/block/by-name/' + name] = [value + '  /dev/block/by-name/' + name + '\n', '']
        else:
            variables = {'product': 'g66v71c2k_dfl_tee', 'is-userspace': 'no', 'unlocked': 'yes',
                         'slot-count': '0', 'partition-size:super': hex(4831838208),
                         'partition-size:userdata': hex(121978716160), 'partition-size:boot': hex(33554432),
                         'partition-size:recovery': hex(33554432), 'partition-size:vbmeta': hex(8388608)}
            responses.update({'-s BOUND getvar ' + k: ['', '(bootloader) ' + k + ': ' + v + '\n'] for k, v in variables.items()})
        responses.update(overrides or {})
        config = self.root / (kind + '.responses.json')
        config.write_text(json.dumps(responses))
        log = self.root / (kind + '.calls.jsonl')
        tool = self.root / kind
        tool.write_text('#!' + sys.executable + '\nimport sys,json\nfrom pathlib import Path\n' +
                        'key=" ".join(sys.argv[1:])\n' +
                        'with open(' + repr(str(log)) + ',"a") as f:f.write(json.dumps(sys.argv[1:])+"\\n")\n' +
                        'responses=json.loads(Path(' + repr(str(config)) + ').read_text())\n' +
                        'if key not in responses:sys.exit(44)\n' +
                        'out,err=responses[key]\nprint(out,end="")\nprint(err,end="",file=sys.stderr)\n')
        tool.chmod(0o700)
        return str(tool), log

    def test_offline_plan_verifies_real_raw_and_gzip_bytes(self):
        with patch.object(subject.subprocess, 'run', side_effect=AssertionError('Device access prohibited')):
            plan = self.plan()
        self.assertEqual(plan['proposed_writes'], ['super'])
        self.assertEqual(plan['proposed_erases'], [])
        self.assertEqual(plan['rollback_super']['sha256'], hashlib.sha256(b'old-super').hexdigest())
        self.assertEqual((plan['device_contacted'], plan['flashing_implemented']), (False, False))

    def test_clean_plan_requires_explicit_data_loss_acknowledgment(self):
        self.data['mode'] = 'clean'
        self.assert_rejected('requires --allow-userdata-erase')
        self.assertEqual(self.plan(allow_userdata_erase=True)['proposed_erases'], ['userdata'])

    def test_missing_recovery_backup_rejected(self):
        (self.root / 'recovery.bin').unlink()
        self.assert_rejected('missing')

    def test_corrupt_image_rejected(self):
        (self.root / 'candidate.img').write_bytes(b'bad-super')
        self.assert_rejected('SHA256 differs')

    def test_truncated_backup_rejected(self):
        (self.root / 'boot.bin').write_bytes(b'x')
        self.assert_rejected('byte count differs')

    def test_oversized_gzip_rejected(self):
        (self.root / 'rollback.img.gz').write_bytes(gzip.compress(b'A' * 100))
        self.assert_rejected('expands beyond')

    def test_expected_partition_hash_must_match_its_backup(self):
        self.data['expected_partitions']['boot'] = '0' * 64
        self.assert_rejected('does not match expected baseline')

    def test_path_traversal_rejected(self):
        self.data['super']['path'] = '../candidate.img'
        self.assert_rejected('escapes')

    def test_absolute_paths_rejected(self):
        self.data['super']['path'] = str(self.root / 'candidate.img')
        self.assert_rejected('escapes')

    def test_symlink_file_rejected(self):
        (self.root / 'link.img').symlink_to('candidate.img')
        self.data['super']['path'] = 'link.img'
        self.assert_rejected('Symlink')

    def test_symlink_parent_rejected(self):
        (self.root / 'linkdir').symlink_to(self.root, target_is_directory=True)
        self.data['super']['path'] = 'linkdir/candidate.img'
        self.assert_rejected('Symlink')

    def test_same_candidate_and_rollback_rejected(self):
        self.data['rollback_super'] = self.data['super'].copy()
        self.assert_rejected('distinct')

    def test_unknown_manifest_fields_rejected(self):
        self.data['erase_everything'] = True
        self.assert_rejected('Unexpected or missing')

    def test_duplicate_json_keys_rejected(self):
        self.manifest.write_text('{"mode":"update","mode":"clean"}')
        with self.assertRaisesRegex(subject.ValidationError, 'Duplicate'):
            subject.load_manifest(self.manifest)

    def test_model_and_build_are_pinned(self):
        self.data['model'] = 'Titan'
        self.assert_rejected('Unsupported device/build')
        self.data['model'] = 'Titan_pocket'
        self.data['build'] = 'unreviewed'
        self.assert_rejected('Unsupported device/build')

    def test_real_cli_enforces_production_size_without_device_access(self):
        output = self.root / 'plan.json'
        run = subprocess.run([sys.executable, subject.__file__, 'plan', '--manifest', str(self.manifest),
                              '--output', str(output)], capture_output=True, text=True)
        self.assertEqual(run.returncode, 1)
        self.assertIn('partition size differs', run.stderr)
        self.assertFalse(output.exists())

    def test_adb_preflight_uses_bound_serial_and_hashes(self):
        tool, log = self.fake_tool('adb')
        result = subject.preflight(self.plan(), 'BOUND', 'adb', adb=tool)
        self.assertTrue(result['protected_baseline_hashes_match'])
        self.assertEqual(result['device_identity_sha256'], hashlib.sha256(b'BOUND').hexdigest())
        self.assertNotIn('BOUND', json.dumps(result))
        calls = [json.loads(line) for line in log.read_text().splitlines()]
        self.assertEqual(calls[0], ['devices'])
        self.assertTrue(all(call[:3] == ['-s', 'BOUND', 'shell'] for call in calls[1:]))
        self.assertTrue(all(call[3].startswith(('getprop ', 'sha256sum ')) for call in calls[1:]))

    def test_two_adb_devices_are_rejected_even_when_selected(self):
        tool, log = self.fake_tool('adb', {'devices': ['BOUND device\nOTHER device\n', '']})
        with self.assertRaisesRegex(subject.ValidationError, 'exactly one'):
            subject.preflight(self.plan(), 'BOUND', 'adb', adb=tool)
        self.assertEqual(len(log.read_text().splitlines()), 1)

    def test_adb_unauthorized_rejected(self):
        tool, _ = self.fake_tool('adb', {'devices': ['BOUND unauthorized\n', '']})
        with self.assertRaisesRegex(subject.ValidationError, 'authorized matching'):
            subject.preflight(self.plan(), 'BOUND', 'adb', adb=tool)

    def test_unknown_device_model_rejected(self):
        tool, _ = self.fake_tool('adb', {'-s BOUND shell getprop ro.product.vendor.device': ['Titan_Slim\n', '']})
        with self.assertRaisesRegex(subject.ValidationError, 'model differs'):
            subject.preflight(self.plan(), 'BOUND', 'adb', adb=tool)

    def test_locked_adb_device_rejected(self):
        tool, _ = self.fake_tool('adb', {'-s BOUND shell getprop ro.boot.flash.locked': ['1\n', '']})
        with self.assertRaisesRegex(subject.ValidationError, 'not confirmed unlocked'):
            subject.preflight(self.plan(), 'BOUND', 'adb', adb=tool)

    def test_live_partition_mismatch_rejected(self):
        tool, _ = self.fake_tool('adb', {'-s BOUND shell sha256sum /dev/block/by-name/boot': ['0' * 64 + '  /dev/block/by-name/boot\n', '']})
        with self.assertRaisesRegex(subject.ValidationError, 'does not match baseline'):
            subject.preflight(self.plan(), 'BOUND', 'adb', adb=tool)

    def test_live_super_and_calibration_must_match_saved_backups(self):
        for name in ['super', 'nvram']:
            with self.subTest(partition=name):
                command = '-s BOUND shell sha256sum /dev/block/by-name/' + name
                tool, _ = self.fake_tool('adb', {command: ['0' * 64 + '  /dev/block/by-name/' + name + '\n', '']})
                with self.assertRaisesRegex(subject.ValidationError, 'does not match baseline'):
                    subject.preflight(self.plan(), 'BOUND', 'adb', adb=tool)

    def test_active_dsu_guest_rejected(self):
        tool, _ = self.fake_tool('adb', {'-s BOUND shell getprop ro.gsid.image_running': ['1\n', '']})
        with self.assertRaisesRegex(subject.ValidationError, 'DSU guest'):
            subject.preflight(self.plan(), 'BOUND', 'adb', adb=tool)

    def test_fastboot_preflight_checks_physical_device_and_partition_sizes(self):
        tool, log = self.fake_tool('fastboot')
        result = subject.preflight(self.plan(), 'BOUND', 'fastboot', fastboot=tool)
        self.assertEqual((result['partition_sizes_match'], result['physical_bootloader']), (True, True))
        calls = [json.loads(line) for line in log.read_text().splitlines()]
        self.assertEqual(calls[0], ['devices'])
        self.assertTrue(all(call[:3] == ['-s', 'BOUND', 'getvar'] for call in calls[1:]))

    def test_fastbootd_locked_wrong_size_wrong_product_and_duplicate_variables_rejected(self):
        for key, output in [('is-userspace', 'yes'), ('unlocked', 'no'),
                            ('partition-size:super', '0x10'), ('product', 'unknown')]:
            with self.subTest(key=key):
                tool, _ = self.fake_tool('fastboot', {'-s BOUND getvar ' + key: ['', key + ': ' + output + '\n']})
                with self.assertRaises(subject.ValidationError):
                    subject.preflight(self.plan(), 'BOUND', 'fastboot', fastboot=tool)
        tool, _ = self.fake_tool('fastboot', {'-s BOUND getvar unlocked': ['', 'unlocked: yes\nunlocked: no\n']})
        with self.assertRaisesRegex(subject.ValidationError, 'Ambiguous'):
            subject.preflight(self.plan(), 'BOUND', 'fastboot', fastboot=tool)

    def test_explicit_serial_injection_rejected(self):
        with self.assertRaisesRegex(subject.ValidationError, 'Invalid explicit serial'):
            subject.preflight(self.plan(), 'BOUND;reboot', 'adb', adb='/not-used')

    def test_output_is_private_and_cannot_overwrite_existing_file(self):
        path = self.root / 'result.json'
        subject.write_record(path, self.plan())
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        before = path.read_bytes()
        with self.assertRaises(subject.ValidationError):
            subject.write_record(path, {'new': 1})
        self.assertEqual(path.read_bytes(), before)


if __name__ == '__main__':
    unittest.main()
