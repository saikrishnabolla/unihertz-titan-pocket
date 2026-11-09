# SPDX-License-Identifier: Apache-2.0
"""All writes target fake fastboot executables and tiny local images."""
import json
from pathlib import Path
import unittest
from unittest.mock import patch

import execute_update as executor
import plan_install as planner
import test_plan_install as fixtures


class UpdateTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.PlannerTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.tmp.cleanup)
        self.root = self.fixture.root
        self.plan = self.fixture.plan()
        self.plan_file = self.root / 'plan.json'
        planner.write_record(self.plan_file, self.plan)
        self.journal = self.root / 'journal.json'
        self.baseline_file = self.root / 'adb-preflight.json'
        tool, _ = self.fixture.fake_tool('adb')
        planner.write_record(self.baseline_file, planner.preflight(self.plan, 'BOUND', 'adb', adb=tool))

    def validate(self, manifest):
        return planner.validate_manifest(manifest, _super_bytes=9,
            _backup_sizes={name: len((name + '-backup').encode()) for name in planner.PROTECTED})

    def run_update(self, overrides=None):
        tool, self.log = self.fixture.fake_tool('fastboot', overrides)
        return executor.execute(self.fixture.manifest, self.plan_file, self.journal,
                                'BOUND', tool, self.baseline_file, _validator=self.validate)

    def calls(self):
        return [json.loads(line) for line in self.log.read_text().splitlines()]

    def test_success_only_flashes_super_and_stays_in_bootloader(self):
        command = '-s BOUND flash super ' + str(self.root / 'candidate.img')
        record = self.run_update({command: ['', 'Sending super OKAY\nWriting super OKAY\n']})
        self.assertEqual(record['status'], 'FLASH_RETURNED_SUCCESS_READBACK_REQUIRED')
        self.assertFalse(record['readback_verified'])
        writes = [c for c in self.calls() if 'getvar' not in c and c != ['devices']]
        self.assertEqual(writes, [['-s', 'BOUND', 'flash', 'super', str(self.root / 'candidate.img')]])
        self.assertEqual(self.journal.stat().st_mode & 0o777, 0o600)
        self.assertNotIn('BOUND', self.journal.read_text())
        self.assertFalse(record['automatic_reboot'])

    def test_unbound_or_stale_adb_receipt_blocks_all_fastboot_commands(self):
        baseline = json.loads(self.baseline_file.read_text())
        for key, value in [('plan_sha256', '0' * 64),
                           ('device_identity_sha256', '0' * 64),
                           ('rollback_super_hash_matches', False),
                           ('immutable_backup_hashes_match', False),
                           ('schema_version', 1),
                           ('writable_partition_observations', {}),
                           ('checked_utc', '2000-01-01T00:00:00+00:00')]:
            with self.subTest(key=key):
                changed = dict(baseline)
                changed[key] = value
                self.baseline_file.write_text(json.dumps(changed))
                with self.assertRaises(planner.ValidationError):
                    self.run_update()
                self.assertFalse(self.log.exists())
                self.assertFalse(self.journal.exists())

    def test_changed_plan_rejected_before_any_tool_command(self):
        self.plan['proposed_writes'] = ['boot']
        self.plan_file.write_text(json.dumps(self.plan))
        with self.assertRaisesRegex(planner.ValidationError, 'Offline plan differs'):
            self.run_update()
        self.assertFalse(self.log.exists())
        self.assertFalse(self.journal.exists())

    def test_changed_candidate_rejected_before_any_tool_command(self):
        (self.root / 'candidate.img').write_bytes(b'bad-super')
        with self.assertRaisesRegex(planner.ValidationError, 'SHA256 differs'):
            self.run_update()
        self.assertFalse(self.log.exists())

    def test_preflight_failure_never_flashes(self):
        with self.assertRaisesRegex(planner.ValidationError, 'locked'):
            self.run_update({'-s BOUND getvar unlocked': ['', 'unlocked: no\n']})
        self.assertTrue(all(c == ['devices'] or c[2] == 'getvar' for c in self.calls()))
        self.assertEqual(json.loads(self.journal.read_text())['status'], 'STOPPED_BEFORE_FLASH')

    def test_flash_failure_never_reboots_or_attempts_rollback(self):
        # No flash response exists in the fake tool, so flash exits with failure.
        with self.assertRaisesRegex(planner.ValidationError, 'flash failed'):
            self.run_update()
        calls = self.calls()
        self.assertEqual(calls[-1][2:4], ['flash', 'super'])
        self.assertEqual(sum('flash' in c for c in calls), 1)
        self.assertFalse(any('reboot' in c or 'erase' in c for c in calls))
        record = json.loads(self.journal.read_text())
        self.assertEqual(record['status'], 'FLASH_FAILED_STATE_UNKNOWN')
        self.assertFalse(record['rollback_attempted'])

    def test_failure_text_with_zero_exit_is_not_success(self):
        command = '-s BOUND flash super ' + str(self.root / 'candidate.img')
        with self.assertRaisesRegex(planner.ValidationError, 'flash failed'):
            self.run_update({command: ['', 'FAILED (remote: write failed)\n']})
        self.assertEqual(json.loads(self.journal.read_text())['status'], 'FLASH_FAILED_STATE_UNKNOWN')

    def test_changed_writable_partition_does_not_block_super_update(self):
        baseline = json.loads(self.baseline_file.read_text())
        for observation in baseline['writable_partition_observations'].values():
            observation.update(live_sha256='0' * 64, raw_hash_matches_backup=False)
        self.baseline_file.write_text(json.dumps(baseline))
        command = '-s BOUND flash super ' + str(self.root / 'candidate.img')
        record = self.run_update({command: ['', 'Writing super OKAY\n']})
        self.assertEqual(record['status'], 'FLASH_RETURNED_SUCCESS_READBACK_REQUIRED')

    def test_false_writable_hash_claim_blocks_all_fastboot_commands(self):
        baseline = json.loads(self.baseline_file.read_text())
        baseline['writable_partition_observations']['nvdata']['live_sha256'] = '0' * 64
        self.baseline_file.write_text(json.dumps(baseline))
        with self.assertRaisesRegex(planner.ValidationError, 'observation differs'):
            self.run_update()
        self.assertFalse(self.log.exists())

    def test_atomic_journal_replace_failure_preserves_previous_record(self):
        previous = {'status': 'FLASH_IN_PROGRESS_STATE_UNKNOWN'}
        planner.write_record(self.journal, previous)
        before = self.journal.read_bytes()
        with patch.object(executor.os, 'replace', side_effect=OSError('simulated failed replace')):
            with self.assertRaises(OSError):
                executor.save_journal(self.journal, {'status': 'FLASH_RETURNED_SUCCESS_READBACK_REQUIRED'})
        self.assertEqual(self.journal.read_bytes(), before)
        self.assertEqual(list(self.root.glob('.journal.json.*')), [])

    def test_atomic_journal_sync_failure_preserves_previous_record(self):
        planner.write_record(self.journal, {'status': 'VALIDATED_NOT_FLASHED'})
        before = self.journal.read_bytes()
        with patch.object(executor.os, 'fsync', side_effect=OSError('simulated failed sync')):
            with self.assertRaises(OSError):
                executor.save_journal(self.journal, {'status': 'FLASH_IN_PROGRESS_STATE_UNKNOWN'})
        self.assertEqual(self.journal.read_bytes(), before)
        self.assertEqual(list(self.root.glob('.journal.json.*')), [])

    def test_existing_journal_blocks_all_device_commands(self):
        self.journal.write_text('keep')
        with self.assertRaisesRegex(planner.ValidationError, 'new file'):
            self.run_update()
        self.assertFalse(self.log.exists())
        self.assertEqual(self.journal.read_text(), 'keep')


if __name__ == '__main__':
    unittest.main()
