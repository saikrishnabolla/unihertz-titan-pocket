#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Write only SUPER after revalidating an offline plan and live bootloader checks."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
from datetime import datetime, timezone

import plan_install as planner


def timestamp():
    return datetime.now(timezone.utc).isoformat()


def execute(manifest, plan_file, journal, serial, fastboot, adb_preflight, *, _validator=None):
    # Tests substitute only the manifest validator's partition sizes; the CLI cannot.
    validator = planner.validate_manifest if _validator is None else _validator
    verified = validator(manifest)
    _, saved = planner.load_manifest(plan_file)
    planner.require(saved == verified, 'Offline plan differs from reverified inputs')
    planner.require(verified['mode'] == 'update' and verified['proposed_writes'] == ['super']
                    and verified['proposed_erases'] == [], 'Only SUPER-only update execution is supported')
    fastboot = planner.binary_path(fastboot)
    planner.require(isinstance(serial, str) and planner.re.fullmatch(r'[A-Za-z0-9._:-]{1,128}', serial),
                    'Invalid explicit serial')
    _, baseline = planner.load_manifest(adb_preflight)
    planner.require(baseline.get('status') == 'READ-ONLY PREFLIGHT PASSED; NOT INSTALLED'
                    and baseline.get('transport') == 'adb'
                    and baseline.get('plan_sha256') == planner.plan_fingerprint(verified)
                    and baseline.get('device_identity_sha256') == hashlib.sha256(serial.encode()).hexdigest()
                    and baseline.get('build') == planner.BUILD and baseline.get('model') == planner.MODEL
                    and baseline.get('expected_partitions') == verified['expected_partitions']
                    and baseline.get('protected_backup_hashes_match') is True
                    and baseline.get('rollback_super_hash_matches') is True,
                    'Rooted ADB preflight does not match this plan, baseline and device')
    age = (datetime.now(timezone.utc) - datetime.fromisoformat(baseline['checked_utc'])).total_seconds()
    planner.require(0 <= age <= 3600, 'Rooted ADB preflight must be less than one hour old')
    record = {'schema_version': 1, 'status': 'VALIDATED_NOT_FLASHED', 'started_utc': timestamp(),
              'device_identity_sha256': hashlib.sha256(serial.encode()).hexdigest(),
              'plan_sha256': hashlib.sha256(Path(plan_file).read_bytes()).hexdigest(),
              'adb_preflight_plan_sha256': baseline['plan_sha256'],
              'candidate_sha256': verified['super']['sha256'], 'partition': 'super',
              'flash_attempted': False, 'readback_verified': False,
              'automatic_reboot': False, 'rollback_attempted': False}
    journal = Path(journal)
    planner.write_record(journal, record)
    def save():
        fd = os.open(journal, os.O_WRONLY | os.O_NOFOLLOW)
        try:
            info = os.fstat(fd)
            planner.require(stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o600,
                            'Journal permissions changed')
            with os.fdopen(fd, 'w', closefd=False) as stream:
                json.dump(record, stream, indent=2)
                stream.write('\n')
                stream.flush()
                os.ftruncate(fd, stream.tell())
                os.fsync(fd)
        finally:
            os.close(fd)
    try:
        record['preflight'] = planner.preflight(verified, serial, 'fastboot', fastboot=fastboot)
        # Rehash again after device checks, immediately before the write.
        candidate = planner.verify_artifact(Path(manifest).absolute().parent, verified['super'])
        image = planner.relative_file(Path(manifest).absolute().parent, candidate['path'])
        before = planner.identity(image.stat(follow_symlinks=False))
        record.update(status='FLASH_IN_PROGRESS_STATE_UNKNOWN', flash_attempted=True, flash_started_utc=timestamp())
        save()
        result = subprocess.run([fastboot, '-s', serial, 'flash', 'super', str(image)],
                                capture_output=True, timeout=1800)
        planner.require(planner.identity(image.stat(follow_symlinks=False)) == before,
                        'Candidate changed during flash; device state is unknown')
        planner.require(result.returncode == 0 and b'FAILED' not in result.stdout + result.stderr
                        and b'ERROR' not in result.stdout + result.stderr,
                        'SUPER flash failed; device state is unknown')
        record.update(status='FLASH_RETURNED_SUCCESS_READBACK_REQUIRED', finished_utc=timestamp())
        save()
        return record
    except BaseException:
        record.update(status='FLASH_FAILED_STATE_UNKNOWN' if record['flash_attempted'] else 'STOPPED_BEFORE_FLASH',
                      stopped_utc=timestamp())
        save()
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--plan', type=Path, required=True)
    parser.add_argument('--journal', type=Path, required=True)
    parser.add_argument('--serial', required=True)
    parser.add_argument('--adb-preflight', type=Path, required=True)
    parser.add_argument('--fastboot', required=True, help='Absolute path to fastboot')
    args = parser.parse_args()
    try:
        execute(args.manifest, args.plan, args.journal, args.serial, args.fastboot, args.adb_preflight)
    except (planner.ValidationError, OSError, ValueError, TypeError, KeyError, EOFError,
            subprocess.TimeoutExpired) as error:
        print('Update stopped: ' + (str(error) if isinstance(error, planner.ValidationError)
                                    else type(error).__name__) + '. No automatic rollback or reboot.', file=sys.stderr)
        return 1
    print('SUPER flash returned success. No reboot occurred; Android readback verification is still required.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
