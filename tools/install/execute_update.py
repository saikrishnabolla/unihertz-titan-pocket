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
import tempfile
from datetime import datetime, timezone

import plan_install as planner


def timestamp():
    return datetime.now(timezone.utc).isoformat()


def save_journal(path, record):
    """Keep the previous complete record until its replacement is durable."""
    info = path.stat(follow_symlinks=False)
    planner.require(stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o600,
                    'Journal permissions changed')
    fd, temporary = tempfile.mkstemp(prefix='.' + path.name + '.', dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as stream:
            json.dump(record, stream, indent=2)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        planner.require(planner.identity(path.stat(follow_symlinks=False)) == planner.identity(info),
                        'Journal changed during save')
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


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
    planner.require(baseline.get('schema_version') == 2
                    and baseline.get('status') == 'READ-ONLY PREFLIGHT PASSED; NOT INSTALLED'
                    and baseline.get('transport') == 'adb'
                    and baseline.get('plan_sha256') == planner.plan_fingerprint(verified)
                    and baseline.get('device_identity_sha256') == hashlib.sha256(serial.encode()).hexdigest()
                    and baseline.get('build') == planner.BUILD and baseline.get('model') == planner.MODEL
                    and baseline.get('expected_partitions') == verified['expected_partitions']
                    and baseline.get('immutable_backup_hashes_match') is True
                    and baseline.get('rollback_super_hash_matches') is True,
                    'Rooted ADB preflight does not match this plan, baseline and device')
    observations = baseline.get('writable_partition_observations')
    planner.keys(observations, planner.WRITABLE_VENDOR, 'writable partition observations')
    for name, observation in observations.items():
        planner.keys(observation, ('backup_sha256', 'live_sha256', 'raw_hash_matches_backup'),
                     'writable partition observation')
        live = planner.checksum(observation['live_sha256'])
        expected = verified['protected_backups'][name]['sha256']
        planner.require(observation['backup_sha256'] == expected
                        and observation['raw_hash_matches_backup'] is (live == expected),
                        'Writable partition observation differs from its verified backup')
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
        save_journal(journal, record)
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
