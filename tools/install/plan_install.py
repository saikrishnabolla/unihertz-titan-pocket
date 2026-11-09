#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Validate local Titan installation inputs and inspect a bound device read-only.

This tool has no flash, erase, reboot, unlock or restore operation.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import stat
import subprocess
import sys
from datetime import datetime, timezone

SUPER_BYTES = 4831838208
BUILD = 'CP3A.260905.010'
MODEL = 'Titan_pocket'
BOOTLOADER_PRODUCT = 'g66v71c2k_dfl_tee'
EXPECTED_PARTITIONS = ('boot', 'recovery', 'vbmeta')
PROTECTED = EXPECTED_PARTITIONS + ('nvram', 'nvdata', 'proinfo', 'persist',
                                 'protect1', 'protect2', 'tee1', 'tee2', 'lk', 'lk2', 'dtbo')
PARTITION_BYTES = {'boot': 33554432, 'recovery': 33554432, 'vbmeta': 8388608,
                   'nvram': 67108864, 'nvdata': 67108864, 'proinfo': 3145728,
                   'persist': 50331648, 'protect1': 8388608, 'protect2': 11395072,
                   'tee1': 5242880, 'tee2': 12582912, 'lk': 1048576,
                   'lk2': 1048576, 'dtbo': 8388608}
WRITABLE_VENDOR = ('nvdata', 'persist', 'protect1', 'protect2')
IMMUTABLE_PROTECTED = tuple(name for name in PROTECTED if name not in WRITABLE_VENDOR)
HEX = re.compile(r'[0-9a-f]{64}')


class ValidationError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise ValidationError(message)


def no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'Duplicate JSON key')
        result[key] = value
    return result


def keys(value, required, label):
    require(isinstance(value, dict) and set(value) == set(required),
            'Unexpected or missing fields in ' + label)


def checksum(value):
    require(isinstance(value, str) and HEX.fullmatch(value), 'Invalid SHA256')
    return value


def relative_file(base, name):
    require(isinstance(name, str) and name and not any(c in name for c in '\x00\r\n\\'),
            'Invalid input path')
    path = Path(name)
    require(not path.is_absolute() and '..' not in path.parts, 'Input path escapes manifest directory')
    destination = base
    for component in path.parts:
        destination /= component
        require(not destination.is_symlink(), 'Symlink input path rejected')
    require(destination.is_file(), 'Required input file is missing')
    require(destination.resolve().is_relative_to(base.resolve()), 'Input path escapes manifest directory')
    return destination


def identity(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def verify_artifact(base, entry, expected_bytes=None):
    keys(entry, ('path', 'sha256', 'bytes', 'compression'), 'artifact')
    require(type(entry['bytes']) is int and entry['bytes'] > 0, 'Invalid artifact byte count')
    require(entry['compression'] in ('raw', 'gzip'), 'Unsupported artifact compression')
    if expected_bytes is not None:
        require(entry['bytes'] == expected_bytes, 'Artifact partition size differs')
    expected_hash = checksum(entry['sha256'])
    path = relative_file(base, entry['path'])
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode), 'Artifact is not a regular file')
        with os.fdopen(fd, 'rb', closefd=False) as raw:
            source = gzip.GzipFile(fileobj=raw) if entry['compression'] == 'gzip' else raw
            count = 0
            digest = hashlib.sha256()
            try:
                while chunk := source.read(min(4 * 1024**2, entry['bytes'] - count + 1)):
                    count += len(chunk)
                    require(count <= entry['bytes'], 'Artifact expands beyond its expected size')
                    digest.update(chunk)
            finally:
                if source is not raw:
                    source.close()
        require(identity(before) == identity(os.fstat(fd)), 'Artifact changed during verification')
        require(identity(before) == identity(path.stat(follow_symlinks=False)), 'Artifact path changed during verification')
        require(count == entry['bytes'], 'Artifact byte count differs')
        require(digest.hexdigest() == expected_hash, 'Artifact SHA256 differs')
    finally:
        os.close(fd)
    return {'path': entry['path'], 'sha256': expected_hash, 'bytes': entry['bytes'],
            'compression': entry['compression']}


def load_manifest(path):
    path = Path(path).absolute()
    require(not path.is_symlink() and path.is_file(), 'Manifest must be a regular file')
    require(path.stat().st_size <= 1024 * 1024, 'Manifest is too large')
    return path, json.loads(path.read_text(), object_pairs_hook=no_duplicates)


def validate_manifest(path, *, allow_userdata_erase=False, _super_bytes=SUPER_BYTES, _backup_sizes=None):
    """The private size override is for tiny host fixtures; the CLI never exposes it."""
    path, data = load_manifest(path)
    keys(data, ('schema_version', 'model', 'build', 'mode', 'super', 'rollback_super',
                'expected_partitions', 'protected_backups'), 'manifest')
    require(data['schema_version'] == 1 and type(data['schema_version']) is int, 'Unsupported manifest schema')
    require(data['model'] == MODEL and data['build'] == BUILD, 'Unsupported device/build')
    require(data['mode'] in ('update', 'clean'), 'Unsupported installation mode')
    require(data['mode'] != 'clean' or allow_userdata_erase,
            'Clean-install planning requires --allow-userdata-erase')
    expected = data['expected_partitions']
    keys(expected, EXPECTED_PARTITIONS, 'expected_partitions')
    expected = {key: checksum(value) for key, value in expected.items()}
    backups = data['protected_backups']
    keys(backups, PROTECTED, 'protected_backups')
    candidate = verify_artifact(path.parent, data['super'], _super_bytes)
    rollback = verify_artifact(path.parent, data['rollback_super'], _super_bytes)
    require(candidate['compression'] == 'raw', 'Candidate SUPER must be raw')
    require(candidate['path'] != rollback['path'] and candidate['sha256'] != rollback['sha256'],
            'Candidate and rollback must be distinct images')
    backup_sizes = PARTITION_BYTES if _backup_sizes is None else _backup_sizes
    require(set(backup_sizes) == set(PROTECTED), 'Incomplete partition size policy')
    verified = {name: verify_artifact(path.parent, backups[name], backup_sizes[name])
                for name in PROTECTED}
    for name in EXPECTED_PARTITIONS:
        require(verified[name]['sha256'] == expected[name], 'Partition backup does not match expected baseline')
    return {
        'schema_version': 1, 'status': 'OFFLINE INPUTS VERIFIED; NOT APPROVED OR INSTALLED',
        'model': MODEL, 'build': BUILD, 'mode': data['mode'],
        'super': candidate, 'rollback_super': rollback, 'expected_partitions': expected,
        'protected_backups': verified, 'proposed_writes': ['super'],
        'proposed_erases': ['userdata'] if data['mode'] == 'clean' else [],
        'additional_preparation_required': ['verify current boot/recovery/vbmeta baseline',
                                          'verify unlocked physical bootloader and partition sizes',
                                          'verify recovery route and current protected partition backups'],
        'device_contacted': False, 'device_writes': False,
        'flashing_implemented': False,
    }


def binary_path(value):
    path = Path(value)
    require(path.is_absolute() and path.is_file() and os.access(path, os.X_OK),
            'Tool must be an absolute executable file')
    return str(path)


def run_tool(binary, args):
    try:
        result = subprocess.run([binary, *args], capture_output=True, timeout=45)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ValidationError('Read-only device command failed: ' + type(error).__name__) from None
    require(result.returncode == 0, 'Read-only device command returned failure')
    require(len(result.stdout) + len(result.stderr) <= 1024 * 1024, 'Device output exceeded bound')
    return result.stdout.decode(errors='strict'), result.stderr.decode(errors='strict')


def plan_fingerprint(plan):
    return hashlib.sha256(json.dumps(plan, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def preflight(plan, serial, transport, adb=None, fastboot=None, root_helper=None):
    require(isinstance(serial, str) and re.fullmatch(r'[A-Za-z0-9._:-]{1,128}', serial), 'Invalid explicit serial')
    record = {'schema_version': 2, 'status': 'READ-ONLY PREFLIGHT PASSED; NOT INSTALLED',
              'device_identity_sha256': hashlib.sha256(serial.encode()).hexdigest(),
              'transport': transport, 'device_contacted': True, 'device_writes': False,
              'plan_sha256': plan_fingerprint(plan),
              'checked_utc': datetime.now(timezone.utc).isoformat(),
              'flashing_implemented': False}
    if transport == 'adb':
        tool = binary_path(adb)
        stdout, _ = run_tool(tool, ['devices'])
        rows = [line.split() for line in stdout.splitlines() if line.strip() and not line.startswith('List of devices')]
        require(len(rows) == 1 and rows[0] == [serial, 'device'], 'Require exactly one authorized matching ADB device')
        def shell(command):
            out, _ = run_tool(tool, ['-s', serial, 'shell', command])
            return out.strip()
        require(shell('getprop ro.product.vendor.device') == MODEL, 'Device model differs')
        require(shell('getprop ro.board.platform') == 'mt6771', 'Device platform differs')
        require(shell('getprop ro.boot.flash.locked') == '0' and
                shell('getprop ro.boot.vbmeta.device_state') == 'unlocked', 'Bootloader is not confirmed unlocked')
        require(shell('getprop sys.boot_completed') == '1', 'Android has not completed boot')
        if plan['mode'] == 'update':
            require(shell('getprop ro.build.id') == BUILD, 'Update baseline build differs')
            require(shell('getprop ro.gsid.image_running') in ('', '0'), 'DSU guest is active')
        if root_helper is not None:
            require(root_helper == '/system_ext/bin/su', 'Unsupported root helper')
        live_hashes = {name: artifact['sha256'] for name, artifact in plan['protected_backups'].items()}
        live_hashes['super'] = plan['rollback_super']['sha256']
        writable_observations = {}
        for partition, expected in live_hashes.items():
            command = 'sha256sum /dev/block/by-name/' + partition
            if root_helper:
                command = shlex.join([root_helper, '-c', command])
            actual = shell(command).split()
            require(len(actual) == 2 and HEX.fullmatch(actual[0]) and
                    actual[1] == '/dev/block/by-name/' + partition,
                    'Invalid live partition hash response')
            if partition in WRITABLE_VENDOR:
                writable_observations[partition] = {
                    'backup_sha256': expected, 'live_sha256': actual[0],
                    'raw_hash_matches_backup': actual[0] == expected,
                }
            else:
                require(actual[0] == expected, 'Live protected partition does not match baseline')
        record.update(model=MODEL, platform='mt6771', bootloader_unlocked=True,
                      boot_completed=True, immutable_baseline_hashes_match=True,
                      build=BUILD if plan['mode']=='update' else None,
                      expected_partitions=plan['expected_partitions'],
                      immutable_backup_hashes_match=True, rollback_super_hash_matches=True,
                      writable_partition_observations=writable_observations,
                      remaining=['Physical bootloader partition-size checks', 'Manual recovery-route verification'])
    elif transport == 'fastboot':
        tool = binary_path(fastboot)
        stdout, _ = run_tool(tool, ['devices'])
        rows = [line.split() for line in stdout.splitlines() if line.strip()]
        require(len(rows) == 1 and rows[0] == [serial, 'fastboot'], 'Require exactly one matching fastboot device')
        def getvar(name):
            out, err = run_tool(tool, ['-s', serial, 'getvar', name])
            text = out + '\n' + err
            require('FAILED' not in text and 'ERROR' not in text, 'Fastboot variable request failed')
            values = re.findall(r'^(?:\(bootloader\)\s*)?' + re.escape(name) + r':\s*(\S+)\s*$', text, re.M)
            require(len(values) == 1, 'Ambiguous or missing fastboot variable')
            return values[0]
        require(getvar('product') == BOOTLOADER_PRODUCT, 'Bootloader product differs')
        require(getvar('is-userspace') == 'no', 'Physical bootloader is required, not fastbootd')
        require(getvar('unlocked') == 'yes', 'Bootloader is locked')
        require(getvar('slot-count') == '0', 'Unexpected A/B partition scheme')
        require(int(getvar('partition-size:super'), 16) == SUPER_BYTES, 'SUPER partition size differs')
        require(int(getvar('partition-size:userdata'), 16) == 121978716160, 'Userdata partition size differs')
        require(int(getvar('partition-size:boot'), 16) == 33554432, 'BOOT partition size differs')
        require(int(getvar('partition-size:recovery'), 16) == 33554432, 'Recovery partition size differs')
        require(int(getvar('partition-size:vbmeta'), 16) == 8388608, 'Vbmeta partition size differs')
        record.update(bootloader_product=BOOTLOADER_PRODUCT, bootloader_unlocked=True,
                      physical_bootloader=True, partition_sizes_match=True,
                      remaining=['Live boot/recovery/vbmeta hash comparison requires rooted Android',
                                 'Current live SUPER rollback comparison',
                                 'Current calibration-backup comparison', 'Manual recovery-route verification'])
    else:
        raise ValidationError('Unsupported transport')
    return record


def write_record(path, data):
    path = Path(path)
    require(path.parent.is_dir() and not path.exists() and not path.is_symlink(), 'Output must be a new file in an existing directory')
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as stream:
        json.dump(data, stream, indent=2)
        stream.write('\n')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('plan', 'preflight'))
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--allow-userdata-erase', action='store_true',
                        help='Acknowledge data loss in a clean-install plan; this tool never erases')
    parser.add_argument('--serial')
    parser.add_argument('--transport', choices=('adb', 'fastboot'))
    parser.add_argument('--adb')
    parser.add_argument('--fastboot')
    parser.add_argument('--root-helper', choices=('/system_ext/bin/su',))
    args = parser.parse_args(argv)
    try:
        plan = validate_manifest(args.manifest, allow_userdata_erase=args.allow_userdata_erase)
        if args.command == 'plan':
            require(not any((args.serial, args.transport, args.adb, args.fastboot, args.root_helper)),
                    'Offline plan does not accept device options')
            result = plan
        else:
            require(args.serial and args.transport, 'Preflight requires explicit --serial and --transport')
            result = preflight(plan, args.serial, args.transport, args.adb, args.fastboot, args.root_helper)
        write_record(args.output, result)
    except (ValidationError, OSError, ValueError, TypeError, KeyError, EOFError) as error:
        # Do not echo commands, tool output, serials or arbitrary manifest values.
        print('Titan validation stopped: ' + (str(error) if isinstance(error, ValidationError)
                                              else type(error).__name__), file=sys.stderr)
        return 1
    print('Record written. No device writes or installation occurred.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
