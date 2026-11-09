#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Extract the unmodified VNDK30 APEX from the pinned raw Google13 GSI."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import stat
import subprocess

SOURCE_BYTES = 1899503616
SOURCE_SHA256 = '9598540f142962bbd0ce3ea623b60b5dfdd842ebcc2523fd93c95d7ed1e42ca6'
APEX_SHA256 = 'ab5bbcbcfd254195bbb4e8773ea5ae85b09153e0ed06506e2f8ed0213e6e4f87'
INSIDE = '/system/system_ext/apex/com.android.vndk.v30.apex'
FILENAME = 'com.android.vndk.v30.apex'


def safe_path(path):
    path = Path(path).absolute()
    if '..' in path.parts:
        raise ValueError('Traversal paths are rejected')
    for component in [*reversed(path.parents), path]:
        if component.is_symlink():
            raise ValueError('Symlink paths are rejected')
    return path


def identity(info):
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns


def digest(path):
    value = hashlib.sha256()
    with path.open('rb') as stream:
        while raw := stream.read(4 * 1024**2):
            value.update(raw)
    return value.hexdigest()


def validate_response(result):
    if result.returncode:
        raise ValueError('debugfs extraction failed')
    try:
        stderr = result.stderr.decode('ascii')
    except UnicodeDecodeError as error:
        raise ValueError('Malformed debugfs response') from error
    if not re.fullmatch(r'debugfs [0-9]+(?:\.[0-9]+)+(?: \([^\r\n()]+\))?\n?', stderr):
        raise ValueError('Malformed debugfs response')
    if hashlib.sha256(result.stdout).hexdigest() != APEX_SHA256:
        raise ValueError('Extracted VNDK30 APEX hash differs')
    return result.stdout


def extract(source, output, debugfs):
    source, output = safe_path(source), safe_path(output)
    info = source.lstat()
    if not stat.S_ISREG(info.st_mode):
        raise ValueError('Source must be a regular file')
    if info.st_size != SOURCE_BYTES or digest(source) != SOURCE_SHA256:
        raise ValueError('Google13 source size or hash differs')
    if output.exists():
        raise ValueError('Output already exists')
    result = subprocess.run([str(debugfs), '-R', 'cat ' + INSIDE, str(source)],
                            capture_output=True, timeout=180)
    raw = validate_response(result)
    if source.is_symlink() or identity(source.lstat()) != identity(info):
        raise ValueError('Source changed during extraction')
    output.mkdir(mode=0o700, exist_ok=False)
    with (output / FILENAME).open('xb') as stream:
        stream.write(raw)
    with (output / 'payloads.json').open('x') as stream:
        json.dump({APEX_SHA256: FILENAME}, stream, indent=2)
        stream.write('\n')
    report = dict(source_sha256=SOURCE_SHA256, source_bytes=SOURCE_BYTES,
                  source_path_in_image=INSIDE, apex_sha256=APEX_SHA256,
                  apex_bytes=len(raw), apex_modified=False, device_actions=False)
    with (output / 'report.json').open('x') as stream:
        json.dump(report, stream, indent=2)
        stream.write('\n')
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ['source', 'output', 'debugfs']:
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(extract(args.source, args.output, args.debugfs), indent=2))
    except (ValueError, OSError, subprocess.TimeoutExpired) as error:
        parser.exit(1, str(error) + '\n')
