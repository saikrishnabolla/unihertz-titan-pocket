#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Assemble signed, caller-pinned SYSTEM and VENDOR using the tested Titan layout."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'hardware/base-apps/super_helpers'))
import assemble_super as assembler
import build_metadata as metadata


def payload(name, path, expected, size, offset):
    if not re.fullmatch('[0-9a-f]{64}', expected):
        raise ValueError('Expected a SHA256 pin for ' + name)
    path = path.absolute()
    fd = assembler._open_regular(path)
    try:
        before = assembler._identity(fd)
        if before[2] != size:
            raise ValueError('Partition size differs: ' + name)
        with os.fdopen(os.dup(fd), 'rb') as stream:
            if hashlib.file_digest(stream, 'sha256').hexdigest() != expected:
                raise ValueError('Partition hash differs: ' + name)
        assembler._verify_source(path, fd, before)
    finally:
        os.close(fd)
    return assembler.Payload(name, path, offset, size, expected)


def assemble(args):
    inputs = [payload('system', args.system, args.system_sha256, 3288334336, 1048576),
              payload('vendor', args.vendor, args.vendor_sha256, 536870912, 3289382912)]
    # avbtool opens a hashtree's partition name beside its input image.
    with tempfile.TemporaryDirectory(prefix='titan-assembly-avb-') as directory:
        directory = Path(directory)
        for item, key in zip(inputs, [args.system_public_key, args.vendor_public_key]):
            if key.is_symlink() or not key.is_file():
                raise ValueError('Supply a regular public key file for ' + item.name)
            link = directory / (item.name + '.img')
            link.symlink_to(item.path)
            subprocess.run([sys.executable, str(args.avbtool), 'verify_image', '--image',
                            str(link), '--key', str(key.absolute())], check=True, timeout=600)
    prefix = metadata.build_prefix()
    return assembler._assemble(prefix, inputs, metadata.SUPER_SIZE, args.output.absolute(),
                               assembler.DEFAULT_RESERVE, metadata.validate_minimal)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('system', 'vendor', 'system-public-key', 'vendor-public-key', 'avbtool', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    for name in ('system-sha256', 'vendor-sha256'):
        parser.add_argument('--' + name, required=True)
    args = parser.parse_args()
    if args.avbtool.is_symlink() or not args.avbtool.is_file():
        parser.error('Supply a regular avbtool.py file')
    if hashlib.sha256(args.avbtool.read_bytes()).hexdigest() != '69783733ce5e198317b02a5567cc356e898c891de872f58a963e9d5c082973c6':
        parser.error('AVB tool differs from the pinned source')
    report = assemble(args)
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, assembler.AssemblyError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        raise SystemExit(str(error))
