#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Extract only SYSTEM from the pinned optional Google GMS GSI ZIP."""
import argparse
import hashlib
import json
from pathlib import Path
import stat
import sys
import zipfile

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1] / 'tools'))
from extract_vndk import safe_path, identity, digest
from extract_gsi import system_member
SOURCE_BYTES = 3953213440
SOURCE_SHA256 = '8b525e2bff18a54b277c4b9a950a0ee667e50ad2e91bcc4c1daa6f081402407e'

ARCHIVE_BYTES = 2076347889
ARCHIVE_SHA256 = 'd55d64aaebc71b2a895d792c152cfc408841bfde38565b082f495b850a2ae3e1'


def extract(source, output):
    source, output = safe_path(source), safe_path(output)
    info = source.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_size != ARCHIVE_BYTES or digest(source) != ARCHIVE_SHA256:
        raise ValueError('Google GMS ZIP differs from the pinned archive')
    if output.exists():
        raise ValueError('Output already exists')
    with zipfile.ZipFile(source) as archive:
        member = system_member(archive, SOURCE_BYTES)
        output.mkdir(mode=0o700, exist_ok=False)
        value, count = hashlib.sha256(), 0
        with archive.open(member) as inp, (output / 'system.img').open('xb') as dst:
            while raw := inp.read(4 * 1024**2):
                count += len(raw)
                if count > SOURCE_BYTES:
                    raise ValueError('GMS SYSTEM exceeds its pinned size')
                value.update(raw)
                dst.write(raw)
    if count != SOURCE_BYTES or value.hexdigest() != SOURCE_SHA256:
        raise ValueError('Extracted GMS SYSTEM size or hash differs')
    if source.is_symlink() or identity(source.lstat()) != identity(info):
        raise ValueError('Google GMS ZIP changed during extraction')
    with (output / 'report.json').open('x') as stream:
        json.dump(dict(archive_sha256=ARCHIVE_SHA256, archive_bytes=ARCHIVE_BYTES,
                       system_sha256=SOURCE_SHA256, system_bytes=SOURCE_BYTES,
                       extracted_members=['system.img'], device_actions=False), stream, indent=2)
        stream.write('\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        extract(args.source, args.output)
    except (OSError, ValueError, zipfile.BadZipFile, RuntimeError) as error:
        parser.exit(1, str(error) + '\n')
