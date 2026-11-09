#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Fetch and unpack the pinned aapt2 and AVB tools; never execute downloads."""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import platform
import zipfile

from fetch_inputs import ROOT, fetch

AVB_SHA = '69783733ce5e198317b02a5567cc356e898c891de872f58a963e9d5c082973c6'


def unpack(aapt_archive, avb_source, output):
    output = Path(output)
    if output.exists() or output.is_symlink():
        raise ValueError('Use a fresh output directory')
    # Read only the two named members, never archive paths supplied by a ZIP.
    with zipfile.ZipFile(aapt_archive) as archive:
        for name in ('aapt2', 'NOTICE'):
            matches = [entry for entry in archive.infolist() if entry.filename == name]
            if len(matches) != 1 or matches[0].file_size > 32 * 1024**2:
                raise ValueError('Unexpected aapt2 archive')
        executable = archive.read('aapt2')
        notice = archive.read('NOTICE')
    avb = base64.b64decode(Path(avb_source).read_bytes(), validate=True)
    if hashlib.sha256(avb).hexdigest() != AVB_SHA:
        raise ValueError('Decoded AVB source differs')
    output.mkdir(mode=0o700)
    for name, data in [('aapt2', executable), ('NOTICE.aapt2', notice), ('avbtool.py', avb)]:
        path = output / name
        with path.open('xb') as stream:
            stream.write(data)
        path.chmod(0o700 if name == 'aapt2' else 0o600)
    return output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cache', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    host = {'Darwin': 'osx', 'Linux': 'linux'}.get(platform.system())
    machine = platform.machine().lower()
    if host is None or (host == 'linux' and machine not in ('x86_64', 'amd64')):
        parser.error('The pinned aapt2 supports macOS or x86_64 Linux; supply your own aapt2 on other hosts')
    manifest = json.loads((ROOT / 'release/sources.json').read_text())['sources']
    aapt = fetch(manifest['aapt2-' + host], args.cache)
    avb = fetch(manifest['avbtool-source'], args.cache)
    out = unpack(aapt, avb, args.output)
    print('Prepared aapt2 and avbtool.py in ' + str(out))
    print('Install debugfs, e2fsck and OpenSSL separately; see docs/BUILDING.md.')


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, zipfile.BadZipFile) as error:
        raise SystemExit(str(error))
