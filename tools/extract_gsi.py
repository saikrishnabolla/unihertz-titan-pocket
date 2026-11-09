#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Extract only the pinned system.img from a downloaded Google GSI ZIP."""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import stat
import zipfile

ROOT = Path(__file__).resolve().parents[1]
IMAGES = {
    'google-gsi': dict(bytes=2072014848, sha256='e5db44e3365f9e542ee3f6d4caf88ece554a460e2987086b8bf21f6c440a25ec'),
    'google13-donor': dict(bytes=1899503616, sha256='9598540f142962bbd0ce3ea623b60b5dfdd842ebcc2523fd93c95d7ed1e42ca6'),
}


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


def digest(stream):
    value = hashlib.sha256()
    while raw := stream.read(4 * 1024**2):
        value.update(raw)
    return value.hexdigest()


def system_member(archive, expected_bytes):
    names = set()
    target = None
    for member in archive.infolist():
        name = member.filename
        path = PurePosixPath(name)
        if (not name or '\\' in name or '\x00' in name or path.is_absolute()
                or '..' in path.parts or str(path) != name.rstrip('/')
                or name in names):
            raise ValueError('Malformed or duplicate ZIP member path')
        names.add(name)
        mode = member.external_attr >> 16
        if stat.S_ISLNK(mode):
            raise ValueError('Symlink ZIP members are rejected')
        if path.name == 'system.img':
            if name != 'system.img' or target is not None:
                raise ValueError('Expected one root system.img member')
            if member.is_dir() or stat.S_IFMT(mode) not in (0, stat.S_IFREG):
                raise ValueError('system.img must be a regular ZIP member')
            if member.flag_bits & 1 or member.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
                raise ValueError('Unsupported system.img ZIP encoding')
            if member.file_size != expected_bytes:
                raise ValueError('system.img member size differs')
            target = member
    if target is None:
        raise ValueError('Missing system.img member')
    return target


def extract(kind, source, output):
    if kind not in IMAGES:
        raise ValueError('Unsupported GSI source name')
    pin = IMAGES[kind]
    entries = json.loads((ROOT / 'release/sources.json').read_text())['sources']
    archive_pin = entries[kind]
    source, output = safe_path(source), safe_path(output)
    info = source.lstat()
    if not stat.S_ISREG(info.st_mode):
        raise ValueError('ZIP source must be a regular file')
    if output.exists():
        raise ValueError('Output already exists')
    with source.open('rb') as stream:
        if info.st_size != archive_pin['bytes'] or digest(stream) != archive_pin['sha256']:
            raise ValueError('GSI ZIP size or SHA-256 differs')
        stream.seek(0)
        with zipfile.ZipFile(stream) as archive:
            member = system_member(archive, pin['bytes'])
            output.mkdir(mode=0o700, exist_ok=False)
            value, count = hashlib.sha256(), 0
            with archive.open(member) as inp, (output / 'system.img').open('xb') as dst:
                while raw := inp.read(4 * 1024**2):
                    count += len(raw)
                    if count > pin['bytes']:
                        raise ValueError('system.img exceeds its pinned size')
                    value.update(raw)
                    dst.write(raw)
            if count != pin['bytes'] or value.hexdigest() != pin['sha256']:
                raise ValueError('Extracted system.img size or SHA-256 differs')
        if identity(source.lstat()) != identity(info) or source.is_symlink():
            raise ValueError('ZIP source changed during extraction')
    report = dict(source_name=kind, archive_sha256=archive_pin['sha256'],
                  archive_bytes=archive_pin['bytes'], member='system.img',
                  system_sha256=value.hexdigest(), system_bytes=count,
                  extracted_members=['system.img'], device_actions=False)
    with (output / 'report.json').open('x') as stream:
        json.dump(report, stream, indent=2)
        stream.write('\n')
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--name', required=True, choices=sorted(IMAGES))
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(extract(args.name, args.source, args.output), indent=2))
    except (OSError, ValueError, zipfile.BadZipFile, RuntimeError) as error:
        parser.exit(1, str(error) + '\n')
