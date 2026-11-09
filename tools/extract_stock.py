#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Extract pinned stock SYSTEM/VENDOR from a local raw or gzip Titan SUPER backup."""
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import struct
import tempfile
import zlib

SUPER_BYTES = 4831838208
POLICY = {
    'source_sha256': '0f1c3a657f42e121c299a44fc39c00d4a5290242191a8a875287ad566d674ab4',
    'super_bytes': SUPER_BYTES, 'metadata_max_size': 65536, 'metadata_slots': 2,
    'metadata_sha256': '6b570b7c4c68a7198bfadbdaefbc7da5b84da60b59963f57b47df01287289a34',
    'partitions': {
        'product': {'offset': 2048 * 512, 'bytes': 1842053120},
        'vendor': {'offset': 3600384 * 512, 'bytes': 452378624,
                   'sha256': 'd991ee39bb233c7f717d9007b1acf9f83c41b3db3e8af188a9c78d4f27b1408f'},
        'system': {'offset': 4485120 * 512, 'bytes': 1790775296,
                   'sha256': '174708e0b8f566267717f512fc6d521bfd0ca9db106b29d19bb1b480edb33339'},
    },
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def safe_path(path):
    path = Path(path).absolute()
    require('..' not in path.parts, 'Traversal paths are rejected')
    for parent in [*reversed(path.parents), path]:
        require(not parent.is_symlink(), 'Symlink paths are rejected')
    return path


def identity(info):
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns


def exact_at(stream, offset, size):
    require(offset >= 0 and size >= 0, 'Negative image range')
    stream.seek(offset)
    data = stream.read(size)
    require(len(data) == size, 'Truncated SUPER metadata')
    return data


def checksum(data, start, end):
    require(hashlib.sha256(data[:start] + b'\0' * (end - start) + data[end:]).digest()
            == data[start:end], 'Metadata checksum differs')


def cstring(raw):
    name, separator, tail = raw.partition(b'\0')
    require(separator and not any(tail), 'Malformed metadata name')
    return name.decode('ascii')


def metadata(stream, policy):
    geometries = [exact_at(stream, offset, 52) for offset in (4096, 8192)]
    require(geometries[0] == geometries[1], 'Geometry copies differ')
    geometry = geometries[0]
    magic, size = struct.unpack_from('<2I', geometry)
    require(magic == 0x616C4467 and size == 52, 'Unsupported liblp geometry')
    checksum(geometry, 8, 40)
    maximum, slots, block = struct.unpack_from('<3I', geometry, 40)
    require(maximum == policy['metadata_max_size'] and slots == policy['metadata_slots']
            and block == 4096, 'Stock metadata geometry differs')
    require(128 <= maximum <= 1024 * 1024 and 1 <= slots <= 3,
            'Metadata allocation outside bounds')
    copies = []
    for copy in range(2):
        for slot in range(slots):
            offset = 12288 + (copy * slots + slot) * maximum
            require(offset + maximum <= policy['super_bytes'], 'Metadata outside SUPER')
            header = exact_at(stream, offset, 128)
            magic, major, minor, size = struct.unpack_from('<I2HI', header)
            require((magic, major, minor, size) == (0x414C5030, 10, 0, 128),
                    'Unsupported liblp header')
            checksum(header, 12, 44)
            table_size = struct.unpack_from('<I', header, 44)[0]
            require(size + table_size <= maximum, 'Metadata tables exceed allocation')
            tables = exact_at(stream, offset + size, table_size)
            require(hashlib.sha256(tables).digest() == header[48:80], 'Table checksum differs')
            copies.append(header + tables)
    require(all(value == copies[0] for value in copies), 'Metadata copies differ')
    header, tables = copies[0][:128], copies[0][128:]
    ranges = []

    def table(at, expected):
        offset, count, width = struct.unpack_from('<3I', header, at)
        end = offset + count * width
        require(width == expected and count > 0 and end <= len(tables), 'Invalid metadata table bounds')
        ranges.append((offset, end))
        return [tables[offset + i * width:offset + (i + 1) * width] for i in range(count)]

    partitions = table(80, 52)
    extents = [struct.unpack('<QIQI', row) for row in table(92, 24)]
    groups = table(104, 48)
    devices = table(116, 64)
    ordered = sorted(ranges)
    require(ordered[0][0] == 0 and ordered[-1][1] == len(tables)
            and all(left[1] == right[0] for left, right in zip(ordered, ordered[1:])),
            'Overlapping or incomplete metadata tables')
    require(len(devices) == 1, 'Expected one SUPER block device')
    first_sector, alignment, alignment_offset, size, name, flags = struct.unpack('<QIIQ36sI', devices[0])
    require(size == policy['super_bytes'] and cstring(name) == 'super' and flags == 0
            and alignment == 1048576 and alignment_offset == 0
            and first_sector * 512 >= 12288 + maximum * slots * 2,
            'Unsupported stock block device')
    require(len(groups) == 2, 'Stock partition groups differ')
    for row in groups:
        group_name, flags, limit = struct.unpack('<36sIQ', row)
        require(cstring(group_name) in ('default', 'main') and flags == 0 and limit <= size,
                'Unsupported partition group')
    names, used_extents, physical = set(), set(), []
    for row in partitions:
        name, attributes, first, count, group = struct.unpack('<36s4I', row)
        name = cstring(name)
        require(name in policy['partitions'] and name not in names, 'Unexpected or duplicate partition')
        names.add(name)
        require(attributes == 1 and group == 1 and count == 1 and first < len(extents)
                and first not in used_extents, 'Unsupported partition layout')
        used_extents.add(first)
        sectors, kind, target, source = extents[first]
        offset, length = target * 512, sectors * 512
        require(kind == 0 and source == 0 and sectors > 0 and target >= first_sector
                and offset + length <= size, 'Invalid stock extent')
        expected = policy['partitions'][name]
        require(offset == expected['offset'] and length == expected['bytes'], 'Stock extent differs')
        physical.append((offset, offset + length))
    require(names == set(policy['partitions']) and len(used_extents) == len(extents),
            'Incomplete stock partition layout')
    physical.sort()
    require(all(a[1] <= b[0] for a, b in zip(physical, physical[1:])), 'Overlapping partition extents')
    require(hashlib.sha256(copies[0]).hexdigest() == policy['metadata_sha256'],
            'Stock metadata pin differs')


def extract(source, output, *, _policy=None):
    policy = POLICY if _policy is None else _policy
    source, output = safe_path(source), safe_path(output)
    require(output.parent.is_dir() and not output.exists(), 'Output must be a new directory')
    fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    staging = None
    created_output = False
    published = []
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode), 'Source must be a regular file')
        with os.fdopen(fd, 'rb', closefd=False) as raw:
            prefix = raw.read(4)
            raw.seek(0)
            require(prefix != b'\x3a\xff\x26\xed', 'Supply a raw SUPER backup, not an Android sparse image')
            compressed = prefix[:2] == b'\x1f\x8b'
            stream = gzip.GzipFile(fileobj=raw) if compressed else raw
            try:
                metadata(stream, policy)
                stream.seek(0)
                staging = Path(tempfile.mkdtemp(prefix='.stock-extract-', dir=output.parent))
                hashes = {name: hashlib.sha256() for name in ('system', 'vendor')}
                counts = dict.fromkeys(hashes, 0)
                streams = {name: (staging / (name + '.img')).open('xb') for name in hashes}
                source_hash = hashlib.sha256()
                position = 0
                try:
                    while chunk := stream.read(min(4 * 1024**2, policy['super_bytes'] - position + 1)):
                        require(position + len(chunk) <= policy['super_bytes'], 'SUPER exceeds pinned byte count')
                        source_hash.update(chunk)
                        for name, dest in streams.items():
                            spec = policy['partitions'][name]
                            start = max(position, spec['offset'])
                            end = min(position + len(chunk), spec['offset'] + spec['bytes'])
                            if end > start:
                                payload = chunk[start-position:end-position]
                                dest.write(payload)
                                hashes[name].update(payload)
                                counts[name] += len(payload)
                        position += len(chunk)
                    require(position == policy['super_bytes'], 'Truncated SUPER image')
                    for name, dest in streams.items():
                        require(counts[name] == policy['partitions'][name]['bytes']
                                and hashes[name].hexdigest() == policy['partitions'][name]['sha256'],
                                'Extracted stock partition hash differs')
                        dest.flush()
                        os.fsync(dest.fileno())
                    require(source_hash.hexdigest() == policy['source_sha256'], 'Stock SUPER hash differs')
                finally:
                    for dest in streams.values():
                        dest.close()
            finally:
                if stream is not raw:
                    stream.close()
        require(identity(before) == identity(os.fstat(fd)) == identity(source.stat(follow_symlinks=False)),
                'Source changed during extraction')
        report = {'source_bytes': position, 'source_sha256': source_hash.hexdigest(),
                  'source_compression': 'gzip' if compressed else 'raw',
                  'partitions': {name: {'bytes': counts[name], 'sha256': hashes[name].hexdigest()}
                                 for name in hashes}, 'device_actions': False}
        (staging / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
        # mkdir refuses existing files, directories and symlinks; hard links never overwrite.
        safe_path(output)
        output.mkdir(mode=0o700)
        created_output = True
        for path in staging.iterdir():
            destination = output / path.name
            os.link(path, destination)
            published.append(destination)
        return report
    except BaseException:
        for path in published:
            path.unlink()
        if created_output:
            output.rmdir()
        raise
    finally:
        os.close(fd)
        if staging is not None:
            shutil.rmtree(staging)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--super', dest='source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        report = extract(args.source, args.output)
    except (OSError, ValueError, EOFError, struct.error, zlib.error) as error:
        parser.exit(1, 'Stock extraction stopped: ' + str(error) + '\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
