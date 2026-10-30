#!/usr/bin/env python3
"""Create an offline diagnostic native derivative. Not an installable APEX.

Only six reviewed minimum-kernel policy branches change. Real feature checks,
kernel/API reporting, verifier failures and attachment failures remain intact.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct

SOURCE_SHA = {
    'netbpfload': '775d705134ac47146a536d31e76af3d439d0e29d48087bc6c64d04c102c4bed6',
    'libnetd_updatable.so': '26f236bcb2ad24a8f34de7372b7859aac3a34a4bbe27d698d413f17086284a40',
}
SITES = {
    'netbpfload': ((0xa538, '29010034', 0xa55c), (0xa570, '2b010036', 0xa594),
                   (0xa5a4, 'ca000036', 0xa5bc), (0xa5cc, '28010036', 0xa5f0)),
    'libnetd_updatable.so': ((0x91d4, '88080036', 0x92e4), (0x92f8, '881c0036', 0x9688)),
}


def executable_offset(data, address):
    if len(data) < 64 or data[:6] != b'\x7fELF\x02\x01' or struct.unpack_from('<H', data, 18)[0] != 183:
        raise ValueError('Expected little-endian ELF64 AArch64')
    start = struct.unpack_from('<Q', data, 32)[0]
    size, count = struct.unpack_from('<HH', data, 54)
    if size != 56 or not count or start + size * count > len(data):
        raise ValueError('Invalid program headers')
    matches = []
    for index in range(count):
        kind, flags, offset, va, _, filesz, _, _ = struct.unpack_from('<IIQQQQQQ', data, start + index * size)
        if kind == 1 and flags & 1 and va <= address and address + 4 <= va + filesz:
            result = offset + address - va
            if result + 4 > len(data):
                raise ValueError('Executable mapping exceeds file')
            matches.append(result)
    if len(matches) != 1:
        raise ValueError('Expected one executable mapping')
    return matches[0]


def patch_native(name, original):
    digest = hashlib.sha256(original).hexdigest()
    if name not in SOURCE_SHA or digest != SOURCE_SHA[name]:
        raise ValueError('Input differs from pinned original')
    result = bytearray(original)
    sites = []
    allowed = set()
    for address, old_hex, target in SITES[name]:
        offset = executable_offset(original, address)
        if offset != address or executable_offset(original, target) != target:
            raise ValueError('Unexpected executable mapping')
        if original[offset:offset + 4] != bytes.fromhex(old_hex):
            raise ValueError('Original instruction mismatch')
        delta = target - address
        if delta % 4 or not -(1 << 27) <= delta < (1 << 27):
            raise ValueError('Unencodable direct branch')
        replacement = struct.pack('<I', 0x14000000 | ((delta // 4) & 0x3ffffff))
        result[offset:offset + 4] = replacement
        allowed.update(range(offset, offset + 4))
        sites.append({'offset': offset, 'va': hex(address), 'target': hex(target),
                      'old_hex': old_hex, 'new_hex': replacement.hex(), 'instruction': 'B'})
    changed = [i for i, (before, after) in enumerate(zip(original, result)) if before != after]
    if len(result) != len(original) or not set(changed) <= allowed:
        raise ValueError('Change outside reviewed instruction windows')
    return bytes(result), {
        'status': 'OFFLINE DIAGNOSTIC ONLY; NOT INSTALL READY', 'name': name,
        'source_sha256': digest, 'result_sha256': hashlib.sha256(result).hexdigest(),
        'sites': sites, 'changed_byte_offsets': changed,
        'all_bytes_outside_reviewed_windows_unchanged': True,
        'limits': ['No APEX packaging or signing', 'No verifier or runtime proof',
                   'Legacy BPF API metadata still needs adaptation', 'No boot authorization'],
    }


def build(source, name, output):
    if source.is_symlink() or not source.is_file():
        raise ValueError('Source must be a regular, non-symlink file')
    original = source.read_bytes()
    derivative, report = patch_native(name, original)
    output.mkdir(mode=0o700, exist_ok=False)
    path = output / name
    with path.open('xb') as stream:
        stream.write(derivative)
    if path.read_bytes() != derivative or source.read_bytes() != original:
        raise ValueError('Readback or source preservation mismatch')
    (output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--name', choices=tuple(SITES), required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(build(args.source, args.name, args.output), indent=2))
