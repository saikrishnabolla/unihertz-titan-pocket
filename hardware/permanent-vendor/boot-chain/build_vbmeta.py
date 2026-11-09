#!/usr/bin/env python3
"""Reproduce the tested top-level vbmeta flags change without device access."""
import argparse
import hashlib
import json
from pathlib import Path
import struct

SOURCE_SHA256 = 'e6457759e2bb9406a0cabfed8438aa302f586e1668fe20bf53f738f9874d8b1d'
OUTPUT_SHA256 = '28f2ceff6aed8e8061c31d0faf075280ef30da9c2e83e1fc72f0735a8f036a3f'
IMAGE_SIZE = 8388608


def transform(data):
    if len(data) != IMAGE_SIZE:
        raise ValueError('Expected an 8 MiB stock vbmeta partition image')
    if hashlib.sha256(data).hexdigest() != SOURCE_SHA256:
        raise ValueError('Stock vbmeta SHA-256 does not match the tested source')
    if data[:4] != b'AVB0':
        raise ValueError('Missing AVB header')
    if struct.unpack_from('>I', data, 120)[0] != 0:
        raise ValueError('Expected stock AVB flags 0')
    result = bytearray(data)
    struct.pack_into('>I', result, 120, 3)
    result = bytes(result)
    if hashlib.sha256(result).hexdigest() != OUTPUT_SHA256:
        raise ValueError('Generated vbmeta does not match the tested image')
    return result


def build(source, output):
    source, output = Path(source), Path(output)
    if source.is_symlink() or not source.is_file():
        raise ValueError('Source must be a regular file, not a symlink')
    result = transform(source.read_bytes())
    # Exclusive creation prevents overwriting stock backups or existing images.
    with output.open('xb') as stream:
        stream.write(result)
    return dict(source_sha256=SOURCE_SHA256, output_sha256=OUTPUT_SHA256,
                size_bytes=IMAGE_SIZE, changed_byte_offset=123,
                old_flags=0, new_flags=3, hashtree_disabled=True,
                verification_disabled=True, original_signature_invalidated=True,
                requires_unlocked_bootloader=True, device_actions=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--stock-vbmeta', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(build(args.stock_vbmeta, args.output), indent=2))
    except (ValueError, OSError) as error:
        parser.exit(1, str(error) + '\n')


if __name__ == '__main__':
    main()
