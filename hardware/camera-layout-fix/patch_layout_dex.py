#!/usr/bin/env python3
"""Prepare one guarded, offline Camera2 DEX layout correction. No APK output."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import zipfile
import zlib

APK_SHA256 = '24632b0e1a1c22741177583b0dfd4a3fa71ff9b1d1b72af60a3d7cf373c7e61f'
DEX_SHA256 = '4eddb6e52ee5f7b6d3674627ce4fb2901e282bfd716407bbfe503e8ee039f4f6'
METHOD_SHA256 = '3446f53b5da9a7ff8fc717afd28536d656b4288701673774737b5de0496b42e4'
CLASS = 'Lcom/android/camera/CaptureLayoutHelper;'
METHOD = 'getUncoveredPreviewRect'
RETURN = 'Landroid/graphics/RectF;'


def sha(data):
    return hashlib.sha256(data).hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def patch_dex(data):
    require(sha(data) == DEX_SHA256, 'Wrong or already patched DEX; original SHA-256 required')
    require(data[:8] == b'dex\n039\0', 'Unexpected DEX version')
    u32 = lambda offset: struct.unpack_from('<I', data, offset)[0]
    require(u32(32) == len(data) and u32(36) == 112, 'Invalid DEX header sizes')
    require(data[12:32] == hashlib.sha1(data[32:]).digest(), 'Invalid original DEX SHA-1')
    require(u32(8) == zlib.adler32(data[12:]) & 0xffffffff, 'Invalid original DEX checksum')

    def leb(offset):
        result = 0
        for shift in range(0, 35, 7):
            value = data[offset]
            offset += 1
            result |= (value & 127) << shift
            if not value & 128:
                return result, offset
        raise ValueError('Invalid ULEB128')

    strings = []
    for index in range(u32(56)):
        offset = leb(u32(u32(60) + index * 4))[1]
        strings.append(data[offset:data.index(0, offset)].decode('utf-8', errors='replace'))
    types = [strings[u32(u32(68) + index * 4)] for index in range(u32(64))]
    matches = []
    for index in range(u32(88)):
        class_id, proto_id, name_id = struct.unpack_from('<HHI', data, u32(92) + index * 8)
        if types[class_id] != CLASS or strings[name_id] != METHOD:
            continue
        _, return_id, params = struct.unpack_from('<III', data, u32(76) + proto_id * 12)
        if types[return_id] == RETURN and (params == 0 or u32(params) == 0):
            matches.append((index, class_id))
    require(len(matches) == 1, 'Target method descriptor must be unique')
    method_id, class_id = matches[0]
    class_offsets = [u32(u32(100) + index * 32 + 24)
                     for index in range(u32(96))
                     if u32(u32(100) + index * 32) == class_id]
    require(len(class_offsets) == 1 and class_offsets[0] != 0, 'Target class must be unique')
    offset = class_offsets[0]
    counts = []
    for _ in range(4):
        count, offset = leb(offset)
        counts.append(count)
    for _ in range(counts[0] + counts[1]):
        _, offset = leb(offset)
        _, offset = leb(offset)
    code_offsets = []
    for count in counts[2:]:
        index = 0
        for _ in range(count):
            delta, offset = leb(offset)
            index += delta
            _, offset = leb(offset)
            code_offset, offset = leb(offset)
            if index == method_id:
                code_offsets.append(code_offset)
    require(len(code_offsets) == 1, 'Target code item must be unique')
    code_offset = code_offsets[0]
    registers, inputs, _, tries, _, code_units = struct.unpack_from('<HHHHII', data, code_offset)
    require((registers, inputs, tries, code_units) == (5, 1, 0, 131), 'Unexpected target code header')
    start = code_offset + 16
    code = data[start:start + 2 * code_units]
    require(sha(code) == METHOD_SHA256, 'Unexpected target method instructions')
    positions = [index for index in range(0, len(code) - 3, 2)
                 if code[index:index + 4] == b'\x37\x10\x2c\x00']
    require(positions == [80], 'Expected unique if-le v0,v1 branch at code unit 40')
    # Exact pinned original instructions have independent baksmali verification:
    # v0=height, v1=width; branch target is unchanged (code unit 0x54).
    instruction_offset = start + positions[0]
    result = bytearray(data)
    result[instruction_offset] = 0x34  # if-lt, preserving registers and relative target.
    result[12:32] = hashlib.sha1(result[32:]).digest()
    struct.pack_into('<I', result, 8, zlib.adler32(result[12:]) & 0xffffffff)
    changed = [index for index, pair in enumerate(zip(data, result)) if pair[0] != pair[1]]
    require(len(data) == len(result), 'DEX size changed')
    require([index for index in changed if not 8 <= index < 32] == [instruction_offset],
            'Unexpected bytes changed outside DEX checksum/signature')
    require(result[instruction_offset:instruction_offset + 4] == b'\x34\x10\x2c\x00',
            'Patched instruction mismatch')
    require(result[12:32] == hashlib.sha1(result[32:]).digest(), 'Patched SHA-1 invalid')
    require(struct.unpack_from('<I', result, 8)[0] == zlib.adler32(result[12:]) & 0xffffffff,
            'Patched Adler-32 invalid')
    return bytes(result), {
        'original_dex_sha256': sha(data), 'patched_dex_sha256': sha(result),
        'bytes': len(data), 'class': CLASS, 'method': METHOD + '()' + RETURN,
        'method_id': method_id, 'code_item_offset': code_offset,
        'instruction_code_unit': 40, 'instruction_file_offset': instruction_offset,
        'old_instruction_hex': '37102c00', 'new_instruction_hex': '34102c00',
        'branch_target_code_unit': 84, 'changed_byte_offsets': changed,
        'allowed_header_change_range': [8, 32],
        'scope': 'Offline DEX only; no APK repackaging, signing, installation or phone testing',
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apk', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    apk = args.apk.read_bytes()
    require(sha(apk) == APK_SHA256, 'Wrong APK; exact original SHA-256 required')
    with zipfile.ZipFile(args.apk) as archive:
        require(archive.namelist().count('classes.dex') == 1, 'Ambiguous classes.dex')
        original = archive.read('classes.dex')
    patched, report = patch_dex(original)
    require(not args.output.exists(), 'Output directory already exists; refusing overwrite')
    args.output.mkdir(parents=True)
    (args.output / 'original.dex').write_bytes(original)
    (args.output / 'patched.dex').write_bytes(patched)
    report['original_apk_sha256'] = sha(apk)
    (args.output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
