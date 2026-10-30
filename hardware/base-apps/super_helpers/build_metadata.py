#!/usr/bin/env python3
"""Build a fixed Titan super metadata prefix. No devices, GPT or payload writes.

Format: AOSP android11-release fs_mgr/liblp/include/liblp/metadata_format.h,
metadata 10.0. Two OEM slots are retained even though names/flags are non-A/B.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import struct

# The first-stage review predates the final keydirectory-only VENDOR rebuild.
SUPER_SIZE = 4831838208
MAXIMUM = 65536
SLOTS = 2
BLOCK = 4096
METADATA_START = 3 * BLOCK
PREFIX_SIZE = METADATA_START + MAXIMUM * SLOTS * 2
GROUP_MAXIMUM = 4829741056
PARTITIONS = [
    {'name': 'system', 'attributes': 1, 'group': 1, 'size': 3288334336,
     'extents': [(6422528, 0, 2048, 0)]},
    {'name': 'vendor', 'attributes': 1, 'group': 1, 'size': 536870912,
     'extents': [(1048576, 0, 6424576, 0)]},
]
GROUPS = [dict(name='default', flags=0, maximum_size=0),
          dict(name='main', flags=0, maximum_size=GROUP_MAXIMUM)]
DEVICES = [dict(first_logical_sector=2048, alignment=1048576,
                alignment_offset=0, size=SUPER_SIZE, name='super', flags=0)]


def sha(data):
    return hashlib.sha256(data).hexdigest()




def checksum(data, begin, end):
    if hashlib.sha256(data[:begin] + b'\0' * (end-begin) + data[end:]).digest() != data[begin:end]:
        raise ValueError('Checksum mismatch')


def fixed_name(data):
    name, separator, padding = data.partition(b'\0')
    if not separator or any(padding) or not re.fullmatch(rb'[A-Za-z0-9_]{1,35}', name):
        raise ValueError('Invalid fixed name')
    return name.decode('ascii')




def geometry(blob):
    if len(blob) < PREFIX_SIZE or any(blob[:BLOCK]):
        raise ValueError('Truncated prefix or nonzero reserved block')
    chunks = [blob[BLOCK:2*BLOCK], blob[2*BLOCK:3*BLOCK]]
    if chunks[0] != chunks[1]:
        raise ValueError('Geometry copies differ')
    g = chunks[0]
    if struct.unpack_from('<II', g) != (0x616c4467, 52):
        raise ValueError('Unsupported geometry header')
    checksum(g[:52], 8, 40)
    if struct.unpack_from('<III', g, 40) != (MAXIMUM, SLOTS, BLOCK) or any(g[52:]):
        raise ValueError('Geometry differs from OEM policy')
    return dict(metadata_max_size=MAXIMUM, metadata_slots=SLOTS, logical_block_size=BLOCK)


def parse_slot(slot):
    if len(slot) != MAXIMUM:
        raise ValueError('Wrong metadata allocation')
    header = slot[:128]
    if struct.unpack_from('<IHHI', header) != (0x414c5030, 10, 0, 128):
        raise ValueError('Unsupported metadata version/header')
    checksum(header, 12, 44)
    length = struct.unpack_from('<I', header, 44)[0]
    if length > MAXIMUM - 128:
        raise ValueError('Tables exceed metadata allocation')
    tables = slot[128:128+length]
    if hashlib.sha256(tables).digest() != header[48:80]:
        raise ValueError('Table checksum mismatch')
    if any(slot[128+length:]):
        raise ValueError('Nonzero metadata padding')
    descriptors = []
    expected_offset = 0
    for at, width in [(80, 52), (92, 24), (104, 48), (116, 64)]:
        offset, count, stride = struct.unpack_from('<III', header, at)
        if stride != width or offset != expected_offset or count > 4096:
            raise ValueError('Table layout/entry size differs')
        end = offset + count * stride
        if end > length:
            raise ValueError('Table bounds exceed tables')
        descriptors.append([tables[offset+i*stride:offset+(i+1)*stride] for i in range(count)])
        expected_offset = end
    if expected_offset != length:
        raise ValueError('Tables contain unclaimed bytes')
    part_rows, extent_rows, group_rows, device_rows = descriptors
    extents = [struct.unpack('<QIQI', row) for row in extent_rows]
    groups = []
    for row in group_rows:
        raw, flags, maximum = struct.unpack('<36sIQ', row)
        groups.append(dict(name=fixed_name(raw), flags=flags, maximum_size=maximum))
    devices = []
    for row in device_rows:
        first, align, delta, size, raw, flags = struct.unpack('<QIIQ36sI', row)
        devices.append(dict(first_logical_sector=first, alignment=align,
                            alignment_offset=delta, size=size, name=fixed_name(raw), flags=flags))
    if groups != GROUPS or devices != DEVICES:
        raise ValueError('Groups/device differ from non-A/B OEM policy')
    partitions = []
    covered = set()
    physical = []
    names = set()
    group_usage = [0] * len(groups)
    for row in part_rows:
        raw, attributes, first, count, group = struct.unpack('<36sIIII', row)
        name = fixed_name(raw)
        if name in names or name.endswith(('_a', '_b')) or attributes != 1:
            raise ValueError('Duplicate, slotted or non-readonly partition')
        names.add(name)
        if count == 0 or first + count > len(extents) or group >= len(groups):
            raise ValueError('Partition extents/group invalid')
        indexes = set(range(first, first+count))
        if covered & indexes:
            raise ValueError('Extent reused by partitions')
        covered |= indexes
        chosen = extents[first:first+count]
        size = 0
        for sectors, kind, target, source in chosen:
            if kind != 0 or source != 0 or sectors == 0 or sectors % 8:
                raise ValueError('Only nonempty aligned linear extents supported')
            if target < 2048 or target % 2048 or (target+sectors)*512 > SUPER_SIZE:
                raise ValueError('Extent outside aligned payload region')
            physical.append((target, target+sectors))
            size += sectors * 512
        partitions.append(dict(name=name, attributes=attributes, group=group,
                               size=size, extents=chosen))
        group_usage[group] += size
    if covered != set(range(len(extents))):
        raise ValueError('Unowned extent')
    physical.sort()
    if any(left[1] > right[0] for left, right in zip(physical, physical[1:])):
        raise ValueError('Physical extents overlap')
    if any(g['maximum_size'] and size > g['maximum_size'] for g, size in zip(groups, group_usage)):
        raise ValueError('Group usage exceeds maximum')
    return dict(partitions=partitions, groups=groups, block_devices=devices,
                header_tables_sha256=sha(slot[:128+length]))


def parse_prefix(blob):
    result = geometry(blob)
    copies = []
    slots = []
    for copy in range(2):
        for index in range(SLOTS):
            offset = METADATA_START + (copy*SLOTS+index) * MAXIMUM
            slot = blob[offset:offset+MAXIMUM]
            parsed = parse_slot(slot)
            slots.append(slot)
            copies.append(dict(copy=copy, slot=index,
                               header_tables_sha256=parsed['header_tables_sha256']))
    if any(slot != slots[0] for slot in slots[1:]):
        raise ValueError('Four metadata allocations differ')
    result.update(expanded_super_size=SUPER_SIZE,
                  partitions=parsed['partitions'], groups=parsed['groups'],
                  block_devices=parsed['block_devices'], metadata_copies=copies)
    return result




def validate_minimal(blob):
    if len(blob) != PREFIX_SIZE:
        raise ValueError('Minimal artifact must contain metadata prefix only')
    parsed = parse_prefix(blob)
    if parsed['partitions'] != PARTITIONS:
        raise ValueError('Partition layout differs from fixed minimal policy')
    return parsed
