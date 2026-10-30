#!/usr/bin/env python3
"""Add an unchanged Google-signed VNDK30 package to a new Google17 filesystem.

Unsigned, incomplete offline draft only. No device access or signing keys.
Requires task-owned paths with no concurrent writers or pathname replacement.
"""
import argparse
import copy
import json
import os
from pathlib import Path
import re
import shutil

from build_dsu_system import full_inventory, regular, runner, tool_check, unshare
from inventory_candidate_product import quote, split_batch
from sign_dsu_product import sha

SOURCE_SHA = 'e5db44e3365f9e542ee3f6d4caf88ece554a460e2987086b8bf21f6c440a25ec'
DONOR_SHA = 'ab5bbcbcfd254195bbb4e8773ea5ae85b09153e0ed06506e2f8ed0213e6e4f87'
TARGET = '/system/system_ext/apex/com.android.vndk.v30.apex'
TEMPLATE = '/system/system_ext/apex/com.android.vndk.v31.apex'
PARENT = '/system/system_ext/apex'
FS_BYTES = 3 * 1024**3


def compare_added_vndk(before, after, donor_sha, donor_size):
    if TARGET in before or TEMPLATE not in before:
        raise ValueError('Unexpected source APEX path set')
    template = before[TEMPLATE]
    if template['type'] != 'regular' or template['links'] != 1:
        raise ValueError('Unexpected source APEX metadata')
    expected = copy.deepcopy(before)
    expected[TARGET] = copy.deepcopy(template)
    expected[TARGET].update(size=donor_size, sha256=donor_sha, same_inode_paths=[TARGET])
    if after != expected:
        differences = sorted(path for path in set(after) | set(expected)
                             if after.get(path) != expected.get(path))
        raise ValueError('Unexpected filesystem delta: ' + str(differences))
    return [TARGET]


def timestamps(path, item):
    commands = []
    if len(item['timestamps_debugfs']) != 4:
        raise ValueError('Incomplete source timestamps')
    for timestamp in item['timestamps_debugfs']:
        match = re.fullmatch(r'(ctime|atime|mtime|crtime): (0x[0-9a-f]{8}):([0-9a-f]{8}) -- .+', timestamp)
        if not match:
            raise ValueError('Unsupported source timestamp')
        commands.extend([f'set_inode_field {quote(path)} {match[1]} {match[2]}',
                         f'set_inode_field {quote(path)} {match[1]}_extra 0x{match[3]}'])
    return commands


def build(source, donor, avbtool, output):
    for path, expected in [(source, SOURCE_SHA), (donor, DONOR_SHA)]:
        regular(path)
        if sha(path) != expected:
            raise ValueError('Input differs from pinned original: ' + str(path))
    tool_check(avbtool)
    if shutil.disk_usage(output.parent).free < FS_BYTES * 4 + 256 * 1024**2:
        raise ValueError('Insufficient space for image and three retained inventories')
    os.umask(0o077)
    output.mkdir(mode=0o700, exist_ok=False)
    run = runner(output)
    before = full_inventory(source, output / 'before')
    if TARGET in before or before[TEMPLATE]['same_inode_paths'] != [TEMPLATE]:
        raise ValueError('Unexpected original APEX paths or hardlinks')
    image = output / 'system-vndk30-draft.partial.ext4'
    shutil.copyfile(source, image)
    run(['python3', avbtool, 'erase_footer', '--image', image])
    with image.open('r+b') as stream:
        stream.truncate(FS_BYTES)
    run(['/usr/sbin/resize2fs', image, str(FS_BYTES // 4096)])
    unshare(image, before, run)
    unshared = full_inventory(image, output / 'unshared')
    if unshared != before:
        raise ValueError('Unsharing changed logical content or inventoried metadata')
    template = before[TEMPLATE]
    commands = ['write ' + quote(str(donor.resolve())) + ' ' + quote(TARGET)]
    fields = [('mode', '0' + format(0o100000 | int(template['permissions'], 8), 'o')),
              ('uid', template['uid']), ('gid', template['gid']), ('flags', hex(template['flags'])),
              ('generation', template['generation']), ('projid', template['project_id'])]
    commands.extend(f'set_inode_field {quote(TARGET)} {field} {value}' for field, value in fields)
    commands.extend(timestamps(TARGET, template))
    for number, (name, value) in enumerate(template['xattrs'].items()):
        attr = output / f'donor-xattr-{number}'
        attr.write_bytes(bytes.fromhex(value))
        commands.append('ea_set -f ' + quote(str(attr.resolve())) + ' ' + quote(TARGET) + ' ' + quote(name))
    commands.extend(timestamps(PARENT, before[PARENT]))
    script = '\n'.join(commands) + '\n'
    (output / 'addition.debugfs').write_text(script)
    raw = run(['/usr/sbin/debugfs', '-w', '-f', '/dev/stdin', image], stdin=script)
    split_batch(commands, raw.stdout, raw.stderr, raw.returncode)
    run(['/usr/sbin/e2fsck', '-fn', image])
    after = full_inventory(image, output / 'after')
    delta = compare_added_vndk(before, after, DONOR_SHA, donor.stat().st_size)
    if sha(source) != SOURCE_SHA or sha(donor) != DONOR_SHA:
        raise ValueError('Original input changed')
    final = output / 'system-vndk30-draft.ext4'
    image.rename(final)
    image = final
    report = {'status': 'UNSIGNED INCOMPLETE OFFLINE DRAFT; NOT INSTALL READY',
              'source_sha256': SOURCE_SHA, 'donor_sha256': DONOR_SHA,
              'image': str(image), 'image_sha256': sha(image), 'image_bytes': FS_BYTES,
              'source_paths': len(before), 'result_paths': len(after), 'added_paths': delta,
              'all_original_logical_content_and_inventoried_metadata_unchanged': True,
              'original_inputs_unchanged': True, 'no_device_access': True,
              'limits': ['No SYSTEM AVB footer; not an installable DSU package.',
                         'APEX activation, linker namespaces, ABI and hardware untested.',
                         'No SELinux, networking, product-mount or diagnostic-access adaptation included.',
                         'Inventory excludes physical allocation and filesystem-wide metadata.']}
    (output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('source', 'donor', 'avbtool', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(build(args.source.absolute(), args.donor.absolute(), args.avbtool.absolute(), args.output.absolute()), indent=2))
