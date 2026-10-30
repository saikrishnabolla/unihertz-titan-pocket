#!/usr/bin/env python3
"""Integrate one pinned diagnostic APEX into a new unsigned Google17 draft.

No signing, installation or device access. Requires task-owned paths without
concurrent writers. Replace the compressed original, never keep both variants.
"""
import argparse
import copy
import json
import os
from pathlib import Path
import shutil

from build_dsu_system import full_inventory, regular, runner
from build_google_vndk_draft import timestamps
from inventory_candidate_product import quote, split_batch
from sign_dsu_product import sha

SOURCE_SHA = '3ac3b5a4abc4ce1ad832a825c3a97c22f4309ef36e2bc2d62d8bb66e2cb85e73'
APEX_SHA = 'fe51f5d3a19bd4d73c3ee6f12912f23f9cfb8817e80f97569400f9378cdec616'
ORIGINAL_SHA = '68f178dbb5de7aee9437aadc03ff061fe004c3878a40420c5d3064d571361682'
OLD = '/system/apex/com.android.tethering.capex'
NEW = '/system/apex/com.android.tethering.apex'
PARENT = '/system/apex'


def compare(before, after, apex_sha, apex_size):
    if NEW in before or OLD not in before:
        raise ValueError('Unexpected original Connectivity paths')
    original = before[OLD]
    if (original['type'], original['links'], original['sha256']) != ('regular', 1, ORIGINAL_SHA):
        raise ValueError('Unexpected compressed original')
    if original['same_inode_paths'] != [OLD]:
        raise ValueError('Original APEX has unexpected hardlinks')
    expected = copy.deepcopy(before)
    item = expected.pop(OLD)
    item.update(size=apex_size, sha256=apex_sha, same_inode_paths=[NEW])
    expected[NEW] = item
    if after != expected:
        raise ValueError('Unexpected filesystem delta: ' + str(sorted(
            path for path in set(after) | set(expected) if after.get(path) != expected.get(path))))
    return {'removed': [OLD], 'added': [NEW], 'all_unrelated_entries_equal': True}


def build(source, apex, output):
    for path, expected in ((source, SOURCE_SHA), (apex, APEX_SHA)):
        regular(path)
        if sha(path) != expected:
            raise ValueError('Input differs from pinned draft: ' + str(path))
    if shutil.disk_usage(output.parent).free < source.stat().st_size * 3 + 256 * 1024**2:
        raise ValueError('Insufficient space for image and retained inventories')
    os.umask(0o077)
    output.mkdir(mode=0o700, exist_ok=False)
    run = runner(output)
    before = full_inventory(source, output / 'before')
    preview = copy.deepcopy(before)
    preview[NEW] = preview.pop(OLD)
    preview[NEW].update(size=apex.stat().st_size, sha256=APEX_SHA, same_inode_paths=[NEW])
    compare(before, preview, APEX_SHA, apex.stat().st_size)
    item = before[OLD]
    image = output / 'system.partial.ext4'
    shutil.copyfile(source, image)
    commands = ['rm ' + quote(OLD), 'write ' + quote(str(apex.resolve())) + ' ' + quote(NEW)]
    for field, value in [('mode', '0' + format(0o100000 | int(item['permissions'], 8), 'o')),
                         ('uid', item['uid']), ('gid', item['gid']), ('flags', hex(item['flags'])),
                         ('generation', item['generation']), ('projid', item['project_id'])]:
        commands.append(f'set_inode_field {quote(NEW)} {field} {value}')
    commands.extend(timestamps(NEW, item))
    for number, (name, value) in enumerate(item['xattrs'].items()):
        attr = output / f'apex-xattr-{number}'
        attr.write_bytes(bytes.fromhex(value))
        commands.append('ea_set -f ' + quote(str(attr.resolve())) + ' ' + quote(NEW) + ' ' + quote(name))
    commands.extend(timestamps(PARENT, before[PARENT]))
    script = '\n'.join(commands) + '\n'
    (output / 'replacement.debugfs').write_text(script)
    raw = run(['/usr/sbin/debugfs', '-w', '-f', '/dev/stdin', image], stdin=script)
    split_batch(commands, raw.stdout, raw.stderr, raw.returncode)
    run(['/usr/sbin/e2fsck', '-fn', image])
    after = full_inventory(image, output / 'after')
    delta = compare(before, after, APEX_SHA, apex.stat().st_size)
    if sha(source) != SOURCE_SHA or sha(apex) != APEX_SHA:
        raise ValueError('Original inputs changed')
    final = output / 'system.ext4'
    image.rename(final)
    report = {'status': 'UNSIGNED INCOMPLETE OFFLINE SYSTEM; NOT INSTALL READY',
              'source_sha256': SOURCE_SHA, 'apex_sha256': APEX_SHA,
              'image_sha256': sha(final), 'image_bytes': final.stat().st_size,
              'paths_before': len(before), 'paths_after': len(after), 'delta': delta,
              'original_inputs_unchanged': True, 'no_device_access': True,
              'limits': ['No SYSTEM AVB footer or DSU package',
                         'Policy, mounts and diagnostic access not integrated',
                         'No runtime APEX, BPF, networking or hardware proof']}
    (output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('source', 'apex', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(build(args.source.absolute(), args.apex.absolute(), args.output.absolute()), indent=2))
