#!/usr/bin/env python3
"""Prepare an unsigned Google-policy guest VENDOR copy. Never touch a device.

New Google cache identifiers select this offline policy; they do not attest
policy semantics. Task-owned paths must have no concurrent writers.
"""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil

from build_dsu_system import full_inventory, regular, runner
from build_google_vndk_draft import timestamps
from inventory_candidate_product import quote, split_batch
from sign_dsu_product import sha

SOURCE_SHA = '7a0e59ff61e0c5da1c1f9dab2e2042d85eb0e0ea1f02df920e6b4d012d0b46c3'
POLICY_SHA = '3517d21223cbe325f2a5ee805ec89a50f45d1990397611cc12750e1f6b1dbde9'
PREFIX = '/etc/selinux/precompiled_sepolicy'
IDENTIFIERS = {
    'plat': 'f533a9872b525cfc95e81a78037da8a9cbcf92b58c018de6f5b8dbb65a6156ee',
    'system_ext': 'c20c78354393ef7dbb1be181810f67478db51650a7b0665937d720adc73e97cd',
    'product': 'c20c78354393ef7dbb1be181810f67478db51650a7b0665937d720adc73e97cd',
}


def compare(before, after, replacements):
    if set(replacements) != {PREFIX} | {PREFIX + '.' + name + '_sepolicy_and_mapping.sha256'
                                        for name in IDENTIFIERS}:
        raise ValueError('Unexpected replacement set')
    expected = copy.deepcopy(before)
    for path, data in replacements.items():
        item = expected[path]
        if item['type'] != 'regular' or item['links'] != 1 or item['same_inode_paths'] != [path]:
            raise ValueError('Replacement must be a single-link regular file')
        item.update(sha256=hashlib.sha256(data).hexdigest(), size=len(data))
    if after != expected:
        raise ValueError('Unexpected vendor content or metadata delta')
    return sorted(replacements)


def build(source, policy, output):
    for path, expected in ((source, SOURCE_SHA), (policy, POLICY_SHA)):
        regular(path)
        if sha(path) != expected:
            raise ValueError('Input differs from pinned candidate')
    if shutil.disk_usage(output.parent).free < source.stat().st_size * 3 + 128 * 1024**2:
        raise ValueError('Insufficient space for image and inventories')
    os.umask(0o077)
    output.mkdir(mode=0o700, exist_ok=False)
    run = runner(output)
    before = full_inventory(source, output / 'before')
    replacements = {PREFIX: policy.read_bytes()}
    replacements.update({PREFIX + '.' + name + '_sepolicy_and_mapping.sha256':
                         (value + '\n').encode() for name, value in IDENTIFIERS.items()})
    preview = copy.deepcopy(before)
    for path, data in replacements.items():
        preview[path].update(sha256=hashlib.sha256(data).hexdigest(), size=len(data))
    compare(before, preview, replacements)
    image = output / 'vendor.partial.ext4'
    shutil.copyfile(source, image)
    commands = []
    for number, (path, data) in enumerate(replacements.items()):
        item = before[path]
        payload = output / f'replacement-{number}'
        payload.write_bytes(data)
        commands.extend(['rm ' + quote(path), 'write ' + quote(str(payload)) + ' ' + quote(path)])
        for field, value in [('mode', '0' + format(0o100000 | int(item['permissions'], 8), 'o')),
                             ('uid', item['uid']), ('gid', item['gid']), ('flags', hex(item['flags'])),
                             ('generation', item['generation']), ('projid', item['project_id'])]:
            commands.append(f'set_inode_field {quote(path)} {field} {value}')
        commands.extend(timestamps(path, item))
        for attr_number, (name, value) in enumerate(item['xattrs'].items()):
            attr = output / f'xattr-{number}-{attr_number}'
            attr.write_bytes(bytes.fromhex(value))
            commands.append('ea_set -f ' + quote(str(attr)) + ' ' + quote(path) + ' ' + quote(name))
    commands.extend(timestamps('/etc/selinux', before['/etc/selinux']))
    script = '\n'.join(commands) + '\n'
    (output / 'replacement.debugfs').write_text(script)
    raw = run(['/usr/sbin/debugfs', '-w', '-f', '/dev/stdin', image], stdin=script)
    split_batch(commands, raw.stdout, raw.stderr, raw.returncode)
    run(['/usr/sbin/e2fsck', '-fn', image])
    after = full_inventory(image, output / 'after')
    delta = compare(before, after, replacements)
    if sha(source) != SOURCE_SHA or sha(policy) != POLICY_SHA:
        raise ValueError('Original inputs changed')
    final = output / 'vendor.ext4'
    image.rename(final)
    report = {'status': 'UNSIGNED OFFLINE GOOGLE POLICY GUEST VENDOR; NOT INSTALL READY',
              'source_sha256': SOURCE_SHA, 'policy_sha256': POLICY_SHA,
              'image_sha256': sha(final), 'image_bytes': final.stat().st_size,
              'changed_payloads': delta, 'paths': len(after),
              'all_unrelated_content_and_inventoried_metadata_equal': True,
              'original_inputs_unchanged': True, 'no_device_access': True,
              'security_tradeoff': 'NLMSG message-type filters removed; ioctl xperms preserved',
              'limits': ['No kernel acceptance or enforcement proof',
                         'Precompiled-policy selection must be verified live',
                         'No diagnostic domain or collector integrated',
                         'SYSTEM VINTF policy30 declaration remains separate work']}
    (output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('source', 'policy', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(build(args.source.absolute(), args.policy.absolute(), args.output.absolute()), indent=2))
