#!/usr/bin/env python3
"""Add pinned API30 maps and one VINTF line to a new unsigned SYSTEM copy.

No device access, signing or VENDOR reads/writes. Requires task-owned paths with
no concurrent writers or pathname replacement. Failed private staging is retained.
"""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import tempfile
import xml.etree.ElementTree as ET

from build_dsu_system import full_inventory, regular, runner
from build_google_vndk_draft import timestamps
from inventory_candidate_product import quote, split_batch
from sign_dsu_product import sha

SOURCE_SHA = '915a1ccf82ca0845dc182d922024fa3edd9f807beb97ebd6f3b4d5b9cc822a22'
SOURCE_BYTES = 3 * 1024**3
MAPPING_SHA = '22a897761e5c9f5e37d61c908819a00183ce5b52c10cc89608d8226eb892bf24'
COMPAT_SHA = '162c01e64db8206631160c14aa132a2e5a36f4cf6a5db229df6fdf81825e4a18'
VENDOR_REFERENCE_SHA = 'a3d0d55f547faf10a466861fe63ca1e8485b1c56cd7e5627bd75a1dcbf0c6c6f'
MATRIX = '/system/etc/vintf/compatibility_matrix.device.xml'
MATRIX_BEFORE_SHA = '0e337ca5df61fd2d9044c61a17ad7d2da49453002a51105197246ba1405fd9ee'
MATRIX_AFTER_SHA = 'c052c7b6c40542602bdd9605e2467fdb5e164cce54cbae51c9439810008bf905'
MAP_DIR = '/system/etc/selinux/mapping'
ADDED = (MAP_DIR + '/30.0.cil', MAP_DIR + '/30.0.compat.cil')
PARENTS = (MAP_DIR, '/system/etc/vintf')
EMPTY_SHA = hashlib.sha256(b'').hexdigest()
NEWLINE_SHA = '01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b'
EXT_POLICY_SHA = 'bcdaa16015d01771f85972ef7a2eb885708294898030d6ab78fbfa30f8090014'
VERSIONS = ('31.0', '32.0', '33.0', '34.0', '202404', '202504')
TEMPLATE_CONTENT = ((142432, '96964df1ab17c132dc077fe55e936169818f6b36ce0584a4115eaf41a426cab3'),
                    (521, 'a48742b9a57d3950efb59952c8fdd815b68d3f8605cc533efae7015cca3d6936'))


def insert_version(data):
    if len(data) != 695 or hashlib.sha256(data).hexdigest() != MATRIX_BEFORE_SHA:
        raise ValueError('Unexpected original matrix bytes')
    root = ET.fromstring(data)
    blocks = root.findall('.//sepolicy')
    if (root.tag != 'compatibility-matrix' or len(blocks) != 1
            or blocks[0].findtext('kernel-sepolicy-version') != '30'
            or [v.text for v in blocks[0].findall('sepolicy-version')] != list(VERSIONS) + ['202604']):
        raise ValueError('Unexpected matrix sepolicy declaration')
    anchor = b'        <sepolicy-version>31.0</sepolicy-version>\n'
    if data.count(anchor) != 1:
        raise ValueError('Ambiguous matrix insertion')
    result = data.replace(anchor, b'        <sepolicy-version>30.0</sepolicy-version>\n' + anchor)
    if len(result) != 745 or hashlib.sha256(result).hexdigest() != MATRIX_AFTER_SHA:
        raise ValueError('Unexpected resulting matrix bytes')
    return result


def single_regular(item, path):
    if (item['type'] != 'regular' or item['links'] != 1
            or item['same_inode_paths'] != [path] or item['symlink_target'] is not None):
        raise ValueError('Expected a single-link regular file: ' + path)


def template_pin(path, size, digest):
    return {'type': 'regular', 'permissions': '0644', 'uid': 0, 'gid': 0,
            'size': size, 'sha256': digest, 'links': 1, 'symlink_target': None,
            'timestamps_debugfs': [f'{name}: 0x495c0780:00000000 -- Thu Jan  1 00:00:00 2009'
                                   for name in ('ctime', 'atime', 'mtime', 'crtime')],
            'flags': 524288, 'generation': 0, 'project_id': 0,
            'same_inode_paths': [path],
            'xattrs': {'security.selinux': b'u:object_r:sepolicy_file:s0\0'.hex()}}


def validate_source_inventory(before):
    if any(path in before for path in ADDED):
        raise ValueError('API30 platform map already exists')
    single_regular(before[MATRIX], MATRIX)
    if (before[MATRIX]['size'], before[MATRIX]['sha256']) != (695, MATRIX_BEFORE_SHA):
        raise ValueError('Matrix inventory differs from pin')
    for suffix, (size, digest) in zip(('.cil', '.compat.cil'), TEMPLATE_CONTENT):
        path = MAP_DIR + '/31.0' + suffix
        if before[path] != template_pin(path, size, digest):
            raise ValueError('Unexpected pinned map template: ' + path)
    for parent in PARENTS:
        if before[parent]['type'] != 'directory':
            raise ValueError('Unexpected parent type')
        timestamps(parent, before[parent])
    for partition in ('system_ext', 'product'):
        alias = before['/' + partition]
        if alias['type'] != 'symlink' or alias['symlink_target'] != '/system/' + partition:
            raise ValueError('Unexpected partition alias')
        prefix = '/system/' + partition + '/etc/selinux/'
        expected = {prefix + 'mapping/' + v + '.cil': (0, EMPTY_SHA) for v in VERSIONS}
        if partition == 'system_ext':
            expected.update({prefix + 'mapping/' + v + '.compat.cil': (0, EMPTY_SHA) for v in VERSIONS})
        expected[prefix + 'mapping/202604.cil'] = (1, NEWLINE_SHA)
        actual = {p for p in before if p.startswith(prefix + 'mapping/')}
        if actual != set(expected):
            raise ValueError('Unexpected extension/product mapping paths: ' + partition)
        expected[prefix + partition + '_sepolicy.cil'] = (275433, EXT_POLICY_SHA)
        for path, content in expected.items():
            single_regular(before[path], path)
            if (before[path]['size'], before[path]['sha256']) != content:
                raise ValueError('Unexpected extension/product CIL content: ' + path)


def expected_inventory(before, mapping, compat):
    validate_source_inventory(before)
    if hashlib.sha256(mapping).hexdigest() != MAPPING_SHA or hashlib.sha256(compat).hexdigest() != COMPAT_SHA:
        raise ValueError('Unexpected mapping bytes')
    expected = copy.deepcopy(before)
    expected[MATRIX].update(size=745, sha256=MATRIX_AFTER_SHA)
    for path, payload, suffix in zip(ADDED, (mapping, compat), ('.cil', '.compat.cil')):
        item = copy.deepcopy(before[MAP_DIR + '/31.0' + suffix])
        item.update(size=len(payload), sha256=hashlib.sha256(payload).hexdigest(), same_inode_paths=[path])
        expected[path] = item
    return expected


def compare(before, after, mapping, compat):
    expected = expected_inventory(before, mapping, compat)
    if after != expected:
        raise ValueError('Unexpected filesystem content/metadata delta: ' + str(sorted(
            p for p in set(after) | set(expected) if after.get(p) != expected.get(p))))
    return {'added': list(ADDED), 'changed': [MATRIX], 'all_unrelated_entries_equal': True}


def read_payload(image, path, before, stage, run, number):
    single_regular(before[path], path)
    target = stage / f'readback-{number}'
    commands = ['dump ' + quote(path) + ' ' + quote(str(target))]
    raw = run(['/usr/sbin/debugfs', '-f', '/dev/stdin', image], stdin=commands[0] + '\n')
    split_batch(commands, raw.stdout, raw.stderr, raw.returncode)
    data = target.read_bytes()
    if len(data) != before[path]['size'] or hashlib.sha256(data).hexdigest() != before[path]['sha256']:
        raise ValueError('Selected readback differs from inventory: ' + path)
    return data


def replacement_commands(path, data, item, stage, number, replace=False):
    payload = stage / f'replacement-{number}'
    payload.write_bytes(data)
    commands = ['rm ' + quote(path)] if replace else []
    commands.append('write ' + quote(str(payload)) + ' ' + quote(path))
    for field, value in [('mode', '0' + format(0o100000 | int(item['permissions'], 8), 'o')),
                         ('uid', item['uid']), ('gid', item['gid']), ('flags', hex(item['flags'])),
                         ('generation', item['generation']), ('projid', item['project_id'])]:
        commands.append(f'set_inode_field {quote(path)} {field} {value}')
    commands.extend(timestamps(path, item))
    for attr_number, (name, value) in enumerate(item['xattrs'].items()):
        attr = stage / f'xattr-{number}-{attr_number}'
        attr.write_bytes(bytes.fromhex(value))
        commands.append('ea_set -f ' + quote(str(attr)) + ' ' + quote(path) + ' ' + quote(name))
    return commands


def check_space(parent, required):
    if shutil.disk_usage(parent).free < required:
        raise ValueError('Insufficient space for image, two retained payload inventories and scratch')


def build(source, mapping, compat, output):
    source, mapping, compat, output = (Path(p).absolute() for p in (source, mapping, compat, output))
    if output.exists() or output.is_symlink():
        raise ValueError('Output already exists')
    if not output.parent.is_dir():
        raise ValueError('Output parent must exist')
    inputs = ((source, SOURCE_SHA), (mapping, MAPPING_SHA), (compat, COMPAT_SHA))
    resolved = [p.resolve() for p, _ in inputs]
    if len(set(resolved)) != 3 or any(output.resolve() == p or output.resolve() in p.parents for p in resolved):
        raise ValueError('Input/output paths alias')
    for path, digest in inputs:
        regular(path)
        if sha(path) != digest:
            raise ValueError('Input differs from pinned candidate: ' + str(path))
    if source.stat().st_size != SOURCE_BYTES:
        raise ValueError('Unexpected source image size')
    for tool in ('/usr/sbin/debugfs', '/usr/sbin/e2fsck'):
        if not os.access(tool, os.X_OK):
            raise ValueError('Required tool unavailable: ' + tool)
    check_space(output.parent, source.stat().st_size * 3 + 256 * 1024**2)
    stage = Path(tempfile.mkdtemp(prefix='.' + output.name + '.partial-', dir=output.parent))
    run = runner(stage)
    before = full_inventory(source, stage / 'before')
    retained_payload_bytes = sum(item['size'] for path, item in before.items()
                                 if item['type'] == 'regular' and item['same_inode_paths'][0] == path)
    if retained_payload_bytes > source.stat().st_size:
        raise ValueError('Retained inventory payloads exceed the pinned three-image space budget')
    mapping_data, compat_data = mapping.read_bytes(), compat.read_bytes()
    expected = expected_inventory(before, mapping_data, compat_data)
    matrix = insert_version(read_payload(source, MATRIX, before, stage, run, 0))
    for number, path in enumerate(sorted(p for p in before if p.startswith('/system/etc/vintf/')
                                         and p.endswith('.xml') and p != MATRIX), 1):
        root = ET.fromstring(read_payload(source, path, before, stage, run, number))
        if root.tag == 'sepolicy' or root.findall('.//sepolicy'):
            raise ValueError('Unexpected additional VINTF sepolicy declaration')
    check_space(output.parent, source.stat().st_size * 2 + 256 * 1024**2)
    image = stage / 'system.partial.ext4'
    shutil.copyfile(source, image)
    image.chmod(0o600)
    commands = []
    for number, (path, data) in enumerate(zip((*ADDED, MATRIX), (mapping_data, compat_data, matrix))):
        commands.extend(replacement_commands(path, data, expected[path], stage, number, path == MATRIX))
    for parent in PARENTS:
        commands.extend(timestamps(parent, before[parent]))
    script = '\n'.join(commands) + '\n'
    (stage / 'replacement.debugfs').write_text(script)
    raw = run(['/usr/sbin/debugfs', '-w', '-f', '/dev/stdin', image], stdin=script)
    split_batch(commands, raw.stdout, raw.stderr, raw.returncode)
    run(['/usr/sbin/e2fsck', '-fn', image])
    check_space(output.parent, source.stat().st_size + 256 * 1024**2)
    after = full_inventory(image, stage / 'after')
    delta = compare(before, after, mapping_data, compat_data)
    for path, digest in inputs:
        regular(path)
        if sha(path) != digest:
            raise ValueError('Original input changed')
    final = stage / 'system.ext4'
    image.rename(final)
    report = {'status': 'UNSIGNED OFFLINE SYSTEM API30 DRAFT; NOT INSTALL READY',
              'source_sha256': SOURCE_SHA, 'mapping_sha256': MAPPING_SHA, 'compat_sha256': COMPAT_SHA,
              'image_sha256': sha(final), 'image_bytes': final.stat().st_size,
              'paths_before': len(before), 'paths_after': len(after), 'delta': delta,
              'retained_payload_bytes_per_inventory': retained_payload_bytes,
              'initial_free_space_required': SOURCE_BYTES * 3 + 256 * 1024**2,
              'original_inputs_unchanged': True, 'no_device_access': True,
              'cache_labels': 'Original opaque Google labels retained unchanged; not authentication',
              'vendor_reference_sha256': VENDOR_REFERENCE_SHA, 'vendor_read_or_modified': False,
              'vendor_pin_and_three_identifier_pairs_verified': False,
              'limits': ['VENDOR reference pin and three identifier pairs need separate combined validation',
                         'ODM cache has priority; debug override eligibility not fully reconstructed',
                         'Fallback argv presence/order and compiler output unproven; may fail or load a different policy',
                         'Stock init has no cache-only stop; no fallback safety/equivalence claim',
                         'No kernel acceptance, live cache selection, boot, recovery or VINTF runtime proof',
                         'No AVB footer, DSU signing, collector, diagnostic domain or pstore integration',
                         'Inventory excludes physical allocation and filesystem-wide metadata']}
    (stage / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    (stage / 'sha256.txt').write_text(report['image_sha256'] + '  system.ext4\n'
                                    + sha(stage / 'report.json') + '  report.json\n')
    if output.exists() or output.is_symlink():
        raise ValueError('Output appeared before publication')
    stage.rename(output)
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('source', 'mapping', 'compat', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    print(json.dumps(build(**vars(parser.parse_args())), indent=2))
