#!/usr/bin/env python3
"""Prepare a separate guest-only config repair; never access a device or key."""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess

from build_google_vndk_draft import timestamps
from compare_vendor_trees import inventory
from inventory_candidate_product import quote, split_batch
from repair_google_legacy_config import patch_fstab, patch_init, patch_ueventd
from sign_google_dsu_pair import private_directory, regular, RESERVE_BYTES
from sign_dsu_product import sha

SOURCES = {
    'system': (3288334336, 3221225472, '374cfaec9ef4b670c76a2e5a186f5918d805d3c760c557a01f8e5cf773377042'),
    'vendor': (536870912, 503316480, '315b2b5330b1c4788a2a3e86f8abfe6c863ef4276396c3a24deab01612a8d922'),
}
CHANGES = {
    'system': {'/system/etc/ueventd.rc': patch_ueventd},
    'vendor': {'/etc/fstab.mt6771': patch_fstab, '/etc/init/hw/init.mt6771.rc': patch_init},
}


def run(args):
    return subprocess.run([str(x) for x in args], capture_output=True, check=True,
                          timeout=600, env={**os.environ, 'LC_ALL': 'C', 'TZ': 'UTC'})


def debugfs(image, commands):
    result = subprocess.run(['/usr/sbin/debugfs', '-f', '/dev/stdin', str(image)],
                            input='\n'.join(commands) + '\n', capture_output=True,
                            text=True, timeout=120)
    return split_batch(commands, result.stdout, result.stderr, result.returncode)


def read_file(image, path):
    result = run(['/usr/sbin/debugfs', '-R', 'cat ' + quote(path), image])
    split_batch([], '', result.stderr.decode(), result.returncode)
    return result.stdout


def logical_inventory(image, output):
    result = inventory(image, output, allow_external_symlinks=True, retain_payloads=False)
    paths = sorted(result)
    for start in range(0, len(paths), 128):
        chunk = paths[start:start + 128]
        for path, text in zip(chunk, debugfs(image, ['stat ' + quote(p) for p in chunk])):
            for field, pattern in [('generation', r'^Generation:\s+(\d+)'),
                                   ('project_id', r'Project:\s+(\d+)')]:
                match = re.search(pattern, text, re.M)
                if not match:
                    raise ValueError('Missing inode field: ' + field)
                result[path][field] = int(match[1])
            if len(result[path]['timestamps_debugfs']) != 4:
                raise ValueError('Incomplete timestamp inventory')
    (output / 'inventory.json').write_text(json.dumps(result, indent=2) + '\n')
    return result


def check_source(path, spec):
    info = regular(path)
    if info.st_size != spec[0] or sha(path) != spec[2]:
        raise ValueError('Source does not match signed-image pin')
    with path.open('rb') as stream:
        header = stream.read(4096)
    if header[1080:1082] != b'\x53\xef':
        raise ValueError('Source is not EXT4')
    block_size = 1024 << struct.unpack_from('<I', header, 1048)[0]
    blocks = struct.unpack_from('<I', header, 1028)[0]
    blocks |= struct.unpack_from('<I', header, 1360)[0] << 32
    if block_size != 4096 or block_size * blocks != spec[1]:
        raise ValueError('Unexpected filesystem geometry')
    return info


def expected_inventory(before, replacements):
    expected = copy.deepcopy(before)
    for path, data in replacements.items():
        if before[path]['type'] != 'regular' or before[path]['links'] != 1:
            raise ValueError('Repair requires a unique regular file')
        expected[path].update(size=len(data), sha256=hashlib.sha256(data).hexdigest())
    return expected


def audit_vendor_configs(image, tree):
    paths = sorted(p for p, item in tree.items() if item['type'] == 'regular'
                   and ('fstab' in p or p.endswith('.rc')))
    allowed_apd = {'chown root system /mnt/vendor/apd', 'chmod 0771 /mnt/vendor/apd'}
    apd_mentions = []
    formattable = []
    for path in paths:
        text = read_file(image, path).decode('utf-8', errors='strict')
        for number, raw in enumerate(text.splitlines(), 1):
            active = raw.split('#', 1)[0].strip()
            if not active:
                continue
            if re.search(r'(?:^|[/=\s])apd(?:$|[/\s])|\bsdc40\b', active, re.I):
                if active not in allowed_apd:
                    raise ValueError('Unresolved APD path in guest configuration')
                apd_mentions.append({'path': path, 'line': number, 'command': active})
            if 'fstab' in path and 'formattable' in active:
                fields = active.split()
                if len(fields) != 5 or fields[:3] != ['/dev/block/by-name/userdata', '/data', 'ext4']:
                    raise ValueError('Physical shared-data format fallback remains')
                formattable.append({'path': path, 'line': number, 'source': fields[0]})
            if re.search(r'\btune2fs\b', active) and re.search(r'\buserdata\b', active):
                raise ValueError('Raw-userdata tune2fs command remains')
    if len(formattable) != 1:
        raise ValueError('Expected only the unchanged DSU userdata format entry')
    return {'scanned_regular_rc_fstab_files': len(paths), 'apd_mentions': apd_mentions,
            'formattable_entries': formattable,
            'limit': 'Audits shipped rc/fstab text, not arbitrary runtime-generated commands or binary behavior.'}


def replace_files(image, before, replacements, output):
    commands = []
    for number, (path, data) in enumerate(replacements.items()):
        old = before[path]
        if old['type'] != 'regular' or old['links'] != 1 or old['same_inode_paths'] != [path]:
            raise ValueError('Cannot replace a shared or non-regular inode')
        payload = output / ('replacement-' + str(number))
        payload.write_bytes(data)
        commands += ['rm ' + quote(path), 'write ' + quote(str(payload)) + ' ' + quote(path)]
        for field, value in [('mode', '0' + format(0o100000 | int(old['permissions'], 8), 'o')),
                             ('uid', old['uid']), ('gid', old['gid']),
                             ('flags', hex(old['flags'])), ('generation', old['generation']),
                             ('projid', old['project_id'])]:
            commands.append(f'set_inode_field {quote(path)} {field} {value}')
        commands += timestamps(path, old)
        for index, (name, value) in enumerate(old['xattrs'].items()):
            attr = output / f'replacement-{number}-attr-{index}'
            attr.write_bytes(bytes.fromhex(value))
            commands.append('ea_set -f ' + quote(str(attr)) + ' ' + quote(path) + ' ' + quote(name))
        parent = str(Path(path).parent)
        commands += timestamps(parent, before[parent])
    script = '\n'.join(commands) + '\n'
    (output / 'replacement.commands').write_text(script)
    result = subprocess.run(['/usr/sbin/debugfs', '-w', '-f', '/dev/stdin', str(image)],
                            input=script, capture_output=True, text=True, timeout=120)
    (output / 'replacement.stdout').write_text(result.stdout)
    (output / 'replacement.stderr').write_text(result.stderr)
    split_batch(commands, result.stdout, result.stderr, result.returncode)


def prepare(system, vendor, output):
    sources = {'system': system, 'vendor': vendor}
    private_directory(output.parent)
    if output.exists() or output.is_symlink():
        raise ValueError('Output already exists; do not retry an ambiguous preparation')
    if output.parent.stat().st_dev != Path('/dev/shm').stat().st_dev:
        raise ValueError('Large new artifacts must stay in private RAM scratch')
    if shutil.disk_usage(Path.home()).free < RESERVE_BYTES:
        raise ValueError('Oracle disk reserve is not available')
    infos = {name: check_source(path, SOURCES[name]) for name, path in sources.items()}
    if len({(s.st_dev, s.st_ino) for s in infos.values()}) != 2:
        raise ValueError('Sources must be distinct')
    # Sparse copies preserve holes; do not budget merely by logical image size.
    required = sum(s.st_blocks * 512 for s in infos.values()) + 384 * 1024**2
    if shutil.disk_usage(output.parent).free < required:
        raise ValueError('Insufficient tmpfs capacity for sparse candidates and tools')
    output.mkdir(mode=0o700)
    os.umask(0o077)
    report = {'scope': 'Unsigned offline repair only; no install or runtime proof', 'artifacts': {}}
    (output / 'preparation-intent.json').write_text(json.dumps({'sources': SOURCES}, indent=2))
    for name, source in sources.items():
        work = output / name
        work.mkdir(mode=0o700)
        before = logical_inventory(source, work / 'before')
        replacements = {}
        for path, transform in CHANGES[name].items():
            original = read_file(source, path)
            if hashlib.sha256(original).hexdigest() != before[path]['sha256']:
                raise ValueError('Config readback differs from inventory')
            replacements[path] = transform(original)
        expected = expected_inventory(before, replacements)
        image = work / (name + '.ext4')
        run(['cp', '--sparse=always', '--reflink=never', '--', source, image])
        with image.open('r+b') as stream:
            stream.truncate(SOURCES[name][1])
        if sha(image) != sha(source, SOURCES[name][1]):
            raise ValueError('Sparse copy changed filesystem bytes')
        replace_files(image, before, replacements, work)
        checked = run(['/usr/sbin/e2fsck', '-fn', image])
        (work / 'e2fsck.txt').write_bytes(checked.stdout + checked.stderr)
        after = logical_inventory(image, work / 'after')
        if after != expected:
            differences = sorted(p for p in set(after) | set(expected) if after.get(p) != expected.get(p))
            (work / 'unexpected-delta.json').write_text(json.dumps(differences))
            raise ValueError('Unexpected logical filesystem change; inspect private delta')
        if name == 'vendor':
            report['vendor_config_audit'] = audit_vendor_configs(image, after)
        report['artifacts'][name] = {'filesystem_sha256': sha(image),
                                     'filesystem_bytes': SOURCES[name][1],
                                     'partition_bytes': SOURCES[name][0],
                                     'changed_paths': sorted(replacements),
                                     'source_sha256': SOURCES[name][2],
                                     'logical_paths': len(after)}
    for name, source in sources.items():
        check_source(source, SOURCES[name])
        now, old = regular(source), infos[name]
        if (now.st_dev, now.st_ino, now.st_size, now.st_mtime_ns, now.st_ctime_ns) != (old.st_dev, old.st_ino, old.st_size, old.st_mtime_ns, old.st_ctime_ns):
            raise ValueError('Original source identity changed')
    if shutil.disk_usage(Path.home()).free < RESERVE_BYTES:
        raise ValueError('Oracle disk reserve lost')
    (output / 'prepared.json').write_text(json.dumps(report, indent=2) + '\n')
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('system', 'vendor', 'output'):
        parser.add_argument('--' + name, required=True, type=Path)
    print(json.dumps(prepare(**vars(parser.parse_args())), indent=2))
