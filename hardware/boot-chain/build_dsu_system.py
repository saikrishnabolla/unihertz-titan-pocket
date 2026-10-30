#!/usr/bin/env python3
"""Prepare and sign a separate SYSTEM copy; never access a phone or block device."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess

from compare_vendor_trees import inventory
from check_dsu_system_avb import check as check_avb, PROPERTIES, ROLLBACK_INDEX
from inventory_candidate_product import quote, split_batch
from sign_dsu_product import sha

SOURCE_SHA512 = 'ebe743126ff8ecdf70991c006fc9f873370676907d7b636f551c677930cf8078bac75b3146f8f528d213b2f9bd731ca94aff3b8c5a4dd5e9e021ca4990eec777'
SOURCE_BYTES = 3121967104
TARGET = '/system/apex/com.android.tethering.apex'
ORIGINAL_APEX_SHA = 'df925e0be47c94c4c2b0e07d66b67783709654c9a34bf00bc76c14231091a145'
AVBTOOL_SHA = '69783733ce5e198317b02a5567cc356e898c891de872f58a963e9d5c082973c6'
FS_BYTES = 3584 * 1024**2
PARTITION_BYTES = 3648 * 1024**2


def regular(path):
    if path.is_symlink() or not path.is_file():
        raise ValueError('Expected a regular, non-symlink file: ' + str(path))


def source_check(source):
    regular(source)
    h = hashlib.sha512()
    with source.open('rb') as stream:
        for block in iter(lambda: stream.read(1024**2), b''):
            h.update(block)
    if source.stat().st_size != SOURCE_BYTES or h.hexdigest() != SOURCE_SHA512:
        raise ValueError('Original SYSTEM does not match pinned candidate')


def tool_check(avbtool):
    regular(avbtool)
    if sha(avbtool) != AVBTOOL_SHA:
        raise ValueError('Unexpected avbtool source')


def runner(output):
    commands = []
    def run(args, allowed=(0,), stdin=None):
        args = [str(arg) for arg in args]
        result = subprocess.run(args, input=stdin, capture_output=True, text=True, timeout=600,
                                env={**os.environ, 'LC_ALL': 'C', 'TZ': 'UTC'})
        commands.append({'command': args, 'exit': result.returncode,
                         'stdout': result.stdout, 'stderr': result.stderr})
        (output / 'commands.json').write_text(json.dumps(commands, indent=2) + '\n')
        if result.returncode not in allowed:
            raise ValueError('Command failed; see ' + str(output / 'commands.json'))
        return result
    return run


def full_inventory(image, output):
    result = inventory(image, output, allow_external_symlinks=True)
    paths = sorted(result)
    for start in range(0, len(paths), 128):
        chunk = paths[start:start + 128]
        commands = ['stat ' + quote(path) for path in chunk]
        raw = subprocess.run(['/usr/sbin/debugfs', '-f', '/dev/stdin', str(image)],
                             input='\n'.join(commands) + '\n', capture_output=True, text=True, timeout=120)
        (output / f'extra-stat-{start}.stdout').write_text(raw.stdout)
        sections = split_batch(commands, raw.stdout, raw.stderr, raw.returncode)
        for path, text in zip(chunk, sections):
            for field, pattern in [('generation', r'^Generation:\s+(\d+)'),
                                   ('project_id', r'Project:\s+(\d+)')]:
                match = re.search(pattern, text, re.M)
                if not match:
                    raise ValueError('Missing inode field ' + field)
                result[path][field] = int(match[1])
            if len(result[path]['timestamps_debugfs']) != 4:
                raise ValueError('Incomplete timestamp inventory: ' + path)
    (output / 'inventory.json').write_text(json.dumps(result, indent=2) + '\n')
    return result


def compare(before, after, replacement=None):
    if before.keys() != after.keys():
        raise ValueError('SYSTEM path set changed')
    changed = {}
    for path, item in before.items():
        if item.keys() != after[path].keys():
            raise ValueError('Inventory fields changed')
        fields = [key for key in item if item[key] != after[path][key]]
        if fields:
            changed[path] = fields
    if replacement is None:
        if changed:
            raise ValueError('Unsharing changed logical content/metadata: ' + str(changed))
    else:
        if changed != {TARGET: ['size', 'sha256']}:
            raise ValueError('Unexpected SYSTEM delta: ' + str(changed))
        if after[TARGET]['sha256'] != sha(replacement) or after[TARGET]['size'] != replacement.stat().st_size:
            raise ValueError('Replacement APEX content mismatch')
    return changed


def unshare(image, before, run):
    if any(item['type'] == 'directory' and item['flags'] & 0x1000 for item in before.values()):
        raise ValueError('Temporary dir_index suppression requires no indexed source directories')
    run(['/usr/sbin/tune2fs', '-O', '^dir_index', image])
    run(['/usr/sbin/e2fsck', '-fy', '-E', 'unshare_blocks,fixes_only', image], allowed=(0, 1))
    run(['/usr/sbin/tune2fs', '-O', 'dir_index', image])


def signing_args(image, key, avbtool, filesystem_sha):
    return ['python3', avbtool, 'add_hashtree_footer', '--image', image, '--partition_name', 'system',
            '--partition_size', str(PARTITION_BYTES), '--hash_algorithm', 'sha256', '--block_size', '4096',
            '--do_not_generate_fec', '--algorithm', 'SHA256_RSA2048', '--key', key,
            '--salt', filesystem_sha, '--rollback_index', str(ROLLBACK_INDEX),
            *[arg for name, value in PROPERTIES.items() for arg in ('--prop', name + ':' + value)]]


def prepare(source, output, avbtool):
    source_check(source)
    tool_check(avbtool)
    os.umask(0o077)
    output.mkdir(mode=0o700, exist_ok=False)
    run = runner(output)
    before = full_inventory(source, output / 'before')
    target = before[TARGET]
    if (target['type'], target['links'], target['sha256']) != ('regular', 1, ORIGINAL_APEX_SHA):
        raise ValueError('Unexpected original APEX')
    image = output / 'system-unshared.img'
    shutil.copyfile(source, image)
    run(['python3', avbtool, 'erase_footer', '--image', image])
    with image.open('r+b') as stream:
        stream.truncate(FS_BYTES)
    run(['/usr/sbin/resize2fs', image, str(FS_BYTES // 4096)])
    unshare(image, before, run)
    run(['/usr/sbin/e2fsck', '-fn', image])
    superblock = run(['/usr/sbin/dumpe2fs', '-h', image]).stdout
    if 'shared_blocks' in superblock:
        raise ValueError('Shared-block feature remains')
    after = full_inventory(image, output / 'unshared')
    compare(before, after)
    source_check(source)
    report = {'scope': 'Offline unshared SYSTEM copy; no replacement or installation yet',
              'source_sha512': SOURCE_SHA512, 'filesystem_bytes': FS_BYTES,
              'source_paths': len(before), 'all_logical_content_and_inventoried_metadata_unchanged': True,
              'unshared_sha256': sha(image), 'system_source': str(source),
              'baseline_inventory_sha256': sha(output / 'before/inventory.json')}
    (output / 'prepared.json').write_text(json.dumps(report, indent=2) + '\n')
    return report


def finish(prepared, apex, apex_sha, output, key, avbtool):
    for path in (apex, key, avbtool):
        regular(path)
    tool_check(avbtool)
    if sha(apex) != apex_sha or key.stat().st_mode & 0o077:
        raise ValueError('Unexpected APEX hash or non-private key')
    state = json.loads((prepared / 'prepared.json').read_text())
    source = prepared / 'system-unshared.img'
    if source.stat().st_size != FS_BYTES or sha(source) != state['unshared_sha256']:
        raise ValueError('Prepared filesystem changed')
    baseline = prepared / 'before/inventory.json'
    if sha(baseline) != state['baseline_inventory_sha256']:
        raise ValueError('Prepared baseline inventory changed')
    before = json.loads(baseline.read_text())
    os.umask(0o077)
    output.mkdir(mode=0o700, exist_ok=False)
    run = runner(output)
    image = output / 'system.img'
    shutil.copyfile(source, image)
    commands = replacement_commands(before[TARGET], apex, output)
    script = '\n'.join(commands) + '\n'
    (output / 'replacement.commands').write_text(script)
    raw = run(['/usr/sbin/debugfs', '-w', '-f', '/dev/stdin', image], stdin=script)
    split_batch(commands, raw.stdout, raw.stderr, raw.returncode)
    run(['/usr/sbin/e2fsck', '-fn', image])
    after = full_inventory(image, output / 'after')
    delta = compare(before, after, apex)
    filesystem_sha = sha(image)
    run(signing_args(image, key, avbtool, filesystem_sha))
    public = output / 'public.pem'
    run(['openssl', 'pkey', '-in', key, '-pubout', '-out', public])
    run(['python3', avbtool, 'verify_image', '--image', image, '--key', public])
    info = run(['python3', avbtool, 'info_image', '--image', image]).stdout
    (output / 'avb-info.txt').write_text(info)
    run(['/usr/sbin/e2fsck', '-fn', image])
    if sha(image, FS_BYTES) != filesystem_sha or sha(apex) != apex_sha or sha(source) != state['unshared_sha256']:
        raise ValueError('Signing changed filesystem prefix or inputs')
    structure = check_avb(image, FS_BYTES, PARTITION_BYTES)
    source_check(Path(state['system_source']))
    report = {'scope': 'Offline signed SYSTEM derivative; no DSU install or boot test',
              'system_sha256': sha(image), 'system_bytes': PARTITION_BYTES,
              'filesystem_bytes': FS_BYTES, 'filesystem_sha256': filesystem_sha,
              'replacement_apex_sha256': apex_sha, 'source_paths': len(before),
              'logical_changes': delta, 'public_key_sha256': sha(public), 'structure': structure,
              'original_candidate_sha512': SOURCE_SHA512,
              'intentional_avb_change': 'New local signing key and regenerated SHA256 tree; FEC omitted (original had two roots)',
              'runtime_apex_activation_and_bpf_verifier_acceptance': 'untested'}
    (output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    return report


def replacement_commands(item, apex, output):
    # debugfs rm/write recreates this single-link inode. Restore its complete tracked metadata.
    commands = ['rm ' + quote(TARGET), 'write ' + quote(str(apex.resolve())) + ' ' + quote(TARGET)]
    for field, value in [('mode', '0' + format(0o100000 | int(item['permissions'], 8), 'o')),
                         ('uid', item['uid']), ('gid', item['gid']), ('flags', hex(item['flags'])),
                         ('generation', item['generation']), ('projid', item['project_id'])]:
        commands.append(f'set_inode_field {quote(TARGET)} {field} {value}')
    for timestamp in item['timestamps_debugfs']:
        match = re.match(r'(\w+): (0x[0-9a-f]+):(\w+) -- ', timestamp)
        if not match:
            raise ValueError('Unsupported timestamp')
        commands.append(f'set_inode_field {quote(TARGET)} {match[1]} {match[2]}')
        commands.append(f'set_inode_field {quote(TARGET)} {match[1]}_extra 0x{match[3]}')
    for name, value in item['xattrs'].items():
        attr = output / ('apex-' + name)
        attr.write_bytes(bytes.fromhex(value))
        commands.append('ea_set -f ' + quote(str(attr.resolve())) + ' ' + quote(TARGET) + ' ' + quote(name))
    return commands


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    first = sub.add_parser('prepare')
    for name in ('source', 'output', 'avbtool'):
        first.add_argument('--' + name, type=Path, required=True)
    last = sub.add_parser('finish')
    for name in ('prepared', 'apex', 'output', 'key', 'avbtool'):
        last.add_argument('--' + name, type=Path, required=True)
    last.add_argument('--apex-sha', required=True)
    args = vars(parser.parse_args())
    action = args.pop('action')
    print(json.dumps((prepare if action == 'prepare' else finish)(**args), indent=2))
