#!/usr/bin/env python3
"""Assemble a permanent VENDOR from pinned stock firmware and generated policy."""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

HERE = Path(__file__).resolve().parent
SOURCE_SHA = 'd991ee39bb233c7f717d9007b1acf9f83c41b3db3e8af188a9c78d4f27b1408f'
STOCK_FS = 445157376
FS = 503316480
SIZE = 536870912
SALT = '8a28b39b2793205d664e4331b2eb9bcd87c976c6117ff4f5fce173fa8280b466'
KEYMAPS = {
    '/usr/idc/aw9523-key.idc': '12583fb3c7e089692d5ae72fc6f50f294db4f7f62843ba233f5e6a23f307adb3',
    '/usr/keychars/aw9523-key.kcm': '357335f66d3eada044ec9f944fa9623efde1c23289fc65a4a14329ea07af3427',
    '/usr/keylayout/aw9523-key.kl': 'a881ff89f2c236584a8b8c6937e8e2ce9cf199ed85c9c1740bb96c72fba33c39',
}
POLICIES = {
    'precompiled_sepolicy': 'cb2e4b879e2de0c0acb97309c9a8380e2c25771a16ed0557733ef80bfd3b2e22',
    'plat_pub_versioned.cil': '76234e88b3bd10224c7ec5a5c9e64a078fd6a23bdd0bce309d5bbe780f95f809',
    'vendor_sepolicy.cil': '166e80022bf7ff521733ff10efe8ecc8f69c2046b222c6b8d82ba26c3d7da18f',
    'precompiled_sepolicy.plat_sepolicy_and_mapping.sha256': '056433d5f41c81d3d0336471e12dd2a8ff313582cd797d017fb259916d9867b8',
    'precompiled_sepolicy.product_sepolicy_and_mapping.sha256': 'b9444b86296fc716ebbea7f7fdbb118c5a0f56e14634ced0a21c82ff0a1cbf28',
    'precompiled_sepolicy.system_ext_sepolicy_and_mapping.sha256': 'b9444b86296fc716ebbea7f7fdbb118c5a0f56e14634ced0a21c82ff0a1cbf28',
}


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def normalize(entry):
    result = copy.deepcopy(entry)
    # Layout and allocation may differ after resizing/replacing files.
    result.pop('inode', None)
    result.pop('allocated_512_blocks', None)
    return result


def build(args):
    if not __debug__:
        raise ValueError('Run without Python optimization; inventory helpers require assertions')
    sys.path.insert(0, str(args.vendor_tools))
    import build_vendor as portable
    from build_policy import transform
    ih = portable.ih
    source, output = args.stock_vendor, args.output
    ih.validate_paths(source, output)
    ih.validate_pin(source, 452378624, SOURCE_SHA)
    if source.is_symlink():
        raise ValueError('Stock source cannot be a symlink')
    if args.key.is_symlink() or not args.key.is_file() or args.key.stat().st_mode & 0o077:
        raise ValueError('Signing key must be a private regular file')
    if digest(args.avbtool.read_bytes()) != '69783733ce5e198317b02a5567cc356e898c891de872f58a963e9d5c082973c6':
        raise ValueError('Unreviewed avbtool')
    replacements = {}
    for name, pin in KEYMAPS.items():
        raw = (args.keymaps / Path(name).name).read_bytes()
        if digest(raw) != pin:
            raise ValueError('Stock keymap hash differs: ' + name)
        replacements[name] = raw
    for name, pin in POLICIES.items():
        raw = (args.policy / name).read_bytes()
        if digest(raw) != pin:
            raise ValueError('Generated policy payload differs: ' + name)
        replacements['/etc/selinux/' + name] = raw
    os.umask(0o077)
    output.mkdir(mode=0o700, exist_ok=False)
    ih.D, ih.E = str(args.debugfs), str(args.e2fsck)
    ih.RUN_ENV = dict(os.environ, LC_ALL='C', TZ='UTC')
    commands = []
    def run(argv):
        p = subprocess.run(list(map(str, argv)), text=True, capture_output=True,
                           timeout=900, env=ih.RUN_ENV)
        commands.append(dict(argv=list(map(str, argv)), returncode=p.returncode,
                             stdout=p.stdout, stderr=p.stderr))
        (output / 'commands.json').write_text(json.dumps(commands, indent=2) + '\n')
        if p.returncode:
            raise ValueError('Command failed: ' + p.stdout + p.stderr)
        return p.stdout
    before = ih.inventory(source, output / 'tree-before.json')
    deltas = json.loads((HERE / 'vendor-source-deltas.json').read_text())
    for name, entry in deltas.items():
        extracted = output / ('original-' + Path(name).name)
        ih.batch(source, ['dump ' + ih.quote(name) + ' ' + ih.quote(str(extracted))])
        raw = transform(extracted.read_bytes(), entry)
        if name == portable.FSTAB:
            raw = portable.transform_fstab(raw)
        replacements[name] = raw
    image = output / 'vendor.img'
    with source.open('rb') as inp, image.open('xb') as dst:
        left = STOCK_FS
        while left:
            raw = inp.read(min(left, 4*1024**2))
            if not raw:
                raise ValueError('Short stock filesystem')
            dst.write(raw)
            left -= len(raw)
        dst.truncate(FS)
    run([args.resize2fs, '-f', image, str(FS // 4096)])
    added = json.loads((HERE / 'added-metadata.json').read_text())
    expected = copy.deepcopy(before)
    expected['/']['links'] += 1
    expected.update(added)
    operations = []
    for name in sorted(added, key=lambda p: (p.count('/'), p)):
        if added[name]['type'] == 'directory':
            operations.append('mkdir ' + ih.quote(name))
    for number, (name, raw) in enumerate(replacements.items()):
        payload = output / ('payload-' + str(number))
        payload.write_bytes(raw)
        if name in before:
            operations.append('rm ' + ih.quote(name))
        operations.append('write ' + ih.quote(str(payload)) + ' ' + ih.quote(name))
        expected[name]['size'] = len(raw)
        expected[name]['content_sha256'] = digest(raw)
    # Restore ownership, modes, labels and all four timestamps after directory writes.
    for name in sorted(set(replacements) | set(added) | {'/', '/etc', '/etc/init/hw', '/etc/selinux'}, reverse=True):
        entry = expected[name]
        operations += ['set_inode_field ' + ih.quote(name) + ' mode 0' + format((0o40000 if entry['type']=='directory' else 0o100000) | int(entry['permissions'], 8), 'o'),
                       'set_inode_field ' + ih.quote(name) + ' uid ' + str(entry['uid']),
                       'set_inode_field ' + ih.quote(name) + ' gid ' + str(entry['gid'])]
        for row in entry['timestamps_debugfs']:
            field, value = row.split(': ', 1)
            seconds, extra = value.split(' -- ', 1)[0].split(':')
            operations += ['set_inode_field ' + ih.quote(name) + ' ' + field + ' ' + seconds,
                           'set_inode_field ' + ih.quote(name) + ' ' + field + '_extra 0x' + extra]
        for attr in entry['xattrs']:
            operations.append('ea_set ' + ih.quote(name) + ' ' + ih.quote(attr['name']) + ' ' + attr['debugfs_value'])
    ih.batch(image, operations, write=True)
    run([args.e2fsck, '-fn', image])
    after = ih.inventory(image, output / 'tree-after.json')
    if set(after) != set(expected):
        raise ValueError('Unexpected path changes')
    for name in expected:
        if normalize(expected[name]) != normalize(after[name]):
            raise ValueError('Unexpected content or metadata: ' + name)
    prefix = ih.sha(image)
    avb = [sys.executable, args.avbtool]
    run([*avb, 'add_hashtree_footer', '--image', image, '--partition_size', str(SIZE),
         '--partition_name', 'vendor', '--hash_algorithm', 'sha256', '--block_size', '4096',
         '--do_not_generate_fec', '--algorithm', 'SHA256_RSA2048', '--key', args.key,
         '--salt', SALT, '--rollback_index', '0', '--rollback_index_location', '0', '--flags', '0'])
    if ih.sha(image, FS) != prefix or image.stat().st_size != SIZE:
        raise ValueError('Signing changed filesystem bytes or output size')
    settings = portable.parse_avb(image)
    if settings['properties'] or settings['salt'] != SALT or settings['rollback_index'] or settings['flags'] or settings['location']:
        raise ValueError('Unexpected AVB settings')
    run([*avb, 'verify_image', '--image', image, '--key', args.key])
    ih.validate_pin(source, 452378624, SOURCE_SHA)
    report = dict(vendor_sha256=ih.sha(image), source_sha256=SOURCE_SHA,
                  changed_paths=sorted(replacements), added_paths=sorted(added),
                  content_and_metadata_verified=True, filesystem_layout_reproduced=False,
                  filesystem_bytes=FS, container_bytes=SIZE,
                  no_device_actions=True, status='OFFLINE CANDIDATE; PHONE BOOT UNVERIFIED',
                  boot_chain_requirement='Unlocked bootloader; never relock')
    (output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ['stock-vendor', 'keymaps', 'policy', 'key', 'avbtool', 'vendor-tools',
                 'output', 'debugfs', 'e2fsck', 'resize2fs']:
        parser.add_argument('--' + name, type=Path, required=True)
    try:
        print(json.dumps(build(parser.parse_args()), indent=2))
    except (ValueError, OSError) as error:
        parser.exit(1, str(error) + '\n')
