#!/usr/bin/env python3
"""Assemble a diagnostic-only derivative of the inspected Google guest pair."""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

import prepare_google_legacy_guest as base
from build_google_vndk_draft import timestamps
from integrate_google_system_policy30 import replacement_commands
from inventory_candidate_product import quote, split_batch
from prepare_early_log_payload import INIT_SHA256, SERVICE, patch_init

SPECS = {
    'system': (3288334336, 3221225472, '90366c4ca8b221dca484e0970abf3e1eee16a9af710b72d3df6a5544f321ae49'),
    'vendor': (536870912, 503316480, 'ef2688dccc5dfcf760884581b9a7ca03b74175b28ed079995690763d138b0bed'),
}
INVENTORIES = {
    'system': '5ecfdd3a5151357ddb3beebbc31ba2655c6caea3fda2c564ac786d65aafdde73',
    'vendor': 'd827d8a4688f47d03e96471577daac927953f8ef842ae70347baa5eabbca4716',
}
OLD_POLICY_SHA = 'b09b39144e2369b7a3213239777a2349acac220bbd881351efee9ab225510b92'
OLD_CONTEXTS_SHA = '85175ed802b5661b44ba7ffff5e820e34dcbcbf9d8cbec799a5a1853499941bb'
HELPER_SHA = '0a77f154e78cd78801d3c3f8128a69dabdd1693de533cbf07e77915d35cc1d09'
POLICY_SHA = '9c9ef476a17c78ee1c5762c42050bdcc270b975396d3cb1991bd4c5a7bc19384'
DEPLOYMENT = (
    ('system', '/system/etc/selinux/plat_sepolicy.cil', 'plat_sepolicy.cil',
     'f6422dd5853e815d340f2e9c4dcba2bb1016b55ffc2a073fc916ac23dfe66fc2',
     '73aeaf4f77a6455d0892e7bdf7ab5065ef629eb9956d89031a2a56e2ce33baa7'),
    ('system', '/system/etc/selinux/plat_sepolicy_and_mapping.sha256', 'plat_sepolicy_and_mapping.sha256',
     'df3522a9b1a43d3ee2810f1b697f272a776623353f768e2d5003d747bd63305e',
     'db2036bcc79c3d07fcda9a7824bd95e6ec6b6a5a332d1024aae5b8c42c060bc8'),
    ('vendor', '/etc/selinux/plat_pub_versioned.cil', 'plat_pub_versioned.cil',
     '08e8f20eeb57eb9d7033b0b1bbcd8315a4e2d509a500b6ea94f334a2327ce5fc',
     '76234e88b3bd10224c7ec5a5c9e64a078fd6a23bdd0bce309d5bbe780f95f809'),
    ('vendor', '/etc/selinux/vendor_sepolicy.cil', 'vendor_sepolicy.cil',
     '8ab247dd60da8544f7e92be8fb013bd8fd31c1e4d4b2e9714310446de9ddf298',
     '166e80022bf7ff521733ff10efe8ecc8f69c2046b222c6b8d82ba26c3d7da18f'),
    ('vendor', '/etc/selinux/precompiled_sepolicy.plat_sepolicy_and_mapping.sha256',
     'precompiled_sepolicy.plat_sepolicy_and_mapping.sha256',
     'df3522a9b1a43d3ee2810f1b697f272a776623353f768e2d5003d747bd63305e',
     'db2036bcc79c3d07fcda9a7824bd95e6ec6b6a5a332d1024aae5b8c42c060bc8'),
    ('vendor', '/etc/selinux/precompiled_sepolicy', 'precompiled_sepolicy', OLD_POLICY_SHA, POLICY_SHA),
)
CONTEXTS = (b'/system/bin/titan-diag u:object_r:titan_diag_exec:s0\n'
            b'/metadata/titan-pocket-diag(/.*)? u:object_r:titan_diag_metadata_file:s0\n')


def digest(data):
    return hashlib.sha256(data).hexdigest()


def add_contexts(data):
    if digest(data) != OLD_CONTEXTS_SHA or not data.endswith(b'\n'):
        raise ValueError('Unexpected original file contexts')
    if b'titan-diag' in data or b'titan-pocket-diag' in data:
        raise ValueError('Diagnostic contexts already exist')
    return data + CONTEXTS


def added_item(template, path, data, *, executable=False):
    item = copy.deepcopy(template)
    if item['type'] != 'regular' or item['links'] != 1:
        raise ValueError('Expected unique regular metadata template')
    label = 'titan_diag_exec' if executable else 'system_file'
    item.update(permissions='0755' if executable else '0644', uid=0, gid=0,
                size=len(data), sha256=digest(data), same_inode_paths=[path],
                xattrs={'security.selinux': ('u:object_r:' + label + ':s0\0').encode().hex()})
    return item


def policy_payloads(deployment):
    result = {'system': {}, 'vendor': {}}
    for partition, path, filename, _, expected in DEPLOYMENT:
        data = (deployment / filename).read_bytes()
        if digest(data) != expected:
            raise ValueError('Policy deployment differs from reviewed pin: ' + filename)
        result[partition][path] = data
    return result


def prepare(system, vendor, payload, deployment, output):
    os.umask(0o077)
    base.private_directory(output.parent)
    if output.exists() or output.is_symlink():
        raise ValueError('Existing build state; reconcile rather than retry')
    policies = policy_payloads(deployment)
    helper = (payload / 'titan-diag').read_bytes()
    if digest(helper) != HELPER_SHA or (payload / 'titan-diag.rc').read_bytes() != SERVICE:
        raise ValueError('Unexpected reviewed kernel recorder payload')
    roots = {'system': system, 'vendor': vendor}
    images = {name: root / name / (name + '.img') for name, root in roots.items()}
    snapshots = {name: base.check_source(image, SPECS[name]) for name, image in images.items()}
    required = sum(s.st_blocks * 512 for s in snapshots.values()) + 256 * 1024**2 + base.RESERVE_BYTES
    if shutil.disk_usage(output.parent).free < required:
        raise ValueError('Insufficient image/scratch capacity above disk reserve')
    before = {}
    for name, root in roots.items():
        raw = (root / name / 'after/inventory.json').read_bytes()
        if digest(raw) != INVENTORIES[name]:
            raise ValueError('Unexpected baseline inventory: ' + name)
        before[name] = json.loads(raw)
    for partition, path, _, expected, _ in DEPLOYMENT:
        if before[partition][path]['sha256'] != expected:
            raise ValueError('Policy source inventory differs from reviewed baseline: ' + path)
    mapping = base.read_file(images['system'], '/system/etc/selinux/mapping/202604.cil')
    platform = '/system/etc/selinux/plat_sepolicy.cil'
    old_sidecar = base.read_file(images['system'], '/system/etc/selinux/plat_sepolicy_and_mapping.sha256')
    if old_sidecar != (digest(base.read_file(images['system'], platform) + mapping) + '\n').encode():
        raise ValueError('Actual original platform hash recipe differs')
    new_sidecar = (digest(policies['system'][platform] + mapping) + '\n').encode()
    if policies['system']['/system/etc/selinux/plat_sepolicy_and_mapping.sha256'] != new_sidecar:
        raise ValueError('New source CIL does not match platform sidecar')
    if policies['vendor']['/etc/selinux/precompiled_sepolicy.plat_sepolicy_and_mapping.sha256'] != new_sidecar:
        raise ValueError('New platform/precompiled sidecars disagree')
    output.mkdir(mode=0o700)
    report = {'scope': 'Early kernel diagnostics only on current Google QPR1 guest; not CP2A or a boot repair',
              'policy_sha256': POLICY_SHA, 'sources': SPECS, 'artifacts': {},
              'runtime_gaps': ['Actual precompiled-policy selection and recorder transition unverified',
                               'Actual kernel access, persistence and early coverage unverified'],
              'policy_loading': 'Merged source CIL and matching platform/precompiled sidecars included; ordinary fallback declares recorder types, runtime legacy-netlink compatibility unverified. Alternate userdebug policy must not be selected.'}
    (output / 'preparation-intent.json').write_text(json.dumps(report, indent=2))
    for name, source in images.items():
        work = output / name
        work.mkdir(mode=0o700)
        tree = before[name]
        additions = {}
        if name == 'system':
            init = base.read_file(source, '/system/etc/init/hw/init.rc')
            if digest(init) != INIT_SHA256:
                raise ValueError('Init baseline changed')
            patched = patch_init(init)
            if patched != (payload / 'init.rc').read_bytes():
                raise ValueError('Staged init differs from validated transform')
            replacements = {'/system/etc/init/hw/init.rc': patched,
                            '/system/etc/selinux/plat_file_contexts': add_contexts(base.read_file(source, '/system/etc/selinux/plat_file_contexts'))}
            replacements.update(policies[name])
            additions = {'/system/bin/titan-diag': helper, '/system/etc/init/titan-diag.rc': SERVICE}
        else:
            replacements = policies[name]
        for path in replacements:
            if digest(base.read_file(source, path)) != tree[path]['sha256']:
                raise ValueError('Changed-file source readback differs from inventory')
        expected = base.expected_inventory(tree, replacements)
        for path, data in additions.items():
            if path in tree:
                raise ValueError('Added path already exists')
            expected[path] = added_item(tree['/system/etc/init/hw/init.rc'], path, data,
                                        executable=path == '/system/bin/titan-diag')
        candidate = work / (name + '.ext4')
        base.run(['cp', '--sparse=always', '--reflink=never', '--', source, candidate])
        with candidate.open('r+b') as stream:
            stream.truncate(SPECS[name][1])
        if base.sha(candidate) != base.sha(source, SPECS[name][1]):
            raise ValueError('Filesystem copy differs')
        base.replace_files(candidate, tree, replacements, work)
        if additions:
            commands = []
            for number, (path, data) in enumerate(additions.items(), 100):
                commands += replacement_commands(path, data, expected[path], work, number)
                parent = str(Path(path).parent)
                commands += timestamps(parent, tree[parent])
            result = subprocess.run(['/usr/sbin/debugfs', '-w', '-f', '/dev/stdin', str(candidate)],
                                    input=('\n'.join(commands) + '\n').encode(), capture_output=True, timeout=120)
            split_batch(commands, result.stdout.decode(), result.stderr.decode(), result.returncode)
        checked = base.run(['/usr/sbin/e2fsck', '-fn', candidate])
        (work / 'e2fsck.txt').write_bytes(checked.stdout + checked.stderr)
        after = base.logical_inventory(candidate, work / 'after')
        if after != expected:
            changed = sorted(p for p in set(after) | set(expected) if after.get(p) != expected.get(p))
            (work / 'unexpected-delta.json').write_text(json.dumps(changed))
            raise ValueError('Unexpected content/metadata delta')
        for path, data in {**replacements, **additions}.items():
            if base.read_file(candidate, path) != data:
                raise ValueError('Candidate payload readback mismatch')
        if name == 'vendor':
            report['vendor_config_audit'] = base.audit_vendor_configs(candidate, after)
        report['artifacts'][name] = {'filesystem_sha256': base.sha(candidate), 'filesystem_bytes': SPECS[name][1],
                                    'partition_bytes': SPECS[name][0], 'source_sha256': SPECS[name][2],
                                    'changed_paths': sorted(replacements), 'added_paths': sorted(additions),
                                    'all_other_inventoried_contents_metadata_unchanged': True}
    for name, source in images.items():
        now, old = base.check_source(source, SPECS[name]), snapshots[name]
        if (now.st_ino, now.st_mtime_ns, now.st_ctime_ns) != (old.st_ino, old.st_mtime_ns, old.st_ctime_ns):
            raise ValueError('Source identity changed')
    if shutil.disk_usage(output.parent).free < base.RESERVE_BYTES:
        raise ValueError('Disk reserve lost')
    (output / 'prepared.json').write_text(json.dumps(report, indent=2) + '\n')
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for field in ('system', 'vendor', 'payload', 'deployment', 'output'):
        parser.add_argument('--' + field, type=Path, required=True)
    print(json.dumps(prepare(**vars(parser.parse_args())), indent=2))
