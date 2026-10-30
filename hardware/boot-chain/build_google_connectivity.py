#!/usr/bin/env python3
"""Build a pinned offline Google Connectivity diagnostic APEX; no device access.

Only eight reviewed words in three payload files change. Original filesystem
metadata and other file bytes stay identical. This does not prove networking.
Task-owned inputs/output parents must have no concurrent writers.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import zipfile

from build_connectivity_apex import (AVB_SHA, JAVA, PRESERVING_SIGNER, SIGNER, TOOLS,
                                     elf_defs, rebuild_zip, verify_zip)
from build_dsu_system import regular, runner
from inventory_candidate_product import split_batch
from patch_google_network_gates import patch_native

APEX_SHA = 'd9364b1501fde40218a4e6e1f21009dd802ff4e8ff53941a538c3aa7d645afa3'
PAYLOAD_SHA = '8eaf8dfa0b895f545f678e298093b1eee4fb1bdf67843f4df4595614420ec1c4'
NETD_SHA = '44151790d74e159bc7c3bc3c06a1219a993a153ff4cd7d44d7da7998193bccf2'
PAYLOAD_BYTES = 34865152
DATA_BYTES = 34582528
FILES = {'netbpfload': '/bin/netbpfload',
         'libnetd_updatable.so': '/lib64/libnetd_updatable.so',
         'netd.o': '/etc/bpf/mainline/netd.o'}
EDITS = (
    (96 * 4096 + 0x538, '29010034', '09000014'),
    (96 * 4096 + 0x570, '2b010036', '09000014'),
    (96 * 4096 + 0x5a4, 'ca000036', '06000014'),
    (96 * 4096 + 0x5cc, '28010036', '09000014'),
    (7354 * 4096 + 0x1d4, '88080036', '44000014'),
    (7354 * 4096 + 0x2f8, '881c0036', 'e4000014'),
    (755 * 4096 + 0x600, 'ac0d0000', '00000100'),
    (755 * 4096 + 0xba0, 'ac0d0000', '00000100'),
)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def patch_payload(original):
    require(len(original) == PAYLOAD_BYTES and sha(original) == PAYLOAD_SHA, 'Payload pin mismatch')
    result = bytearray(original)
    for offset, old, new in EDITS:
        require(original[offset:offset + 4] == bytes.fromhex(old), 'Wrong original instruction or field')
        result[offset:offset + 4] = bytes.fromhex(new)
    allowed = {offset + index for offset, old, new in EDITS
               for index, (a, b) in enumerate(zip(bytes.fromhex(old), bytes.fromhex(new))) if a != b}
    changed = {index for index, (a, b) in enumerate(zip(original, result)) if a != b}
    require(changed == allowed and len(changed) == 23, 'Unexpected payload byte delta')
    return bytes(result)


def patch_netd(original):
    require(sha(original) == NETD_SHA, 'BPF object pin mismatch')
    before = elf_defs(original)
    expected = {'ingress_stats_4_9_t_def': 0x1e600, 'egress_stats_4_9_t_def': 0x1eba0}
    result = bytearray(original)
    for name, offset in expected.items():
        require(before[name]['offset'] + 32 == offset and before[name]['max_api'] == 3500,
                'Unexpected legacy BPF definition')
        struct.pack_into('<I', result, offset, 65536)
    after = elf_defs(result)
    require(before.keys() == after.keys() and len(before) == 47, 'BPF definitions changed')
    for name in before:
        old, new = before[name], after[name]
        wanted = dict(old)
        if name in expected:
            wanted.update(max_api=65536, bytes_sha256=new['bytes_sha256'])
        require(wanted == new, 'Unapproved BPF definition change')
    return bytes(result), {'count': len(before), 'changed': sorted(expected),
                           'old_max_api': 3500, 'new_max_api': 65536,
                           'runtime_load_tested': False}


def build(source, avbtool, output):
    regular(source)
    regular(avbtool)
    original_apex = source.read_bytes()
    require(sha(original_apex) == APEX_SHA, 'Original APEX pin mismatch')
    require(sha(avbtool.read_bytes()) == AVB_SHA, 'AVB tool pin mismatch')
    with zipfile.ZipFile(source) as archive:
        require(len(archive.namelist()) == len(set(archive.namelist())), 'Duplicate ZIP entries')
        original = archive.read('apex_payload.img')
    patched = patch_payload(original)
    os.umask(0o077)
    output.mkdir(mode=0o700, exist_ok=False)
    run = runner(output)
    avb = ['python3', avbtool]
    original_image = output / 'original-payload.img'
    original_image.write_bytes(original)
    signature = run(SIGNER + ['verify', '--verbose', '--min-sdk-version', '29',
                              '--max-sdk-version', '37', source]).stdout
    require('Verified using v3 scheme (APK Signature Scheme v3): true' in signature,
            'Original APKv3 signature not verified')
    run(avb + ['verify_image', '--image', original_image])
    inode_count = struct.unpack_from('<I', original, 1024)[0]
    require(inode_count == 96, 'Unexpected payload inode count')
    commands = [f'blocks <{inode}>' for inode in range(1, inode_count + 1)]
    raw = run(['/usr/sbin/debugfs', '-f', '/dev/stdin', original_image],
              stdin='\n'.join(commands) + '\n')
    sections = split_batch(commands, raw.stdout, raw.stderr, raw.returncode)
    owners = {96: [], 7354: [], 755: []}
    for inode, text in enumerate(sections, 1):
        require(re.fullmatch(r'[\d\s]*', text) is not None, 'Unexpected block-list output')
        for block in map(int, text.split()):
            if block in owners:
                owners[block].append(inode)
    require(owners == {96: [16], 7354: [82], 755: [27]}, 'Edited blocks have unexpected owners')
    info = run(avb + ['info_image', '--image', original_image]).stdout
    match = re.search(r'^\s*Salt:\s*([0-9a-f]{64})\s*$', info, re.M)
    require(match is not None, 'Missing original salt')
    salt = match[1]
    require(struct.unpack_from('>Q', original, len(original) - 52)[0] == DATA_BYTES,
            'Unexpected original AVB data size')
    image = output / 'patched-stale-avb.img'
    image.write_bytes(patched)
    reports = {}
    for name, path in FILES.items():
        old_path, new_path = output / ('original-' + name), output / ('modified-' + name)
        run(['/usr/sbin/debugfs', '-R', f'dump {path} {old_path}', original_image])
        run(['/usr/sbin/debugfs', '-R', f'dump {path} {new_path}', image])
        if name == 'netd.o':
            expected, report = patch_netd(old_path.read_bytes())
        else:
            expected, report = patch_native(name, old_path.read_bytes())
        require(new_path.read_bytes() == expected, 'Logical file readback mismatch: ' + name)
        reports[name] = report
    run(['/usr/sbin/e2fsck', '-fn', image])
    keys = output / 'keys'
    keys.mkdir(mode=0o700)
    payload_key, container_key = keys / 'payload.pem', keys / 'container.pem'
    for key in (payload_key, container_key):
        run(['openssl', 'genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:4096', '-out', key])
    der, cert = keys / 'container.pk8', keys / 'container.x509.pem'
    run(['openssl', 'pkcs8', '-topk8', '-nocrypt', '-in', container_key, '-outform', 'DER', '-out', der])
    run(['openssl', 'req', '-new', '-x509', '-key', container_key, '-sha256', '-days', '3650',
         '-subj', '/CN=Titan Google17 offline diagnostic/', '-out', cert])
    run(avb + ['erase_footer', '--image', image])
    require(image.read_bytes() == patched[:DATA_BYTES], 'AVB erasure changed filesystem')
    run(avb + ['add_hashtree_footer', '--image', image, '--partition_size', '0',
               '--hash_algorithm', 'sha256', '--salt', salt, '--do_not_generate_fec',
               '--algorithm', 'SHA256_RSA4096', '--key', payload_key,
               '--prop', 'apex.key:com.android.tethering'])
    payload = image.read_bytes()
    require(len(payload) == PAYLOAD_BYTES and payload[:DATA_BYTES] == patched[:DATA_BYTES],
            'Signed payload layout or filesystem changed')
    pub = output / 'apex_pubkey'
    run(avb + ['extract_public_key', '--key', payload_key, '--output', pub])
    run(avb + ['verify_image', '--image', image, '--key', payload_key])
    run(['/usr/sbin/e2fsck', '-fn', image])
    unsigned, candidate = output / 'unsigned.apex', output / 'candidate.partial.apex'
    rebuild_zip(source, unsigned, payload, pub.read_bytes())
    helper = output / 'PreserveSign.java'
    helper.write_text(PRESERVING_SIGNER)
    run([JAVA, '-XX:ActiveProcessorCount=1', '-Xmx128m', '-cp', TOOLS / 'share/java/apksig.jar',
         helper, der, cert, unsigned, candidate])
    signature = run(SIGNER + ['verify', '--verbose', '--print-certs', '--min-sdk-version', '29',
                              '--max-sdk-version', '37', candidate]).stdout
    require('Verified using v3 scheme (APK Signature Scheme v3): true' in signature,
            'Derivative APKv3 signature not verified')
    zip_report = verify_zip(source, candidate, payload, pub.read_bytes())
    require(source.read_bytes() == original_apex, 'Original APEX changed')
    final = output / 'com.android.tethering.apex'
    candidate.rename(final)
    report = {'status': 'OFFLINE DIAGNOSTIC APEX; NOT BOOT-TESTED OR INSTALL READY',
              'source_sha256': APEX_SHA, 'output_sha256': sha(final.read_bytes()),
              'payload_sha256': sha(payload), 'payload_bytes': len(payload),
              'filesystem_changed_bytes': 23, 'files': reports, 'zip': zip_report,
              'edited_block_owners': owners,
              'original_unchanged': True, 'no_device_access': True,
              'keys': 'Task-private output/keys; not repository; new built-in APEX keys only',
              'limits': ['Not a same-key Google APEX update', 'APEX activation and namespace untested',
                         'No verifier/load/attachment or functional networking proof',
                         'SELinux, mounts and diagnostic access remain separate integration work']}
    (output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('source', 'avbtool', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    report = build(args.source.absolute(), args.avbtool.absolute(), args.output.absolute())
    print(json.dumps({key: report[key] for key in ('status', 'output_sha256', 'filesystem_changed_bytes')}, indent=2))
