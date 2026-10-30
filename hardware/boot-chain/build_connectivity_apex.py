#!/usr/bin/env python3
"""Offline, pinned Connectivity APEX derivative. Never installs or touches a device."""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import zipfile

SOURCE = Path('/tmp/opencode/bpf-work/com.android.tethering.apex')
WORK = Path('/tmp/opencode/titan-connectivity-apex-v1')
AVB = Path('/tmp/opencode/titan-pocket-inspection/tools/avbtool-android13.py')
AVB_SHA = '69783733ce5e198317b02a5567cc356e898c891de872f58a963e9d5c082973c6'
SOURCE_SHA = 'df925e0be47c94c4c2b0e07d66b67783709654c9a34bf00bc76c14231091a145'
PAYLOAD_SHA = '9f78acea28780ac82cf462660b6cd6bf60e9eb13e15a888ba5db1baeaf43a1da'
NETD_SHA = '007959569daeae586b6ee617a6d9494e7c74c05e1c111c3221383880becc2677'
SIZE = 36814848
DATA_SIZE = 36515840
NETD_OFFSET = 0x2d0000
NETD_SIZE = 544992
FIELDS = {'ingress_stats_4_9_t_def': 0x302370,
          'egress_stats_4_9_t_def': 0x3029c4}
SALT = '07ef9904b69427951e0ccfcd9fa86a7b962e3b52254d93e23e62e0c045a3947b'
TOOLS = Path('/tmp/opencode/titan-apk-tools-v1/root/usr')
JAVA = TOOLS / 'lib/jvm/java-21-openjdk-arm64/bin/java'
SIGNER = [str(JAVA), '-XX:ActiveProcessorCount=1', '-Xmx128m', '-cp',
          f'{TOOLS}/share/java/apksigner.jar:{TOOLS}/share/java/apksig.jar',
          'com.android.apksigner.ApkSignerTool']
PRESERVING_SIGNER = '''import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.security.cert.*;
import java.security.spec.*;
import java.util.*;
import java.lang.reflect.*;
import com.android.apksig.ApkSigner;
import com.android.apksig.ApkSignerEngine;
import com.android.apksig.DefaultApkSignerEngine;
class PreserveSign {
  public static void main(String[] args) throws Exception {
    PrivateKey key = KeyFactory.getInstance("RSA").generatePrivate(
      new PKCS8EncodedKeySpec(Files.readAllBytes(Path.of(args[0]))));
    X509Certificate cert;
    try (InputStream in = Files.newInputStream(Path.of(args[1]))) {
      cert = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(in);
    }
    DefaultApkSignerEngine.SignerConfig config = new DefaultApkSignerEngine.SignerConfig.Builder(
      "TITAN", key, List.of(cert)).build();
    ApkSignerEngine engine = new DefaultApkSignerEngine.Builder(List.of(config), 29)
      .setV1SigningEnabled(false).setV2SigningEnabled(false).setV3SigningEnabled(true).build();
    Set<String> retained = Set.of("META-INF/CERT.SF", "META-INF/CERT.RSA", "META-INF/MANIFEST.MF");
    ApkSignerEngine preserving = (ApkSignerEngine) Proxy.newProxyInstance(
      ApkSignerEngine.class.getClassLoader(), new Class<?>[]{ApkSignerEngine.class},
      (proxy, method, params) -> {
        if (method.getName().equals("inputJarEntry") && retained.contains((String) params[0])) {
          return new ApkSignerEngine.InputJarEntryInstructions(
            ApkSignerEngine.InputJarEntryInstructions.OutputPolicy.OUTPUT);
        }
        try { return method.invoke(engine, params); }
        catch (InvocationTargetException e) { throw e.getCause(); }
      });
    new ApkSigner.Builder(preserving)
      .setInputApk(new File(args[2])).setOutputApk(new File(args[3])).build().sign();
  }
}
'''


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def pinned(data, expected):
    require(sha(data) == expected, 'SHA-256 pin mismatch')


def run(args, log=None, allowed=(0,)):
    args = list(map(str, args))
    p = subprocess.run(args, capture_output=True, text=True, timeout=180)
    item = dict(command=args, exit=p.returncode, stdout=p.stdout, stderr=p.stderr)
    if log is not None:
        log.append(item)
    require(p.returncode in allowed, f'command failed: {args}: {p.stderr} {p.stdout}')
    return p.stdout


def changed_offsets(before, after):
    require(len(before) == len(after), 'length changed')
    return [n for n, (a, b) in enumerate(zip(before, after)) if a != b]


def expected_delta():
    old, new = struct.pack('<I', 3500), struct.pack('<I', 65536)
    return sorted(offset + n for offset in FIELDS.values()
                  for n in range(4) if old[n] != new[n])


def patch_payload(data):
    require(len(data) == SIZE, 'wrong payload length')
    for offset in FIELDS.values():
        require(struct.unpack_from('<I', data, offset)[0] == 3500, 'wrong max_api field')
    pinned(data, PAYLOAD_SHA)
    result = bytearray(data)
    for offset in FIELDS.values():
        struct.pack_into('<I', result, offset, 65536)
    require(changed_offsets(data, result) == expected_delta(), 'unexpected byte delta')
    require(len(expected_delta()) == 6, 'expected exactly six differing bytes')
    return bytes(result)


def verify_fs_delta(original, modified):
    require(len(original) == len(modified) == SIZE, 'wrong payload size')
    require(changed_offsets(original[:DATA_SIZE], modified[:DATA_SIZE]) == expected_delta(),
            'filesystem differs outside the two fields')


def elf_defs(data):
    require(data[:6] == b'\x7fELF\x02\x01', 'expected ELF64 little endian')
    require(struct.unpack_from('<H', data, 18)[0] == 247, 'expected EM_BPF')
    start = struct.unpack_from('<Q', data, 40)[0]
    width, count, names_index = struct.unpack_from('<HHH', data, 58)
    require(width == 64 and start + width * count <= len(data), 'bad section table')
    sections = [struct.unpack_from('<IIQQQQIIQQ', data, start + n * width)
                for n in range(count)]
    names_sec = sections[names_index]
    names = data[names_sec[4]:names_sec[4] + names_sec[5]]
    def string(table, offset):
        end = table.find(b'\0', offset)
        require(0 <= offset < len(table) and end >= 0, 'bad ELF string')
        return table[offset:end].decode()
    result = {}
    for section in sections:
        if section[1] != 2:
            continue
        require(section[9] == 24 and section[5] % 24 == 0, 'bad symbol table')
        strings_sec = sections[section[6]]
        strings = data[strings_sec[4]:strings_sec[4] + strings_sec[5]]
        for pos in range(section[4], section[4] + section[5], 24):
            name, info, _, index, value, size = struct.unpack_from('<IBBHQQ', data, pos)
            if not index or index >= count or info & 15 != 1:
                continue
            target = sections[index]
            if string(names, target[0]) != '.android_progs':
                continue
            require(size == 180 and value + size <= target[5], 'bad bpf_prog_def')
            offset = target[4] + value
            values = struct.unpack_from('<9I', data, offset)
            symbol = string(strings, name)
            require(symbol not in result, 'duplicate program definition')
            result[symbol] = dict(offset=offset, type=values[0], attach=values[1],
                                  min_kver=values[4], max_kver=values[5],
                                  optional=values[6], min_api=values[7], max_api=values[8],
                                  bytes_sha256=sha(data[offset:offset + size]))
    require(result, 'no program definitions')
    return result


def compare_defs(original, modified):
    before, after = elf_defs(original), elf_defs(modified)
    require(before.keys() == after.keys(), 'program definition inventory changed')
    changes = []
    for name, old in before.items():
        new = after[name]
        if old == new:
            continue
        require(name in FIELDS, 'unapproved program changed')
        require(old['offset'] + NETD_OFFSET + 32 == FIELDS[name], 'field offset mismatch')
        require(old['max_api'] == 3500 and new['max_api'] == 65536, 'wrong API change')
        require({k: v for k, v in old.items() if k not in ('max_api', 'bytes_sha256')} ==
                {k: v for k, v in new.items() if k not in ('max_api', 'bytes_sha256')},
                'another definition field changed')
        changes.append(dict(name=name, before=old, after=new))
    require({x['name'] for x in changes} == set(FIELDS), 'missing changes')
    require(changed_offsets(original, modified) ==
            [n - NETD_OFFSET for n in expected_delta()], 'other netd bytes changed')
    def eligible(defs):
        return sorted(name for name, d in defs.items()
                      if d['min_kver'] <= 0x040e0000 < d['max_kver']
                      and d['min_api'] <= 3700 < d['max_api'])
    gained = set(eligible(after)) - set(eligible(before))
    require(gained == set(FIELDS), 'unexpected kernel 4.14/API 3700 gate delta')
    return dict(count=len(before), changes=changes, before=before, after=after,
                gates=dict(kernel_encoded='0x040e0000', api_full=3700,
                           eligible_before=eligible(before), eligible_after=eligible(after),
                           newly_eligible=sorted(gained), runtime_load_tested=False))


def payload_offset(apex, entry):
    with apex.open('rb') as stream:
        stream.seek(entry.header_offset)
        local = stream.read(30)
    require(local[:4] == b'PK\x03\x04', 'bad ZIP local header')
    name_size, extra_size = struct.unpack_from('<HH', local, 26)
    return entry.header_offset + 30 + name_size + extra_size


def verify_zip(source, output, payload, pubkey):
    with zipfile.ZipFile(source) as old, zipfile.ZipFile(output) as new:
        names = old.namelist()
        require(len(set(names)) == len(names), 'duplicate ZIP entry')
        require(new.namelist() == names, 'ZIP entry inventory or order changed')
        require(new.testzip() is None, 'ZIP CRC failure')
        inventory = []
        for name in names:
            wanted = {'apex_payload.img': payload, 'apex_pubkey': pubkey}.get(name)
            if wanted is None:
                wanted = old.read(name)
            actual = new.read(name)
            require(actual == wanted, f'ZIP entry changed: {name}')
            inventory.append(dict(name=name, size=len(actual), sha256=sha(actual)))
        entry = new.getinfo('apex_payload.img')
        offset = payload_offset(output, entry)
        require(entry.compress_type == zipfile.ZIP_STORED and offset % 4096 == 0,
                'payload must be STORED and 4096 aligned')
        return dict(payload_offset=offset, entries=inventory)


def rebuild_zip(source, output, payload, pubkey):
    require(source.resolve() != output.resolve(), 'refuse overwrite source')
    with zipfile.ZipFile(source) as old, zipfile.ZipFile(output, 'w') as new:
        new.comment = old.comment
        for entry in old.infolist():
            info = copy.copy(entry)
            data = {'apex_payload.img': payload, 'apex_pubkey': pubkey}.get(entry.filename)
            if data is None:
                data = old.read(entry)
            if entry.filename == 'apex_payload.img':
                require(info.compress_type == zipfile.ZIP_STORED, 'compressed source payload')
                base = new.fp.tell() + 30 + len(info.filename.encode())
                length = (-base) % 4096
                if 0 < length < 4:
                    length += 4096
                info.extra = struct.pack('<HH', 0xcafe, length - 4) + b'\0' * (length - 4) if length else b''
            new.writestr(info, data)
    verify_zip(source, output, payload, pubkey)


def embedded_key(payload):
    require(payload[-64:-60] == b'AVBf', 'missing AVB footer')
    data_size, vbmeta, vbmeta_size = struct.unpack_from('>QQQ', payload, len(payload) - 52)
    require(data_size == DATA_SIZE and vbmeta == 36806656 and vbmeta_size == 2176,
            'AVB footer layout changed')
    require(payload[vbmeta:vbmeta + 4] == b'AVB0', 'missing vbmeta')
    auth_size = struct.unpack_from('>Q', payload, vbmeta + 12)[0]
    offset, size = struct.unpack_from('>QQ', payload, vbmeta + 64)
    require(size == 1032, 'not RSA4096 AVB key')
    start = vbmeta + 256 + auth_size + offset
    return payload[start:start + size]


def filesystem_check(image, log):
    data = image.read_bytes()
    require(struct.unpack_from('<H', data, 1024 + 56)[0] == 0xef53, 'not ext4')
    count = struct.unpack_from('<I', data, 1024)[0]
    require(count == 96, 'unexpected inode count')
    shared_flag = bool(struct.unpack_from('<I', data, 1024 + 100)[0] & 0x4000)
    require(shared_flag, 'expected original shared_blocks flag')
    owners, duplicates = {}, []
    for inode in range(1, count + 1):
        blocks = run(['/usr/sbin/debugfs', '-R', f'blocks <{inode}>', image])
        require(re.fullmatch(r'[\d\s]*', blocks) is not None, 'unexpected blocks output')
        for block in map(int, blocks.split()):
            if block in owners:
                duplicates.append((block, owners[block], inode))
            owners[block] = inode
    require(not duplicates, 'actual shared payload blocks found')
    check = run(['/usr/sbin/e2fsck', '-fn', image], log)
    return dict(shared_blocks_feature=shared_flag, inodes_scanned=count,
                allocated_blocks_scanned=len(owners), actual_shared_blocks=duplicates,
                e2fsck_exit=0, e2fsck_stdout=check)


def dump_objects(image, directory):
    directory.mkdir(exist_ok=True)
    run(['/usr/sbin/debugfs', '-R', f'rdump /etc/bpf {directory}', image])
    files = sorted(directory.rglob('*.o'))
    require(files, 'no BPF objects extracted')
    return {str(p.relative_to(directory)): p.read_bytes() for p in files}


def check_avb_info(text):
    for label, value in [('Image size', f'{SIZE} bytes'),
                         ('Original image size', f'{DATA_SIZE} bytes'),
                         ('VBMeta offset', '36806656'), ('VBMeta size', '2176 bytes'),
                         ('Algorithm', 'SHA256_RSA4096'), ('Tree Offset', str(DATA_SIZE)),
                         ('Tree Size', '290816 bytes'), ('FEC num roots', '0'),
                         ('FEC size', '0 bytes'), ('Hash Algorithm', 'sha256'), ('Salt', SALT)]:
        require(re.search(r'^\s*' + re.escape(label) + r':\s*' + re.escape(value) + r'\s*$',
                          text, re.M), f'wrong AVB field: {label}')
    require("Prop: apex.key -> 'com.android.tethering'" in text, 'missing apex.key')


def build(source=SOURCE, work=WORK):
    require(work == WORK, 'use the task-owned scratch directory only')
    require(not work.is_symlink(), 'scratch directory is a symlink')
    work.mkdir(mode=0o700, exist_ok=True)
    require(work.stat().st_uid == os.getuid(), 'scratch owned by another user')
    require(not source.resolve().is_relative_to(work.resolve()), 'source inside output directory')
    require(not any(p.is_symlink() for p in work.rglob('*')), 'scratch symlinks refused')
    os.chmod(work, 0o700)
    original_apex = source.read_bytes()
    pinned(original_apex, SOURCE_SHA)
    pinned(AVB.read_bytes(), AVB_SHA)
    log = []
    avb = ['python3', str(AVB)]
    with zipfile.ZipFile(source) as z:
        require(len(set(z.namelist())) == len(z.namelist()), 'duplicate ZIP entry')
        original = z.read('apex_payload.img')
        original_pubkey = z.read('apex_pubkey')
    patched = patch_payload(original)
    require(embedded_key(original) == original_pubkey, 'original key mismatch')
    original_image = work / 'original-payload.img'
    original_image.write_bytes(original)
    check_avb_info(run(avb + ['info_image', '--image', original_image], log))
    run(avb + ['verify_image', '--image', original_image], log)
    original_fs = filesystem_check(original_image, log)
    image = work / 'apex_payload.img'
    image.write_bytes(patched)
    keys = work / 'keys'
    keys.mkdir(mode=0o700, exist_ok=True)
    os.chmod(keys, 0o700)
    key, apk_pem = keys / 'payload.pem', keys / 'container.pem'
    for path in (key, apk_pem):
        require(not path.is_symlink(), 'key symlink refused')
        if not path.exists():
            run(['openssl', 'genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:4096',
                 '-out', path], log)
        os.chmod(path, 0o600)
    der, cert = keys / 'container.pk8', keys / 'container.x509.pem'
    if not der.exists():
        run(['openssl', 'pkcs8', '-topk8', '-nocrypt', '-in', apk_pem, '-outform', 'DER',
             '-out', der], log)
    if not cert.exists():
        run(['openssl', 'req', '-new', '-x509', '-key', apk_pem, '-sha256', '-days', '3650',
             '-subj', '/CN=Titan Pocket offline Connectivity experiment/', '-out', cert], log)
    for path in (der, cert):
        os.chmod(path, 0o600)
    run(avb + ['erase_footer', '--image', image], log)
    require(image.read_bytes() == patched[:DATA_SIZE], 'erase_footer changed filesystem')
    run(avb + ['add_hashtree_footer', '--image', image, '--partition_size', '0',
               '--hash_algorithm', 'sha256', '--salt', SALT, '--do_not_generate_fec',
               '--algorithm', 'SHA256_RSA4096', '--key', key,
               '--prop', 'apex.key:com.android.tethering'], log)
    payload = image.read_bytes()
    verify_fs_delta(original, payload)
    check_avb_info(run(avb + ['info_image', '--image', image], log))
    run(avb + ['verify_image', '--image', image, '--key', key], log)
    pub = work / 'apex_pubkey'
    run(avb + ['extract_public_key', '--key', key, '--output', pub], log)
    pubkey = pub.read_bytes()
    require(embedded_key(payload) == pubkey, 'bundled key != embedded AVB key')
    modified_fs = filesystem_check(image, log)
    old_objects = dump_objects(original_image, work / 'original-objects')
    new_objects = dump_objects(image, work / 'modified-objects')
    require(old_objects.keys() == new_objects.keys(), 'BPF inventory changed')
    netd_name = 'bpf/mainline/netd.o'
    netd = old_objects[netd_name]
    pinned(netd, NETD_SHA)
    require(netd == original[NETD_OFFSET:NETD_OFFSET + NETD_SIZE], 'netd not contiguous as pinned')
    require(new_objects[netd_name] == payload[NETD_OFFSET:NETD_OFFSET + NETD_SIZE], 'new netd offset changed')
    defs = compare_defs(netd, new_objects[netd_name])
    inventory = []
    for name, content in old_objects.items():
        if name != netd_name:
            require(content == new_objects[name], f'other BPF object changed: {name}')
        inventory.append(dict(name=name, original_sha256=sha(content),
                              modified_sha256=sha(new_objects[name]), size=len(content)))
    unsigned, output = work / 'unsigned.apex', work / 'candidate.apex'
    rebuild_zip(source, unsigned, payload, pubkey)
    helper = work / 'PreserveSign.java'
    helper.write_text(PRESERVING_SIGNER)
    run([str(JAVA), '-XX:ActiveProcessorCount=1', '-Xmx128m', '-cp',
         str(TOOLS / 'share/java/apksig.jar'), str(helper), str(der), str(cert),
         str(unsigned), str(output)], log)
    signature = run(SIGNER + ['verify', '--verbose', '--print-certs', '--min-sdk-version', '29',
                             '--max-sdk-version', '37', str(output)], log)
    require('Verified using v3 scheme (APK Signature Scheme v3): true' in signature,
            'v3 not verified')
    zip_info = verify_zip(source, output, payload, pubkey)
    pinned(source.read_bytes(), SOURCE_SHA)
    require(original_image.read_bytes() == original, 'original scratch payload modified')
    final = work / 'com.android.tethering.apex'
    output.replace(final)
    output = final
    return dict(schema='titan-pocket-connectivity-apex-build/1',
                scope='Offline only; no device, SSH, installation, flash, DSU or system image edits.',
                source=dict(path=str(source), sha256=SOURCE_SHA, size=len(original_apex)),
                output=dict(path=str(output), sha256=sha(output.read_bytes()), size=output.stat().st_size),
                payload=dict(path=str(image), sha256=sha(payload), size=SIZE, data_size=DATA_SIZE,
                             actual_filesystem_byte_delta=expected_delta(), differing_bytes=6,
                             original_sha256=PAYLOAD_SHA, pubkey_sha256=sha(pubkey)),
                original_filesystem=original_fs, modified_filesystem=modified_fs,
                program_definitions=defs, bpf_objects=inventory, zip=zip_info,
                tools=dict(avbtool_path=str(AVB), avbtool_sha256=AVB_SHA,
                           apksigner_sha256=sha((TOOLS / 'share/java/apksigner.jar').read_bytes()),
                           apksig_sha256=sha((TOOLS / 'share/java/apksig.jar').read_bytes())),
                key_directory=str(keys), private_keys_in_repository=False,
                packaging_notes=[
                    'Pinned avbtool 1.2 uses --partition_size 0 to avoid its conservative 64 KiB metadata reservation; final size and all footer offsets are checked against the original.',
                    'CLI apksigner strips original META-INF entries. apksig DefaultApkSignerEngine supplies v3 signing through a narrow inputJarEntry policy wrapper retaining exactly CERT.SF, CERT.RSA and MANIFEST.MF as data. Its advertised preservation flag throws UnsupportedOperationException.',
                    'All original ZIP entry data except apex_payload.img and apex_pubkey is identical, including inactive v1 metadata. Authoritative outer signature is the new verified v3 signer.',
                    'All 36515840 filesystem bytes match except six differing bytes spanning the two uint32 max_api fields; later bytes contain regenerated hashtree, vbmeta and footer.'],
                reproducibility='Retained keys and certificate reused; not yet measured.',
                commands=log,
                limitations=['Runtime APEX activation and Android 17 boot UNTESTED.',
                             'Linux 4.14 verifier/libbpf compatibility UNTESTED.',
                             'Network enforcement and UID-map population UNTESTED.',
                             'New keys are for a built-in system APEX, not a same-key data APEX update.',
                             'System-image integration is separate and not performed by this script.'])


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source', type=Path, default=SOURCE)
    p.add_argument('--work', type=Path, default=WORK)
    p.add_argument('--evidence', type=Path, required=True)
    p.add_argument('--reproduce', action='store_true',
                   help='Build twice with retained keys/certificate and compare artifact hashes')
    args = p.parse_args()
    require(args.evidence.resolve() ==
            (Path(__file__).resolve().parents[1] / 'evidence/connectivity-apex-build.json'),
            'evidence destination must be the task-owned repository file')
    os.umask(0o077)
    report = build(args.source, args.work)
    if args.reproduce:
        first = report
        report = build(args.source, args.work)
        require(first['output'] == report['output'], 'APEX rebuild was not byte-identical')
        require(first['payload']['sha256'] == report['payload']['sha256'],
                'payload rebuild was not byte-identical')
        report['reproducibility'] = dict(
            scope='Two consecutive local builds with the same retained private keys, certificate, inputs and tools.',
            byte_identical=True, apex_sha256=report['output']['sha256'],
            payload_sha256=report['payload']['sha256'],
            caveat='Not a key-independent or cross-toolchain reproducibility claim.')
    args.evidence.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report['output'], indent=2))


if __name__ == '__main__':
    main()
