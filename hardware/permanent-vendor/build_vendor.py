#!/usr/bin/env python3
"""Build an offline clean-install vendor from the pinned working guest.

Re-signing with a new key is opt-in and has not been phone-tested.
No device operations are performed.
"""
from pathlib import Path
import argparse, hashlib, json, os, re, shutil, stat, struct, subprocess, sys
sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
HELPER_PINS = {'image_helpers.py':'8aa8d5d020d9d4b028b8b5f4ecb869861b0e5ebf096f7ba15a111fbf38a4b140', 'inventory_helpers.py':'3d09f6c8d3b731f50d9074230458b6f75f0f6ea6a6445bf7ae3ea6a3b34ed5a0', 'check_google_dsu_pair_avb.py':'19accfd6de9daba5b1e9d5d2d9d568344555e1fe30bb753dd0f66faa0e7dab51'}
for helper, pin in HELPER_PINS.items():
    if hashlib.sha256((HERE / 'helpers' / helper).read_bytes()).hexdigest() != pin:
        raise ValueError('Helper hash differs: ' + helper)
sys.path.insert(0, str(HERE / 'helpers'))
import image_helpers as ih
SOURCE_SHA = 'a39d5c127539a7858cfc8d558da9c9eebb3e9b7992b9505ea884e89e4afbbe42'
FS = 503316480
SIZE = 536870912
FSTAB = '/etc/fstab.mt6771'
OLD_KEY = 'keydirectory=/metadata/vold/metadata_encryption'
NEW_KEY = OLD_KEY + '/titan17'


def transform_fstab(raw):
    text = raw.decode('utf-8')
    lines = text.splitlines(keepends=True)
    rows = [(i, line.split()) for i, line in enumerate(lines)
            if line.strip() and not line.lstrip().startswith('#')]
    data = [(i, fields) for i, fields in rows if len(fields) > 1 and fields[1] == '/data']
    if len(data) != 1:
        raise ValueError('Exactly one /data entry required')
    i, fields = data[0]
    if len(fields) != 5 or fields[:3] != ['/dev/block/by-name/userdata', '/data', 'ext4']:
        raise ValueError('Unexpected /data source/type/column count')
    flags = fields[4].split(',')
    if len(flags) != len(set(flags)):
        raise ValueError('Duplicate /data fs_mgr flag')
    if sum(f.startswith('keydirectory=') for f in flags) != 1 or OLD_KEY not in flags:
        raise ValueError('Unexpected /data key directory')
    for required in ['formattable', 'resize', 'checkpoint=block',
                     'fileencryption=aes-256-xts:aes-256-cts:v2']:
        if flags.count(required) != 1:
            raise ValueError('Missing expected /data flag: ' + required)
    if 'inlinecrypt' not in fields[3].split(','):
        raise ValueError('Missing inlinecrypt')
    newflags = [NEW_KEY if f == OLD_KEY else f for f in flags]
    oldline = lines[i]
    if not oldline.endswith('\n') or oldline.endswith('\r\n'):
        raise ValueError('Expected LF-terminated fstab entry')
    pos = oldline.rfind(fields[4])
    if pos < 0 or oldline[pos + len(fields[4]):].strip():
        raise ValueError('Unexpected trailing /data content')
    newline = oldline[:pos] + ','.join(newflags) + oldline[pos + len(fields[4]):]
    extra = len(newline.encode()) - len(oldline.encode())
    if extra != 8:
        raise ValueError('Expected eight-byte key-directory extension')
    # Reclaim exactly eight empty separator lines; leave all nonempty lines intact.
    blanks = [j for j, line in enumerate(lines) if line == '\n']
    if len(blanks) < extra:
        raise ValueError('Insufficient empty separators to preserve fstab allocation')
    removed = set(blanks[:extra])
    lines[i] = newline
    result = ''.join(line for j, line in enumerate(lines) if j not in removed).encode()
    if len(result) != len(raw) or result == raw:
        raise ValueError('Fstab replacement has unexpected length or no change')
    before_nonempty = [line for line in text.splitlines() if line]
    after_nonempty = [line for line in result.decode().splitlines() if line]
    expected_nonempty = [newline.rstrip('\n') if line == oldline.rstrip('\n') else line
                         for line in before_nonempty]
    if after_nonempty != expected_nonempty:
        raise ValueError('Nonempty fstab lines changed outside data key directory')
    after = newline.split()
    if after[:4] != fields[:4] or after[4].split(',') != newflags:
        raise ValueError('Fstab semantic check failed')
    return result


def validate_scope(before, after, allowed):
    """Require exact bytes outside explicitly expected fstab ranges."""
    if len(before) != len(after):
        raise ValueError('Filesystem length changed')
    changes = [i for i, (a, b) in enumerate(zip(before, after)) if a != b]
    if any(not any(start <= i < end for start, end in allowed) for i in changes):
        raise ValueError('Unexpected filesystem byte change')
    return len(changes)


def parse_avb(image):
    with image.open('rb') as f:
        f.seek(-64, 2)
        footer = struct.unpack('>4sIIQQQ28s', f.read(64))
        if footer[:4] != (b'AVBf', 1, 0, FS) or footer[6] != bytes(28):
            raise ValueError('Unexpected AVB footer')
        off, size = footer[4:6]
        if off < FS or off % 4096 or size < 256 or off + size > SIZE - 64:
            raise ValueError('Invalid AVB bounds')
        f.seek(off); v = f.read(size)
    if v[:12] != struct.pack('>4sII', b'AVB0', 1, 0):
        raise ValueError('Unexpected AVB header')
    auth, aux, alg = struct.unpack_from('>QQI', v, 12)
    doff, dsize, rollback, flags, loc = struct.unpack_from('>QQQII', v, 96)
    if (alg, auth, flags, loc, rollback) != (1, 320, 0, 0, 0) or 256 + auth + aux != len(v):
        raise ValueError('Unexpected vendor AVB signing/rollback settings')
    poff, plen = struct.unpack_from('>QQ', v, 64)
    if plen != 520 or poff + plen > aux or doff + dsize > aux:
        raise ValueError('Invalid vendor AVB auxiliary bounds')
    pub = v[256 + auth + poff:256 + auth + poff + plen]
    cursor, end = 256 + auth + doff, 256 + auth + doff + dsize
    props, tree = {}, None
    while cursor < end:
        tag, following = struct.unpack_from('>QQ', v, cursor)
        length = 16 + following
        if length % 8 or length < 16 or cursor + length > end:
            raise ValueError('Invalid descriptor bounds')
        d = v[cursor:cursor + length]
        if tag == 0:
            kl, vl = struct.unpack_from('>QQ', d, 16)
            stop = 32 + kl + 1 + vl + 1
            if stop > length or d[32 + kl] or d[stop - 1] or any(d[stop:]):
                raise ValueError('Malformed AVB property')
            k, val = d[32:32 + kl].decode(), d[33 + kl:stop - 1].decode()
            if k in props or '\0' in k + val:
                raise ValueError('Duplicate/invalid AVB property')
            props[k] = val
        elif tag == 1 and tree is None:
            vals = struct.unpack_from('>QQIQQQIIIQQ32sIIII60s', d)
            (_, _, version, original, toff, tsize, db, hb, fec, fo, fs,
             halg, nl, sl, dl, tf, reserved) = vals
            if (version, original, toff, db, hb, fec, fo, fs, halg.rstrip(b'\0'), nl, sl, dl, tf, reserved) != (1, FS, FS, 4096, 4096, 0, 0, 0, b'sha256', 6, 32, 32, 0, bytes(60)):
                raise ValueError('Unexpected vendor tree settings')
            if d[180:186] != b'vendor' or length != 256 or any(d[250:]) or toff + tsize != off:
                raise ValueError('Unexpected vendor tree name/bounds/padding')
            tree = {'salt': d[186:218].hex(), 'tree_bytes': tsize}
        else:
            raise ValueError('Unexpected or duplicate AVB descriptor')
        cursor += length
    if cursor != end or tree is None:
        raise ValueError('Missing vendor hashtree')
    return {'public_key': pub, 'properties': props, 'rollback_index': rollback,
            'flags': flags, 'location': loc, **tree}


def compare_prefix(source, image, allowed):
    changed = 0
    with source.open('rb') as a, image.open('rb') as b:
        offset = 0
        while offset < FS:
            n = min(1024 * 1024, FS - offset)
            old, new = a.read(n), b.read(n)
            if len(old) != n or len(new) != n:
                raise ValueError('Short filesystem read')
            local = [(max(0, x - offset), min(n, y - offset)) for x, y in allowed
                     if x < offset + n and y > offset]
            if old != new:
                changed += validate_scope(old, new, local)
            offset += n
    if not changed:
        raise ValueError('No filesystem change recorded')
    return changed


def verify_public_key(actual, expected, allow_new_key=False):
    if actual != expected and not allow_new_key:
        raise ValueError('Supplied key does not match existing vendor AVB public key; '
                         'use --new-signing-key only for a separately validated boot chain')
    return actual != expected


def verify_avb_settings(before, after, allow_new_key=False):
    """Rekeying permits only the public key to differ, never other settings."""
    expected = dict(before)
    if allow_new_key:
        expected['public_key'] = after['public_key']
    if expected != after:
        raise ValueError('Unexpected AVB settings/public key/property change')


def build(args):
    if not __debug__:
        raise ValueError('Run without Python optimization; helper checks require assertions')
    source, output, key = args.source, args.output, args.key
    if source.is_symlink() or not source.is_file():
        raise ValueError('Source must be a regular non-symlink file')
    ih.validate_paths(source, output)
    ih.validate_pin(source, SIZE, SOURCE_SHA)
    if key.is_symlink() or not key.is_file() or key.stat().st_mode & 0o077:
        raise ValueError('Key must be a private regular non-symlink file')
    if hashlib.sha256(args.avbtool.read_bytes()).hexdigest() != '69783733ce5e198317b02a5567cc356e898c891de872f58a963e9d5c082973c6':
        raise ValueError('Unreviewed avbtool')
    old_avb = parse_avb(source)
    os.umask(0o077)
    output.mkdir(mode=0o700, exist_ok=False)
    ih.D, ih.E = str(args.debugfs), str(args.e2fsck)
    ih.RUN_ENV = dict(os.environ, LC_ALL='C', TZ='UTC')
    commands = []
    def run(argv):
        r = subprocess.run(list(map(str, argv)), capture_output=True, text=True,
                           timeout=900, env=ih.RUN_ENV)
        commands.append({'argv':list(map(str, argv)), 'exit':r.returncode,
                         'stdout':r.stdout, 'stderr':r.stderr})
        (output / 'commands.json').write_text(json.dumps(commands, indent=2) + '\n')
        if r.returncode:
            raise ValueError('Command failed: ' + str(argv[0]) + ': ' + r.stderr + r.stdout)
        return r.stdout
    avb = [sys.executable, str(args.avbtool)]
    pub = output / 'candidate.avbpubkey'
    run([*avb, 'extract_public_key', '--key', key, '--output', pub])
    rekeyed = verify_public_key(pub.read_bytes(), old_avb['public_key'],
                                getattr(args, 'new_signing_key', False))
    run([*avb, 'verify_image', '--image', source])
    run([args.e2fsck, '-fn', source])
    before = ih.inventory(source, output / 'tree-before.json')
    entry = before.get(FSTAB)
    if not entry or entry['type'] != 'regular' or entry['links'] != 1:
        raise ValueError('Fstab must be a single-link regular file')
    raw = b''
    # debugfs reads verified by the existing strict helper.
    cat, err = ih.run([args.debugfs, '-R', 'cat ' + FSTAB, source])
    if any(s and not re.fullmatch(r'debugfs \d[^\n]*', s) for s in err.splitlines()):
        raise ValueError('Unverified fstab read')
    raw = cat.encode(); replacement = transform_fstab(raw)
    if len(raw) != entry['size'] or hashlib.sha256(raw).hexdigest() != entry['content_sha256']:
        raise ValueError('Fstab content differs from inventory')
    blocks_text, err = ih.run([args.debugfs, '-R', 'blocks ' + FSTAB, source])
    if any(s and not re.fullmatch(r'debugfs \d[^\n]*', s) for s in err.splitlines()):
        raise ValueError('Unverified fstab block mapping')
    if not re.fullmatch(r'(?:\d+\s+)+', blocks_text):
        raise ValueError('Unsupported fstab block mapping')
    blocks = list(map(int, blocks_text.split()))
    # Pinned source has one data block, no extent-node ambiguity.
    if len(raw) > 4096 or len(blocks) != 1 or not 0 < blocks[0] < FS // 4096:
        raise ValueError('Expected one in-range fstab data block')
    with source.open('rb') as f:
        f.seek(blocks[0] * 4096)
        if f.read(len(raw)) != raw:
            raise ValueError('Mapped block does not contain exact fstab')
    image = output / 'vendor.img'
    with source.open('rb') as a, image.open('xb') as b:
        left = FS
        while left:
            chunk = a.read(min(left, 4 * 1024 * 1024))
            if not chunk: raise ValueError('Short source read')
            b.write(chunk); left -= len(chunk)
    start = blocks[0] * 4096
    with image.open('r+b') as f:
        f.seek(start); f.write(replacement); f.flush(); os.fsync(f.fileno())
    allowed = [(start, start + len(raw))]
    changed = compare_prefix(source, image, allowed)
    run([args.e2fsck, '-fn', image])
    after = ih.inventory(image, output / 'tree-after.json')
    if set(before) != set(after): raise ValueError('Filesystem paths changed')
    for name in before:
        expected = dict(before[name])
        if name == FSTAB:
            expected['content_sha256'] = hashlib.sha256(replacement).hexdigest()
        if expected != after[name]:
            raise ValueError('Unexpected filesystem entry change: ' + name)
    prefix_hash = ih.sha(image)
    settings = ['--partition_size', str(SIZE), '--partition_name', 'vendor',
                '--hash_algorithm', 'sha256', '--block_size', '4096',
                '--do_not_generate_fec', '--algorithm', 'SHA256_RSA2048',
                '--key', str(key), '--salt', old_avb['salt'], '--rollback_index', '0',
                '--rollback_index_location', '0', '--flags', '0']
    for k, v in old_avb['properties'].items(): settings += ['--prop', k + ':' + v]
    run([*avb, 'add_hashtree_footer', '--image', image, *settings])
    if image.stat().st_size != SIZE or ih.sha(image, FS) != prefix_hash:
        raise ValueError('Signing changed filesystem prefix or container size')
    new_avb = parse_avb(image)
    verify_avb_settings(old_avb, new_avb, getattr(args, 'new_signing_key', False))
    if new_avb['public_key'] != pub.read_bytes():
        raise ValueError('Output AVB key differs from the requested signing key')
    run([*avb, 'verify_image', '--image', image, '--key', key])
    run([args.e2fsck, '-fn', image])
    compare_prefix(source, image, allowed)
    ih.validate_pin(source, SIZE, SOURCE_SHA)
    (output / 'fstab-before.txt').write_bytes(raw)
    (output / 'fstab-after.txt').write_bytes(replacement)
    report = {'source_sha256':SOURCE_SHA, 'vendor_sha256':ih.sha(image),
              'filesystem_bytes':FS, 'container_bytes':SIZE,
              'filesystem_changed_bytes':changed, 'only_changed_path':FSTAB,
              'inode_metadata_unchanged':True, 'properties_and_rollback_preserved':True,
              'signing_key_preserved':not rekeyed, 'rekeyed':rekeyed,
              'new_signing_key_explicitly_allowed':getattr(args, 'new_signing_key', False),
              'status':'OFFLINE CANDIDATE; PHONE BOOT AND RECOVERY UNVERIFIED',
              'boot_chain_requirement':'Unlocked bootloader and independently validated vbmeta policy; never relock',
              'keydirectory':NEW_KEY.split('=',1)[1], 'removed_flags':[], 'empty_separator_bytes_reclaimed':8,
              'no_phone_operations':True, 'permanent_boot_proven':False}
    (output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    return report

if __name__ == '__main__':
    if not __debug__:
        raise SystemExit('Run without Python optimization; helper checks require assertions')
    parser = argparse.ArgumentParser()
    for name in ['source', 'key', 'avbtool', 'output', 'debugfs', 'e2fsck']:
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--new-signing-key', action='store_true',
                        help='Allow a different RSA-2048 signing key; output is offline and phone compatibility is unverified')
    print(json.dumps(build(parser.parse_args()), indent=2))
