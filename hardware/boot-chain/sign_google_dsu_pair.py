#!/usr/bin/env python3
"""Prepare a pinned Google SYSTEM/VENDOR pair offline; never install or boot."""
import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys

from check_google_dsu_pair_avb import (check, SYSTEM_PROPERTIES, SYSTEM_ROLLBACK,
                                       VENDOR_PROPERTIES, VENDOR_ROLLBACK)
from sign_dsu_product import sha

AVBTOOL_SHA = '69783733ce5e198317b02a5567cc356e898c891de872f58a963e9d5c082973c6'
PUBLIC_KEY_PEM_SHA = '4b942e8aa74a0ace264cca09d78bcc5e1c09b87412d05402c9775db3e64a1fe9'
SPECS = {
    'system': (3221225472, 3136 * 1024**2, '9de56e44a4dcade6386a225f1366bdab29dc814fb85418563d40b0f154c912fa'),
    'vendor': (503316480, 512 * 1024**2, 'a3d0d55f547faf10a466861fe63ca1e8485b1c56cd7e5627bd75a1dcbf0c6c6f'),
}
RESERVE_BYTES = 2 * 1024**3


def regular(path):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode):
        raise ValueError('Expected regular non-symlink file: ' + str(path))
    return info


def run(args):
    result = subprocess.run([str(x) for x in args], capture_output=True, timeout=600,
                            env={**os.environ, 'LC_ALL': 'C', 'TZ': 'UTC'}, stdin=subprocess.DEVNULL)
    if result.returncode:
        raise ValueError('Offline tool failed: ' + str(args[0]))
    return result.stdout


def source_check(path, spec):
    if regular(path).st_size != spec[0] or sha(path) != spec[2]:
        raise ValueError('Unsigned source does not match literal pin')


def private_directory(path):
    if not stat.S_ISDIR(path.lstat().st_mode) or stat.S_IMODE(path.stat().st_mode) != 0o700:
        raise ValueError('Directory must be non-symlink mode 0700')


def retained_public_key(key):
    if stat.S_IMODE(regular(key).st_mode) != 0o600:
        raise ValueError('Key must have mode 0600')
    private_directory(key.parent)
    run(['openssl', 'rsa', '-in', key, '-check', '-noout'])
    public_bytes = run(['openssl', 'pkey', '-in', key, '-pubout'])
    public_check = subprocess.run(['openssl', 'rsa', '-pubin', '-text', '-noout'],
                                  input=public_bytes, capture_output=True, timeout=30)
    if public_check.returncode or not public_check.stdout.startswith(b'Public-Key: (2048 bit)\n'):
        raise ValueError('Only RSA2048 keys are permitted')
    if hashlib.sha256(public_bytes).hexdigest() != PUBLIC_KEY_PEM_SHA:
        raise ValueError('Public key does not match the retained guest-image key')
    return public_bytes


def publish(staging, output):
    # Linux atomic no-replace rename also rejects a concurrently created empty target.
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.renameat2(-100, os.fsencode(staging), -100, os.fsencode(output), 1):
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code), str(output))


def build(system, vendor, key, avbtool, output):
    sources = {'system': system, 'vendor': vendor}
    private_directory(output.parent)
    if output.exists() or output.is_symlink():
        raise ValueError('Output already exists')
    paths = [system, vendor, key, avbtool]
    infos = [regular(path) for path in paths]
    if len({(info.st_dev, info.st_ino) for info in infos}) != len(paths):
        raise ValueError('Inputs, key and tool must be distinct files')
    if stat.S_IMODE(infos[2].st_mode) != 0o600:
        raise ValueError('Key must have mode 0600')
    private_directory(key.parent)
    if sha(avbtool) != AVBTOOL_SHA:
        raise ValueError('Unexpected avbtool')
    for name, source in sources.items():
        source_check(source, SPECS[name])
    key_sha = sha(key)
    public_bytes = retained_public_key(key)
    tool = [sys.executable, avbtool]
    capacities = {}
    for name, (fs_bytes, partition_bytes, _) in SPECS.items():
        if fs_bytes % 4096 or partition_bytes % 4096:
            raise ValueError('Unaligned filesystem or partition')
        maximum = int(run([*tool, 'add_hashtree_footer', *settings(partition_bytes), '--calc_max_image_size']).strip())
        if fs_bytes > maximum:
            raise ValueError('Filesystem exceeds authoritative AVB capacity')
        capacities[name] = maximum
    required = sum(spec[1] for spec in SPECS.values()) + RESERVE_BYTES
    if shutil.disk_usage(output.parent).free < required:
        raise ValueError('Insufficient disk budget including 2 GiB reserve')
    for source in sources.values():
        run(['/usr/sbin/e2fsck', '-fn', source])
    staging = output.with_name(output.name + '.partial')
    staging.mkdir(mode=0o700, exist_ok=False)
    old_umask = os.umask(0o077)
    try:
        public = staging / 'public.pem'
        public.write_bytes(public_bytes)
        artifacts = {}
        for name, source in sources.items():
            fs_bytes, partition_bytes, source_sha = SPECS[name]
            image = staging / (name + '.img')
            shutil.copyfile(source, image)
            properties, rollback = ((SYSTEM_PROPERTIES, SYSTEM_ROLLBACK) if name == 'system'
                                    else (VENDOR_PROPERTIES, VENDOR_ROLLBACK))
            run([*tool, 'add_hashtree_footer', '--image', image, '--partition_name', name,
                 *settings(partition_bytes), '--algorithm', 'SHA256_RSA2048', '--key', key,
                 '--salt', source_sha, '--rollback_index', rollback, '--rollback_index_location', 0,
                 *[arg for k, v in properties.items() for arg in ('--prop', k + ':' + v)]])
            run([*tool, 'verify_image', '--image', image, '--key', public])
            structure = check(image, name, fs_bytes, partition_bytes, source_sha)
            run(['/usr/sbin/e2fsck', '-fn', image])
            if sha(image, fs_bytes) != source_sha:
                raise ValueError('Filesystem prefix changed')
            artifacts[name] = {'sha256': sha(image), 'bytes': partition_bytes,
                               'source_sha256': source_sha, 'filesystem_bytes': fs_bytes,
                               'maximum_filesystem_bytes': capacities[name], 'structure': structure}
        for name, source in sources.items():
            source_check(source, SPECS[name])
        if sha(key) != key_sha or sha(avbtool) != AVBTOOL_SHA:
            raise ValueError('Key or tool changed during preparation')
        if sha(public) != hashlib.sha256(public_bytes).hexdigest():
            raise ValueError('Public key export changed')
        for path, before in zip(paths, infos):
            after = regular(path)
            if (before.st_dev, before.st_ino, before.st_mode) != (after.st_dev, after.st_ino, after.st_mode):
                raise ValueError('Input identity or mode changed')
        private_directory(key.parent)
        report = {'scope': 'Offline only; no installation, boot or security certification',
                  'artifacts': artifacts, 'public_key_sha256': sha(public), 'avbtool_sha256': AVBTOOL_SHA,
                  'intentional_departures': 'Local RSA2048 instead of original Google RSA4096; FEC2 omitted',
                  'limitations': 'OEM acceptance, policy fallback equivalence and all runtime behavior unproven'}
        (staging / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
        publish(staging, output)
        return report
    except BaseException:
        shutil.rmtree(staging)
        raise
    finally:
        os.umask(old_umask)


def settings(partition_bytes):
    return ['--partition_size', partition_bytes, '--hash_algorithm', 'sha256',
            '--block_size', 4096, '--do_not_generate_fec']


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('system', 'vendor', 'key', 'avbtool', 'output'):
        parser.add_argument('--' + name, required=True, type=Path)
    args = parser.parse_args()
    print(json.dumps(build(args.system, args.vendor, args.key, args.avbtool, args.output), indent=2))
