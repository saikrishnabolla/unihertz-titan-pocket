#!/usr/bin/env python3
"""Sign only the separately reviewed legacy-config guest pair, in place."""
import argparse
import json
from pathlib import Path
import re
import shutil
import stat
import sys

from check_google_dsu_pair_avb import check, SYSTEM_PROPERTIES, SYSTEM_ROLLBACK, VENDOR_PROPERTIES, VENDOR_ROLLBACK
from prepare_google_legacy_guest import CHANGES, SOURCES
import sign_google_dsu_pair as pair
from sign_google_cgroup_system import write_json

# Actual-image preparation pins; signing still requires independent verification.
FILESYSTEM_SHAS = {
    'system': 'b4b2a6bdf1977b605209b5fc16c1f31063198fbc3da7d0e13c07330b4fb82655',
    'vendor': 'e535f0bbcad6c9c83b873987ee87e5e77d255edf5f835dda7f9fc0fb64d8694b',
}


def identity(path):
    s = pair.regular(path)
    return s.st_dev, s.st_ino, s.st_size, s.st_mode, s.st_mtime_ns, s.st_ctime_ns


def validate_manifest(report):
    if set(report['artifacts']) != set(SOURCES):
        raise ValueError('Expected exactly SYSTEM and VENDOR')
    for name, spec in SOURCES.items():
        pin = FILESYSTEM_SHAS[name]
        if not isinstance(pin, str) or re.fullmatch('[0-9a-f]{64}', pin) is None:
            raise ValueError('Candidate filesystem pins have not been reviewed')
        artifact = report['artifacts'][name]
        expected = {'filesystem_sha256': pin, 'filesystem_bytes': spec[1],
                    'partition_bytes': spec[0], 'source_sha256': spec[2],
                    'changed_paths': sorted(CHANGES[name])}
        if any(artifact.get(k) != v for k, v in expected.items()):
            raise ValueError('Preparation differs from reviewed repair pins')
    entries = report['vendor_config_audit']['formattable_entries']
    if len(entries) != 1 or entries[0]['source'] != '/dev/block/by-name/userdata':
        raise ValueError('Shared physical-data format guard is not established')


def sign(prepared, key, avbtool, *, sources=SOURCES, filesystem_shas=FILESYSTEM_SHAS,
         validate=validate_manifest, require_ram=True):
    pair.private_directory(prepared)
    if require_ram and prepared.stat().st_dev != Path('/dev/shm').stat().st_dev:
        raise ValueError('New large signing artifacts must remain in RAM scratch')
    report_path = prepared / 'prepared.json'
    pair.regular(report_path)
    manifest = json.loads(report_path.read_text())
    validate(manifest)
    marker = prepared / 'signing-intent.json'
    report_target = prepared / 'signing-report.json'
    public = prepared / 'public.pem'
    for p in [marker, report_target, public, *[prepared / n / (n + '.img') for n in sources]]:
        if p.exists() or p.is_symlink():
            raise ValueError('Signing state already exists; reconcile instead of retrying')
    paths = {n: prepared / n / (n + '.ext4') for n in sources}
    snapshots = {}
    for name, path in paths.items():
        pair.private_directory(path.parent)
        s = pair.regular(path)
        if s.st_nlink != 1 or stat.S_IMODE(s.st_mode) != 0o600:
            raise ValueError('Candidate must be a private single-link regular file')
        if s.st_size != sources[name][1] or pair.sha(path) != filesystem_shas[name]:
            raise ValueError('Actual filesystem differs from literal repair pin')
        snapshots[name] = identity(path)
    inputs = [*paths.values(), key, avbtool, report_path]
    ids = [identity(p) for p in inputs]
    if len({entry[:2] for entry in ids}) != len(ids):
        raise ValueError('Images, key, tool and manifest must be distinct')
    if pair.sha(avbtool) != pair.AVBTOOL_SHA:
        raise ValueError('Unexpected AVB tool')
    key_hash = pair.sha(key)
    public_bytes = pair.retained_public_key(key)
    tool = [sys.executable, avbtool]
    for name, path in paths.items():
        maximum = int(pair.run([*tool, 'add_hashtree_footer', *pair.settings(sources[name][0]), '--calc_max_image_size']).strip())
        if sources[name][1] > maximum:
            raise ValueError('Filesystem exceeds authoritative AVB capacity')
        pair.run(['/usr/sbin/e2fsck', '-fn', path])
    if any(identity(p) != old for p, old in zip(inputs, ids)):
        raise ValueError('Signing input changed before intent')
    extra = sum(spec[0] - spec[1] for spec in sources.values())
    reserve = pair.RESERVE_BYTES if prepared.stat().st_dev == Path.home().stat().st_dev else 0
    if shutil.disk_usage(prepared).free < extra + 128 * 1024**2 + reserve:
        raise ValueError('Insufficient append/tool capacity above required reserve')
    if shutil.disk_usage(Path.home()).free < pair.RESERVE_BYTES:
        raise ValueError('Oracle disk reserve is unavailable')
    write_json(marker, {'scope': 'Append AVB only to reviewed new guest candidates; no source/device writes',
                        'filesystem_sha256': filesystem_shas, 'public_key_pem_sha256': pair.PUBLIC_KEY_PEM_SHA})
    with public.open('xb') as stream:
        stream.write(public_bytes)
    public.chmod(0o600)
    result = {'scope': 'Signed offline guest pair; runtime unproven', 'artifacts': {},
              'public_key_pem_sha256': pair.PUBLIC_KEY_PEM_SHA, 'original_source_pins': sources}
    for name, path in paths.items():
        properties, rollback = ((SYSTEM_PROPERTIES, SYSTEM_ROLLBACK) if name == 'system'
                                else (VENDOR_PROPERTIES, VENDOR_ROLLBACK))
        pair.run([*tool, 'add_hashtree_footer', '--image', path, '--partition_name', name,
                  *pair.settings(sources[name][0]), '--algorithm', 'SHA256_RSA2048', '--key', key,
                  '--salt', filesystem_shas[name], '--rollback_index', rollback,
                  '--rollback_index_location', 0,
                  *[arg for k, v in properties.items() for arg in ('--prop', k + ':' + v)]])
        signed_identity = identity(path)
        pair.run([*tool, 'verify_image', '--image', path, '--key', public])
        structure = check(path, name, sources[name][1], sources[name][0], filesystem_shas[name])
        pair.run(['/usr/sbin/e2fsck', '-fn', path])
        if pair.sha(path, sources[name][1]) != filesystem_shas[name]:
            raise ValueError('Signing changed filesystem bytes')
        digest = pair.sha(path)
        if identity(path) != signed_identity or signed_identity[:2] != snapshots[name][:2]:
            raise ValueError('Candidate identity changed during verification')
        final = path.with_suffix('.img')
        pair.publish(path, final)
        if pair.sha(final) != digest:
            raise ValueError('Published signed image changed')
        result['artifacts'][name] = {'sha256': digest, 'bytes': sources[name][0],
                                     'filesystem_sha256': filesystem_shas[name],
                                     'filesystem_bytes': sources[name][1], 'structure': structure}
    if pair.sha(key) != key_hash or pair.sha(avbtool) != pair.AVBTOOL_SHA:
        raise ValueError('Key or AVB tool changed')
    for p, old in zip(inputs[len(paths):], ids[len(paths):]):
        if identity(p) != old:
            raise ValueError('Key, tool or manifest identity changed')
    if pair.sha(public) != pair.PUBLIC_KEY_PEM_SHA:
        raise ValueError('Public-key export changed')
    if shutil.disk_usage(Path.home()).free < pair.RESERVE_BYTES:
        raise ValueError('Oracle disk reserve lost')
    write_json(report_target, result)
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('prepared', 'key', 'avbtool'):
        parser.add_argument('--' + name, required=True, type=Path)
    print(json.dumps(sign(**vars(parser.parse_args())), indent=2))
