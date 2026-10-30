#!/usr/bin/env python3
"""Prepare an offline early-log payload, without changing an image or phone."""
import argparse
import hashlib
import json
import os
from pathlib import Path

from google_diag_build import build

INIT_SHA256 = '165d0bfac10c8d6715260f1214b55858dcd1284775ce13fd7b900a9936f82937'
ANCHOR = b'    start logd\n'
START = (b'    mkdir /metadata/titan-pocket-diag 0700 root root\n'
         b'    restorecon /metadata/titan-pocket-diag\n'
         b'    start titan-diag-kernel\n')
SERVICE = b'''service titan-diag-kernel /system/bin/titan-diag --kernel
    disabled
    oneshot
    user root
    group root
    capabilities SYSLOG
    timeout_period 120
    stdio_to_kmsg
'''


def patch_init(data):
    if hashlib.sha256(data).hexdigest() != INIT_SHA256:
        raise ValueError('Init is not the inspected Google QPR1 baseline; re-inspect before adapting')
    if data.count(ANCHOR) != 1 or b'titan-diag' in data:
        raise ValueError('Ambiguous or already integrated diagnostic start')
    before, after = data.split(ANCHOR)
    if b'\non init\n' not in before or b'\non late-init\n' not in after:
        raise ValueError('Unexpected init event order')
    if after.index(b'    trigger early-fs\n') >= after.index(b'    trigger late-fs\n'):
        raise ValueError('Unexpected filesystem event order')
    return before + ANCHOR + START + after


def prepare(init_path, output):
    data = init_path.read_bytes()
    patched = patch_init(data)
    output.mkdir(mode=0o700, exist_ok=False)
    (output / 'init.rc').write_bytes(patched)
    (output / 'titan-diag.rc').write_bytes(SERVICE)
    headers = build(output / 'titan-diag', kernel_only=True)
    (output / 'elf-check.txt').write_text(headers)
    manifest = {'scope': 'Offline payload only; no image installation, metadata writes or boot performed',
                'baseline_init_sha256': INIT_SHA256,
                'startup': 'Asynchronous immediately after start logd in on init, before early-fs/late-fs',
                'limits': {'log_bytes': 2097152, 'seconds': 120, 'snapshot_mode': False},
                'recorder': 'Direct independent /dev/kmsg reader; no logcat, shell, runtime or logd dependency',
                'storage': '/metadata/titan-pocket-diag/kernel-v1/kernel.log',
                'repeat_behavior': 'Existing kernel-v1 is refused, never overwritten; retrieve and reconcile before another trial',
                'pending': ['Apply and verify narrow combined SELinux policy and file contexts',
                            'Build/sign candidate when disk reserve permits',
                            'Verify actual image payload and init import',
                            'Confirm private metadata target and fresh output before coordinated trial',
                            'Validate kernel device access, early coverage and persistence on guest'],
                'files': {}}
    for name, target, label, mode in [
        ('init.rc', '/system/etc/init/hw/init.rc', 'u:object_r:system_file:s0', '0644'),
        ('titan-diag.rc', '/system/etc/init/titan-diag.rc', 'u:object_r:system_file:s0', '0644'),
        ('titan-diag', '/system/bin/titan-diag', 'u:object_r:titan_diag_exec:s0', '0755')]:
        payload = (output / name).read_bytes()
        manifest['files'][target] = {'payload': name, 'sha256': hashlib.sha256(payload).hexdigest(),
                                     'bytes': len(payload), 'uid': 0, 'gid': 0, 'mode': mode, 'label': label}
    (output / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    return manifest


if __name__ == '__main__':
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--init', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(prepare(args.init, args.output), indent=2))
