#!/usr/bin/env python3
"""Extract hash-pinned policy inputs and keyboard maps from original images."""
import argparse
import base64
import urllib.request
import build_mapping
import hashlib
import json
from pathlib import Path
import subprocess
import build_policy as p
from build_stock_vendor import KEYMAPS


def extract(debugfs, image, inside, expected):
    result = subprocess.run([str(debugfs), '-R', 'cat ' + inside, str(image)],
                            capture_output=True, timeout=60)
    if result.returncode or hashlib.sha256(result.stdout).hexdigest() != expected:
        raise ValueError('Missing or changed source file: ' + inside)
    return result.stdout


def build(args):
    deltas = json.loads((Path(__file__).parent / 'policy-source-deltas.json').read_text())
    spec = [
        ('plat_sepolicy.cil', args.google17_system, '/system/etc/selinux/plat_sepolicy.cil', deltas['plat_sepolicy.cil']['source_sha256']),
        ('plat_pub_versioned.cil', args.stock_vendor, '/etc/selinux/plat_pub_versioned.cil', deltas['plat_pub_versioned.cil']['source_sha256']),
        ('vendor_sepolicy.cil', args.stock_vendor, '/etc/selinux/vendor_sepolicy.cil', deltas['vendor_sepolicy.cil']['source_sha256']),
        ('mapping-202604.cil', args.google17_system, '/system/etc/selinux/mapping/202604.cil', p.INPUT_PINS['mapping-202604.cil']),
        ('system_ext_sepolicy.cil', args.google17_system, '/system/system_ext/etc/selinux/system_ext_sepolicy.cil', p.INPUT_PINS['system_ext_sepolicy.cil']),
        ('product_sepolicy.cil', args.google17_system, '/system/product/etc/selinux/product_sepolicy.cil', p.INPUT_PINS['product_sepolicy.cil']),
    ]
    payloads = {name: extract(args.debugfs, image, inside, pin) for name, image, inside, pin in spec}
    if args.fetch_compat:
        with urllib.request.urlopen(build_mapping.COMPAT_URL, timeout=60) as response:
            compat = base64.b64decode(response.read())
    else:
        compat = args.aosp16_compat.read_bytes()
    donor_map = extract(args.debugfs, args.google13_system, '/system/etc/selinux/mapping/30.0.cil', build_mapping.PINS['google13_map'])
    bridge = extract(args.debugfs, args.google17_system, '/system/etc/selinux/mapping/31.0.cil', build_mapping.PINS['google17_map31'])
    bridge_compat = extract(args.debugfs, args.google17_system, '/system/etc/selinux/mapping/31.0.compat.cil', build_mapping.PINS['google17_compat31'])
    mapping, mapping_compat = build_mapping.build(donor_map, bridge, bridge_compat, compat)
    for name, raw in [('mapping-30.0.cil', mapping), ('mapping-30.0.compat.cil', mapping_compat)]:
        if hashlib.sha256(raw).hexdigest() != p.INPUT_PINS[name]:
            raise ValueError('Generated mapping differs: ' + name)
        payloads[name] = raw
    keymaps = {Path(name).name: extract(args.debugfs, args.stock_system, '/system' + name, pin)
               for name, pin in KEYMAPS.items()}
    args.output.mkdir(mode=0o700, exist_ok=False)
    inputs, keys = args.output / 'inputs', args.output / 'keymaps'
    inputs.mkdir(); keys.mkdir()
    for directory, values in [(inputs, payloads), (keys, keymaps)]:
        for name, raw in values.items():
            (directory / name).write_bytes(raw)
    (args.output / 'report.json').write_text(json.dumps(dict(
        input_sha256={name: hashlib.sha256(raw).hexdigest() for name, raw in payloads.items()},
        keymap_sha256={name: hashlib.sha256(raw).hexdigest() for name, raw in keymaps.items()},
        device_actions=False), indent=2) + '\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ['google17-system', 'google13-system', 'stock-vendor', 'stock-system', 'debugfs', 'output']:
        parser.add_argument('--' + name, required=True, type=Path)
    compat = parser.add_mutually_exclusive_group(required=True)
    compat.add_argument('--fetch-compat', action='store_true', help='Fetch hash-pinned AOSP16 compat source')
    compat.add_argument('--aosp16-compat', type=Path)
    try:
        build(parser.parse_args())
    except (OSError, ValueError) as error:
        parser.exit(1, str(error) + '\n')
