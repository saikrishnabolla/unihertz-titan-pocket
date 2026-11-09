#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Rebuild the optional Play Core module locally from the matching Google GMS GSI."""
import argparse
import copy
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys
import xml.etree.ElementTree as ET

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1] / 'tools'))
from extract_vndk import safe_path, identity, digest

SOURCE_BYTES = 3953213440
SOURCE_SHA256 = '8b525e2bff18a54b277c4b9a950a0ee667e50ad2e91bcc4c1daa6f081402407e'
PACKAGES = {'com.google.android.gms', 'com.android.vending', 'com.google.android.gsf'}
BROADCASTS = {'com.google.android.checkin.CHECKIN_COMPLETE',
              'com.google.gservices.intent.action.GSERVICES_CHANGED',
              'com.google.gservices.intent.action.GSERVICES_OVERRIDE',
              'com.google.android.c2dm.intent.RECEIVE'}
XML_SOURCES = {
    'system/product/etc/permissions/privapp-permissions-titan-google-core.xml': '/system/product/etc/permissions/privapp-permissions-google-p.xml',
    'system/system_ext/etc/permissions/privapp-permissions-titan-google-core.xml': '/system/system_ext/etc/permissions/privapp-permissions-google-se.xml',
    'system/product/etc/sysconfig/titan-core-google-hiddenapi-package-whitelist.xml': '/system/product/etc/sysconfig/google-hiddenapi-package-whitelist.xml',
    'system/product/etc/sysconfig/titan-core-google.xml': '/system/product/etc/sysconfig/google.xml',
    'system/product/etc/sysconfig/titan-core-preinstalled-packages-gms-mandatory-product.xml': '/system/product/etc/sysconfig/preinstalled-packages-gms-mandatory-product.xml',
}


def checked_path(name):
    path = PurePosixPath(name)
    if not name or path.is_absolute() or '..' in path.parts or str(path) != name or '\\' in name:
        raise ValueError('Invalid module file path')
    return path


def read_image(source, inside, debugfs):
    result = subprocess.run([str(debugfs), '-R', 'cat ' + inside, str(source)],
                            capture_output=True, timeout=180)
    if result.returncode or not re.fullmatch(rb'debugfs [0-9]+(?:\.[0-9]+)+(?: \([^\r\n()]+\))?\n?', result.stderr):
        raise ValueError('Image extraction failed: ' + inside)
    return result.stdout


def filtered_xml(raw):
    original = ET.fromstring(raw)
    if original.tag not in ('permissions', 'config'):
        raise ValueError('Unexpected Google configuration root')
    root = ET.Element(original.tag, original.attrib)
    for child in original:
        if child.get('package') in PACKAGES or (child.tag == 'allow-implicit-broadcast' and child.get('action') in BROADCASTS):
            root.append(copy.deepcopy(child))
    return ET.tostring(root, encoding='utf-8', xml_declaration=True)


def build(source, output, debugfs):
    source, output = safe_path(source), safe_path(output)
    info = source.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_size != SOURCE_BYTES or digest(source) != SOURCE_SHA256:
        raise ValueError('Google GMS raw SYSTEM differs from the pinned source')
    if output.exists():
        raise ValueError('Output already exists')
    recipe = json.loads((HERE / 'recipe.json').read_text())
    values = {}
    for name, pin in recipe['files'].items():
        checked_path(name)
        if name.endswith('.apk'):
            raw = read_image(source, '/' + name, debugfs)
        elif name in XML_SOURCES:
            raw = filtered_xml(read_image(source, XML_SOURCES[name], debugfs))
        elif name in ('module.prop', 'service.sh'):
            raw = (HERE / 'templates' / name).read_bytes()
        else:
            raise ValueError('Unexpected module payload: ' + name)
        if len(raw) != pin['bytes'] or hashlib.sha256(raw).hexdigest() != pin['sha256']:
            raise ValueError('Module file differs from the verified original: ' + name)
        values[name] = raw
    if source.is_symlink() or identity(source.lstat()) != identity(info):
        raise ValueError('Source changed during module assembly')
    output.mkdir(mode=0o700, exist_ok=False)
    module = output / 'module'
    module.mkdir(mode=0o755)
    for name, raw in values.items():
        destination = module / name
        destination.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        with destination.open('xb') as stream:
            stream.write(raw)
        destination.chmod(0o755 if name == 'service.sh' else 0o644)
    report = dict(source_sha256=SOURCE_SHA256, source_bytes=SOURCE_BYTES,
                  files={name: dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())
                         for name, raw in values.items()},
                  all_original_file_hashes_match=True, source_apks_modified=False,
                  installed_on_device=False, device_actions=False)
    with (output / 'report.json').open('x') as stream:
        json.dump(report, stream, indent=2)
        stream.write('\n')
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ['source', 'output', 'debugfs']:
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(build(args.source, args.output, args.debugfs), indent=2))
    except (ValueError, OSError, ET.ParseError, subprocess.TimeoutExpired) as error:
        parser.exit(1, str(error) + '\n')
