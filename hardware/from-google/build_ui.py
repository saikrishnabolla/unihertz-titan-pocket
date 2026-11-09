#!/usr/bin/env python3
"""Rebuild three resource overlays and SystemUI from Google's pinned GSI."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import zipfile

from clean_system import SOURCE_BYTES, SOURCE_SHA, digest, h, regular
from public_seals import apply_zip, public_entry

JADX_SHA = '05b8f908d6f5cdde2e5fae25e87c2d74095ca2e0fc1ef6aa8aa9b9619ecc3cb3'
DEX_TOOL_SHA = 'c729e81b0352823b07aa3ee48da89d899b5e653f4a7e878d202fd7545845aef8'
FRAMEWORK_SHA = '07e8eef9f777195fe91bd60b0e699d869bd2033b5efffe02dd0a89a11fe0dd1c'
SYSTEMUI_SHA = '8bd6490cb42e3de628805cfdf17854f24ef150dc1e5cb193fc4e98af4901a789'
PIN_TARGET = 'Lcom/android/systemui/bouncer/ui/composable/BouncerContentKt$BouncerContentLayout$3$1;'
FINAL = {
    'TitanPocketFingerprint.apk': '40a0322207dc74fbd716b8d7306528b46503ddbb10f7235bfcfef552d975a7a2',
    'TitanPocketLauncherSpacing.apk': '29db785963ded652716704983908209f3b999545e154835af57badeb9e946d2f',
    'TitanPocketNotificationLight.apk': '7b642a35ec75a2af1c5e8f80a9a663adb3a2a05f19de1a9a1bbda388ac0249c9',
    'SystemUI.apk': '0c7b88f96d4e895b8431a3808191602b32a36cc1f9415a3cfc86820ed455803e',
}


def need(condition, message):
    if not condition:
        raise ValueError(message)


def module(path, name):
    regular(path)
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def seal_for(repo, name):
    prefix = 'system__system_ext__priv-app__SystemUI__' if name == 'SystemUI.apk' else 'system__product__overlay__'
    path = repo / 'hardware/from-google/seals' / (prefix + name + '.zip-seal.json')
    regular(path)
    need(json.loads(path.read_text())['sha256'] == FINAL[name], 'Wrong final APK seal: ' + name)
    return path


def strip_signatures(source, output):
    """Keep Google payload entries; the final seal supplies public signatures."""
    with zipfile.ZipFile(source) as src, zipfile.ZipFile(output, 'x') as dst:
        need(len(src.namelist()) == len(set(src.namelist())) and src.testzip() is None, 'Invalid original APK')
        for info in src.infolist():
            if not public_entry(info.filename):
                dst.writestr(info, src.read(info.filename))


def build(source, repo, dex_tools, java_home, debugfs, aapt2, output):
    for path in (source, dex_tools, repo / 'services/DexTool.java'):
        regular(path)
    need(source.stat().st_size == SOURCE_BYTES and digest(source) == SOURCE_SHA, 'Wrong Google GSI')
    need(digest(dex_tools) == JADX_SHA, 'Wrong JADX 1.5.3 tool JAR')
    need(digest(repo / 'services/DexTool.java') == DEX_TOOL_SHA, 'Wrong DexTool.java')
    java = (java_home / 'bin/java').resolve()
    for path in (java, debugfs, aapt2):
        need(path.is_file() and os.access(path, os.X_OK), 'Missing executable: ' + str(path))
    seals = {name: seal_for(repo, name) for name in FINAL}
    output = output.absolute()
    need(not output.exists() and not output.is_symlink() and output.parent.is_dir(), 'Output must be new')
    for path in (source, repo, dex_tools, java_home, debugfs, aapt2):
        need(not path.resolve().is_relative_to(output.resolve()), 'Input is inside output')
    os.umask(0o077)
    output.mkdir(mode=0o700)
    commands = []

    def run(argv):
        args = list(map(str, argv))
        result = subprocess.run(args, capture_output=True, text=True, timeout=180)
        commands.append({'argv': args, 'status': result.returncode, 'stdout': result.stdout, 'stderr': result.stderr})
        (output / 'commands.json').write_text(json.dumps(commands, indent=2) + '\n')
        need(result.returncode == 0, 'Tool failed; inspect commands.json')
        return result

    def extract(image_path, filename, expected):
        target = output / filename
        result = run([debugfs, '-R', 'dump ' + image_path + ' ' + h.quote(str(target)), source])
        need(all(not line or re.fullmatch(r'debugfs \d[^\n]*', line)
                 for line in result.stderr.splitlines()), 'Google extraction failed: ' + image_path)
        regular(target)
        need(digest(target) == expected, 'Wrong Google file: ' + image_path)
        return target

    framework = extract('/system/framework/framework-res.apk', 'framework-res.apk', FRAMEWORK_SHA)
    original = extract('/system/system_ext/priv-app/SystemUI/SystemUI.apk', 'SystemUI-google.apk', SYSTEMUI_SHA)
    overlays = {
        'TitanPocketFingerprint.apk': repo / 'hardware/fingerprint-overlay',
        'TitanPocketNotificationLight.apk': repo / 'hardware/notification-led-v1/overlay-source',
    }
    launcher = module(repo / 'hardware/ui-spacing-v1/apk-source/launcher/build_overlay.py', 'ui_launcher_source')
    launcher.validate_sources(launcher.MANIFEST, launcher.RESOURCES)
    launcher_source = output / 'launcher-source'
    (launcher_source / 'res/values').mkdir(parents=True)
    (launcher_source / 'AndroidManifest.xml').write_text(launcher.MANIFEST)
    (launcher_source / 'res/values/dimens.xml').write_text(launcher.RESOURCES)
    overlays['TitanPocketLauncherSpacing.apk'] = launcher_source
    payloads = {}
    report = {
        'source_sha256': SOURCE_SHA,
        'tools': {'aapt2_sha256': digest(aapt2), 'jadx_sha256': JADX_SHA, 'dex_tool_sha256': DEX_TOOL_SHA},
        'apks': {},
        'private_key_used': False,
        'device_access': False,
    }
    for name, xml_source in overlays.items():
        regular(xml_source / 'AndroidManifest.xml')
        for path in (xml_source / 'res').rglob('*'):
            need(not path.is_symlink(), 'Resource source cannot be a symlink')
        work = output / name.removesuffix('.apk')
        work.mkdir()
        compiled, unsigned = work / 'resources.zip', work / 'unsigned.apk'
        run([aapt2, 'compile', '--dir', xml_source / 'res', '-o', compiled])
        run([aapt2, 'link', '--manifest', xml_source / 'AndroidManifest.xml', '-I', framework,
             '--auto-add-overlay', '-o', unsigned, compiled])
        target = output / name
        report['apks'][name] = apply_zip(unsigned, seals[name], target)
        payloads[FINAL[name]] = str(target)

    with zipfile.ZipFile(original) as src:
        classes = output / 'classes-google.dex'
        classes.write_bytes(src.read('classes.dex'))
        qs = module(repo / 'hardware/ui-spacing-v1/apk-source/qs/patch_dex.py', 'ui_qs_patch')
        patched_qs, qs_report = qs.patch(src.read('classes2.dex'))
    qs_output = output / 'classes2-patched.dex'
    qs_output.write_bytes(patched_qs)
    adapter = module(repo / 'hardware/pin-hardware-v1/apk-source/transform_adapter.py', 'ui_pin_patch')
    java_args = [java, '-Xmx512m', '-XX:ActiveProcessorCount=2', '--class-path', dex_tools, repo / 'services/DexTool.java']
    source_smali = output / 'source-smali'
    run(java_args + ['disassemble', classes, source_smali, PIN_TARGET])
    relative_smali = Path(PIN_TARGET[1:-1] + '.smali')
    patched_smali = output / 'patch-smali' / relative_smali
    patched_smali.parent.mkdir(parents=True)
    adapter.transform(source_smali / relative_smali, patched_smali)
    patch_dex, pin_output = output / 'patch.dex', output / 'classes-patched.dex'
    run(java_args + ['assemble', output / 'patch-smali', patch_dex])
    run(java_args + ['merge', classes, patch_dex, pin_output])
    need(digest(pin_output) == '388586d9ab57472714e81e532723ecef296ca25a6cd6d36b7dc07fdbed169d4c', 'PIN DEX differs')
    need(digest(qs_output) == '564b1309510143a442cecfbfc4b5952e804bbdfdeb9fa8d4ca674f653683cb93', 'QS DEX differs')
    unsigned = output / 'SystemUI-unsigned.apk'
    strip_signatures(original, unsigned)
    target = output / 'SystemUI.apk'
    report['apks']['SystemUI.apk'] = apply_zip(unsigned, seals['SystemUI.apk'], target,
                                            {'classes.dex': str(pin_output), 'classes2.dex': str(qs_output)})
    report['systemui_patches'] = {'classes.dex': digest(pin_output), 'classes2.dex': digest(qs_output), 'qs': qs_report}
    payloads[FINAL['SystemUI.apk']] = str(target)
    (output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    (output / 'payloads.json').write_text(json.dumps(payloads, indent=2) + '\n')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('source', 'repo', 'dex-tools', 'java-home', 'debugfs', 'aapt2', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    report = build(args.source.absolute(), args.repo.resolve(), args.dex_tools.absolute(),
                   args.java_home.resolve(), args.debugfs.resolve(), args.aapt2.resolve(), args.output)
    print(json.dumps(report['apks'], indent=2))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, KeyError, subprocess.SubprocessError, zipfile.BadZipFile) as error:
        raise SystemExit(str(error))
