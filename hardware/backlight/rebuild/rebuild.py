#!/usr/bin/env python3
"""Rebuild the reviewed offline services.jar from pinned relative inputs."""
from pathlib import Path
import argparse
import copy
import hashlib
import json
import re
import shutil
import struct
import subprocess
import sys
import zipfile
import zlib

BASE = Path(__file__).resolve().parent
CONTROLLER = 'com/android/server/input/KeyboardBacklightController.smali'


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def canonical(text):
    text = re.sub(r'^(\.field .*:[^\n ]+) = (?:null|false|0x0)$', r'\1', text, flags=re.M)
    text = text.replace('const-string/jumbo ', 'const-string ')
    result = []
    for block in re.split(r'(?=^\.method )', text, flags=re.M):
        labels = {label: ':label_' + str(i) for i, label in enumerate(re.findall(r'^\s*(:[\w$]+)\s*$', block, re.M))}
        for line in block.splitlines():
            if not line.lstrip().startswith('#'):
                quoted = re.split(r'("(?:\\.|[^"\\])*")', line)
                for index in range(0, len(quoted), 2):
                    quoted[index] = re.sub(r':[\w$]+', lambda m: labels.get(m[0],m[0]), quoted[index])
                result.append(''.join(quoted))
    return '\n'.join(result)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--tools', required=True, type=Path, help='Directory containing pinned jadx JAR and DexTool.java')
    parser.add_argument('--java-home', type=Path, default=Path('/opt/homebrew/opt/openjdk@17'))
    parser.add_argument('--output', required=True, type=Path, help='New output directory; never overwritten')
    parser.add_argument('--keep-work', action='store_true', help='Retain generated disassembly/intermediates after success')
    parser.add_argument('--derive-new-output-pins', action='store_true', help='First variant build only; outputs require independent review and exact rerun')
    args = parser.parse_args()
    tools = args.tools.resolve()
    output = args.output.resolve()
    require(not output.exists(), 'Output exists; refusing overwrite')
    manifest = json.loads((BASE/'source-manifest.json').read_text())
    require(digest(Path(__file__)) == manifest['build_script_sha256'], 'Build script pin mismatch')
    for relative, pin in manifest['inputs'].items():
        path = BASE/relative
        require(path.stat().st_size == pin['bytes'] and digest(path) == pin['sha256'], 'Input pin mismatch: '+relative)
    for name, pin in manifest['shared_tools'].items():
        require(digest(tools/name) == pin, 'Tool pin mismatch: '+name)
    java = args.java_home/'bin/java'
    javac = args.java_home/'bin/javac'
    version = subprocess.run([str(java),'-version'],capture_output=True,text=True,check=True).stderr
    require(re.search(r'version "17\.',version) is not None, 'Java17 required')
    compiler = subprocess.run([str(javac),'-version'],capture_output=True,text=True,check=True).stdout
    require(compiler.startswith('javac 17.'), 'javac17 required')
    output.mkdir(parents=True)
    work = output/'work'
    work.mkdir()
    log = output/'build.log'

    def run(command):
        command = list(map(str,command))
        with log.open('a') as stream:
            stream.write(json.dumps(command)+'\n')
            stream.flush()
            subprocess.run(command,stdout=stream,stderr=subprocess.STDOUT,check=True,cwd=work)

    jar = tools/'jadx-1.5.3-all.jar'
    dex_tool = tools/'DexTool.java'
    java_options = ['-Xmx384m','-XX:ActiveProcessorCount=2']
    def dex(*arguments):
        run([java,*java_options,'--class-path',jar,dex_tool,*arguments])

    inputs = BASE/'inputs'
    stubs = work/'compile-only-stubs'
    production = work/'production-classes'
    stubs.mkdir(); production.mkdir()
    run([javac,'--release','8','-Xlint:all','-Werror','-d',stubs,*sorted((inputs/'stubs').rglob('*.java'))])
    run([javac,'--release','8','-Xlint:all','-Werror','-classpath',stubs,'-sourcepath',inputs/'src','-d',production,*sorted((inputs/'src').rglob('*.java'))])
    classes = {str(p.relative_to(production)):digest(p) for p in production.rglob('*.class')}
    bridge_class = 'com/android/server/input/LegacyKeyboardLightBridge.class'
    if args.derive_new_output_pins:
        require(manifest.get('variant') == 'turnOff-v3-pins-pending', 'Derivation allowed only for the reviewed variant')
        require(set(classes) == set(manifest['production_classfiles']), 'Production class inventory mismatch')
        require({k:v for k,v in classes.items() if k != bridge_class} == {k:v for k,v in manifest['production_classfiles'].items() if k != bridge_class}, 'Unexpected classfile change outside bridge')
        require(classes[bridge_class] != manifest['production_classfiles'][bridge_class], 'Bridge class did not change')
    else:
        require(classes == manifest['production_classfiles'], 'Production classfile boundary/hash mismatch')
    helpers = work/'helpers.jar'
    with zipfile.ZipFile(helpers,'x') as archive:
        for name in sorted(classes):
            archive.writestr(zipfile.ZipInfo(name,date_time=(1980,1,1,0,0,0)),(production/name).read_bytes())
    d8 = work/'d8'; d8.mkdir()
    run([java,*java_options,'-cp',jar,'com.android.tools.r8.D8','--release','--min-api','36','--output',d8,helpers])
    if not args.derive_new_output_pins:
        require(digest(d8/'classes.dex') == manifest['expected']['helper_dex'], 'Helper DEX differs from reviewed build')
    controller_dir = work/'controller'
    run([sys.executable,inputs/'patch_controller.py','--source',inputs/'KeyboardBacklightController-original.smali','--services',inputs/'services-original.jar','--output',controller_dir])
    dex('assemble',controller_dir,work/'controller.dex')
    dex('disassemble',work/'controller.dex',work/'controller-roundtrip','Lcom/android/server/input/KeyboardBacklightController;')
    require(digest(work/'controller-roundtrip'/CONTROLLER) == manifest['expected']['controller_roundtrip_smali'], 'Controller roundtrip differs')
    with zipfile.ZipFile(inputs/'services-original.jar') as original:
        require(len(original.namelist()) == len(set(original.namelist())), 'Original JAR duplicate entries')
        (work/'original-classes2.dex').write_bytes(original.read('classes2.dex'))
    dex('merge',work/'original-classes2.dex',work/'controller.dex',work/'controller-merged.dex')
    dex('merge',work/'controller-merged.dex',d8/'classes.dex',work/'merged-classes2.dex')
    if not args.derive_new_output_pins:
        require(digest(work/'merged-classes2.dex') == manifest['expected']['merged_dex'], 'Merged DEX differs from reviewed build')
    dex('disassemble',work/'original-classes2.dex',work/'original-smali')
    dex('disassemble',work/'merged-classes2.dex',work/'merged-smali')
    original_classes = {str(p.relative_to(work/'original-smali')):p for p in (work/'original-smali').rglob('*.smali')}
    merged_classes = {str(p.relative_to(work/'merged-smali')):p for p in (work/'merged-smali').rglob('*.smali')}
    require(len(original_classes) == 6898 and len(merged_classes) == 6918 and set(original_classes) <= set(merged_classes), 'Unexpected class inventory')
    changed = sorted(name for name in original_classes if canonical(original_classes[name].read_text()) != canonical(merged_classes[name].read_text()))
    require(changed == [CONTROLLER], 'Unexpected changed original classes: '+str(changed))
    added = sorted(set(merged_classes)-set(original_classes))
    require(len(added) == 20 and all(n.startswith('com/android/server/input/LegacyKeyboardLight') for n in added), 'Unexpected added classes')
    require(not any('LambdaMetafactory' in merged_classes[n].read_text() or 'Ljava/lang/invoke/' in merged_classes[n].read_text() for n in added), 'Undesugared helper bootstrap reference')
    require(merged_classes[CONTROLLER].read_bytes() == (work/'controller-roundtrip'/CONTROLLER).read_bytes(), 'Merged controller changed')
    data = (work/'merged-classes2.dex').read_bytes()
    require(data[:8] == b'dex\n039\0' and len(data) == struct.unpack_from('<I',data,32)[0], 'Invalid DEX version/size')
    require(data[12:32] == hashlib.sha1(data[32:]).digest(), 'Invalid DEX SHA1')
    require(struct.unpack_from('<I',data,8)[0] == zlib.adler32(data[12:]) & 0xffffffff, 'Invalid DEX Adler32')
    counts = [struct.unpack_from('<I',data,n)[0] for n in [88,80,64]]
    require(max(counts) < 65536, 'DEX reference limit exceeded')
    result_jar = output/'services-patched.jar'
    with zipfile.ZipFile(inputs/'services-original.jar') as original, zipfile.ZipFile(result_jar,'x') as rebuilt:
        for entry in original.infolist():
            aligned = copy.copy(entry)
            if entry.filename.endswith('.dex'):
                start = rebuilt.fp.tell()+30+len(entry.filename.encode('utf-8'))+len(aligned.extra)
                padding = (-(start+4)) % 4
                aligned.extra += struct.pack('<HH',0xd935,padding)+b'\0'*padding
            rebuilt.writestr(aligned,data if entry.filename == 'classes2.dex' else original.read(entry.filename))
    with zipfile.ZipFile(inputs/'services-original.jar') as original, zipfile.ZipFile(result_jar) as rebuilt:
        require(original.namelist() == rebuilt.namelist() and rebuilt.testzip() is None,'JAR inventory/CRC failure')
        require([n for n in original.namelist() if original.read(n) != rebuilt.read(n)] == ['classes2.dex'],'Unexpected JAR entry change')
        with result_jar.open('rb') as raw:
            for name in rebuilt.namelist():
                if name.endswith('.dex'):
                    info = rebuilt.getinfo(name)
                    require(info.compress_type == zipfile.ZIP_STORED,'Compressed DEX')
                    raw.seek(info.header_offset)
                    name_length,extra_length = struct.unpack_from('<HH',raw.read(30),26)
                    require((info.header_offset+30+name_length+extra_length)%4 == 0,'DEX local-header alignment failure')
    if not args.derive_new_output_pins:
        require(digest(result_jar) == manifest['expected']['services_jar'],'Final JAR differs from reviewed build')
    report = {'status':'exact offline reproduction passed','java':version.strip(),'javac':compiler.strip(),'d8_min_api':36,'device_sdk_target':37,'production_classfiles':classes,'original_classes':6898,'merged_classes':6918,'semantically_unchanged_original_classes':6897,'changed_original_classes':changed,'added_classes':added,'method_field_type_refs':counts,'jar_changed_entries':['classes2.dex'],'dex_local_headers_four_byte_aligned':True,'helper_dex_sha256':digest(d8/'classes.dex'),'merged_dex_sha256':digest(work/'merged-classes2.dex'),'services_jar_sha256':digest(result_jar),'phone_image_or_install_work':False}
    if args.derive_new_output_pins:
        report['status'] = 'UNREVIEWED variant output; independent review and exact rerun required'
        derived = copy.deepcopy(manifest)
        derived['variant'] = 'turnOff-v3-reviewed-pins'
        derived['production_classfiles'] = classes
        for key, path in [('helper_dex', d8/'classes.dex'), ('merged_dex', work/'merged-classes2.dex'), ('services_jar', result_jar)]:
            derived['expected'][key] = digest(path)
        (output/'derived-source-manifest.json').write_text(json.dumps(derived,indent=2)+'\n')
    (output/'reproduction.json').write_text(json.dumps(report,indent=2)+'\n')
    if not args.keep_work:
        shutil.rmtree(work)
    print(json.dumps({'status':report['status'],'services_jar_sha256':report['services_jar_sha256'],'merged_dex_sha256':report['merged_dex_sha256']},indent=2))


if __name__ == '__main__':
    main()
