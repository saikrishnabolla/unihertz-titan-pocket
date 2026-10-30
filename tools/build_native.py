#!/usr/bin/env python3
"""Build the native extension using caller-supplied CP3 headers and link inputs."""
from pathlib import Path
import argparse, hashlib, json, os, subprocess
ROOT = Path(__file__).resolve().parents[1]

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--inputs', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    args = p.parse_args()
    if not args.inputs.is_file(): p.error('Missing private input configuration; copy private-inputs.example.json and supply matching headers/libraries.')
    cfg = json.loads(args.inputs.read_text())
    base = args.inputs.resolve().parent
    def path(value):
        q = Path(value)
        return q if q.is_absolute() else base / q
    include = [ROOT/'native/proven', ROOT/'native']
    for value in cfg['include_dirs']:
        q = path(value)
        if not q.is_dir(): p.error('Missing private header directory: '+value)
        include.append(q)
    flags = list(cfg['target_flags'])
    external_headers = include[2:].copy()
    for q in include: flags += ['-I', str(q)]
    for value in cfg['system_include_dirs']:
        q = path(value)
        if not q.is_dir(): p.error('Missing private system header directory: '+value)
        flags += ['-isystem',str(q)]
        external_headers.append(q)
    if external_headers:
        headers_root = os.path.commonpath([str(q.resolve()) for q in external_headers])
        flags.append('-ffile-prefix-map='+headers_root+'=android-headers')
    flags.append('-ffile-prefix-map='+str((ROOT/'native').resolve())+'=native')
    libs = []
    for entry in cfg['link_libraries']:
        q = path(entry['path'])
        if not q.is_file(): p.error('Missing private link input: '+entry['path'])
        if hashlib.sha256(q.read_bytes()).hexdigest()!=entry['sha256']: p.error('Private link input hash differs: '+entry['path'])
        libs.append(str(q))
    if not libs: p.error('Private Android link libraries are required.')
    output = args.output.resolve(); output.mkdir(parents=True, exist_ok=True)
    objects = []
    for name in json.loads((ROOT/'native-sources.json').read_text()):
        obj = output/(name.replace('/','_')+'.o')
        subprocess.run([cfg.get('cxx','clang++'),*flags,'-c',str(ROOT/'native'/name),'-o',str(obj)],check=True)
        objects.append(str(obj))
    library = output/'libtitan_keyboard_surface.so'
    subprocess.run([cfg.get('linker','ld.lld'),'--shared','--no-undefined','-z','defs','-Bsymbolic-functions',
        '--soname=libtitan_keyboard_surface.so','-z','max-page-size=16384','-z','noexecstack',
        '-z','relro','-z','now','-z','nodelete','--build-id=sha1',*objects,*libs,'-o',str(library)],check=True)
    elf = subprocess.check_output([cfg.get('readelf','llvm-readelf'),'-l','-d','--wide',str(library)],text=True)
    if 'TEXTREL' in elf or 'NODELETE' not in elf: p.error('ELF safety checks failed.')
    print('Built native extension; SHA256 '+hashlib.sha256(library.read_bytes()).hexdigest())

if __name__ == '__main__':
    try: main()
    except (OSError, KeyError, json.JSONDecodeError, subprocess.CalledProcessError) as e: raise SystemExit('Build failed: '+str(e))
