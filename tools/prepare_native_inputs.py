#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Verify public headers and extract native link inputs from the pinned Google GSI."""
import argparse, hashlib, json, pathlib, subprocess, tempfile, zipfile

def fresh_output(path):
    if path.is_symlink(): raise ValueError('Output must be a new directory')
    path=path.resolve()
    path.mkdir(mode=0o700,parents=True,exist_ok=False)
    return path

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--system',type=pathlib.Path,required=True)
    p.add_argument('--headers',type=pathlib.Path,required=True,help='Directory containing headers/ and header-manifest.json')
    p.add_argument('--output',type=pathlib.Path,required=True)
    p.add_argument('--debugfs',default='debugfs')
    p.add_argument('--cxx',default='clang++')
    p.add_argument('--linker',default='ld.lld')
    p.add_argument('--readelf',default='llvm-readelf')
    a=p.parse_args()
    kit=a.headers.resolve()
    sources=pathlib.Path(__file__).resolve().parents[1]/'release/native-header-sources.json'
    expected={name: {'sha256':entry['sha256'], 'bytes':entry['bytes']}
              for name,entry in json.loads(sources.read_text())['headers'].items()}
    if json.loads((kit/'header-manifest.json').read_text()) != expected:
        raise ValueError('Header inventory differs from pinned public sources')
    for name,entry in expected.items():
        f=kit/name
        if not f.is_file() or hashlib.sha256(f.read_bytes()).hexdigest()!=entry['sha256']:
            raise ValueError('Header checksum mismatch: '+name)
    a.output=fresh_output(a.output)
    libs=[('libc++.so','/system/lib64/libc++.so','cb118e98c74d3454858921123b9b51ba13df9cad7dfa141dd892c453661a4d78'),('libc.so','/system/lib64/bootstrap/libc.so','4ff19962145f3e471ae73d68bd30136164c7bafa5950d0410cc55792ed080425'),('libdl.so','/system/lib64/bootstrap/libdl.so','a9d3405f5147e195921896ab6a8d6e58fb7970311d55b60bad4c14de27bc2582'),('liblog.so','/system/lib64/liblog.so','8dab885114a41c63e2c4451dfb59ec745610418faeead26c7607173eaf57e8c4'),('libm.so','/lib64/bionic/libm.so','105cf4240e3bd950222c878ec5828bc27d9d0316c593485d165de77f481212c1')]
    def dump(image,source,dest):
        # debugfs opens read-only unless -w is supplied. Paths are quoted for its command parser.
        if any(x in str(dest) for x in ['"','\n','\r']): raise ValueError('Unsupported output path')
        subprocess.run([a.debugfs,'-R','dump '+source+' "'+str(dest)+'"',str(image)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
        if not dest.is_file(): raise ValueError('Missing image member: '+source)
    entries=[]
    with tempfile.TemporaryDirectory(prefix='titan-native-') as temp:
        temp=pathlib.Path(temp);apex=temp/'runtime.apex';runtime=temp/'runtime.img'
        dump(a.system,'/system/apex/com.android.runtime.apex',apex)
        with zipfile.ZipFile(apex) as z, z.open('apex_payload.img') as src, runtime.open('wb') as dst:
            import shutil; shutil.copyfileobj(src,dst)
        for name,source,sha in libs:
            dest=a.output/name; dump(runtime if name=='libm.so' else a.system,source,dest)
            if hashlib.sha256(dest.read_bytes()).hexdigest()!=sha: raise ValueError('Pinned library checksum mismatch: '+name)
            entries.append({'path':str(dest),'sha256':sha})
    regular=['native-include','native-include/android','libui-include','libmath-include','libcutils-include','jni','fmt-include','libutils-binder-include','binder-include','arect-include','generated','libutils-include','libbase-include','liblog-include']
    system=['platform-libcxx','bionic','uapi/asm-arm64','uapi','android-uapi']
    cfg={'cxx':a.cxx,'linker':a.linker,'readelf':a.readelf,'target_flags':['--target=aarch64-linux-android37','-fPIC','-fno-exceptions','-fno-rtti','-nostdinc++','-Wno-invalid-specialization','-std=c++20','-O2','-Werror','-mno-outline-atomics'],'include_dirs':[str(kit/'headers'/x) for x in regular],'system_include_dirs':[str(kit/'headers'/x) for x in system],'link_libraries':entries}
    dest=a.output/'native-inputs.json';dest.write_text(json.dumps(cfg,indent=2)+'\n');print(dest)
if __name__=='__main__':
    try: main()
    except (OSError,ValueError,KeyError,subprocess.CalledProcessError,zipfile.BadZipFile) as e: raise SystemExit(str(e))
