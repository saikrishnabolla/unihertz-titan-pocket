#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Fetch and verify the public headers consumed by the Titan native build."""
import argparse,base64,concurrent.futures,hashlib,io,json,pathlib,re,subprocess,tarfile,tempfile,urllib.request

def fetch(url):
    with urllib.request.urlopen(url,timeout=120) as r: return r.read()
def safe_relative(name):
    if (not isinstance(name,str) or not name or any(c in name for c in ['\\','\0','\r','\n'])
            or pathlib.PurePosixPath(name).is_absolute() or any(c in ('.','..','') for c in name.split('/'))):
        raise ValueError('Unsafe relative header path')
    return pathlib.Path(name)

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--manifest',type=pathlib.Path,required=True)
    p.add_argument('--output',type=pathlib.Path,required=True)
    p.add_argument('--aidl',required=True,help='Android SDK Build Tools 37.0.0 aidl executable')
    a=p.parse_args(); manifest=json.loads(a.manifest.read_text()); entries=manifest['headers']
    for name,e in entries.items():
        if safe_relative(name).parts[0]!='headers': raise ValueError('Expected headers/ path')
        if 'aidl' in e: safe_relative(e['aidl'])
    if a.output.is_symlink(): raise ValueError('Use a fresh output directory')
    a.output=a.output.resolve();a.output.mkdir(parents=True,exist_ok=False,mode=0o700)
    def put(name,data):
        e=entries[name]
        if hashlib.sha256(data).hexdigest()!=e['sha256']:raise ValueError('Header checksum mismatch: '+name)
        path=a.output/safe_relative(name);path.parent.mkdir(parents=True,exist_ok=True)
        for parent in [path,*path.parents]:
            if parent.is_symlink(): raise ValueError('Symlink output path rejected')
            if parent==a.output: break
        with path.open('xb') as stream: stream.write(data)
    groups={}
    for name,e in entries.items():
        if 'archive_url' in e: groups.setdefault(e['archive_url'],[]).append((name,e['member']))
    def archive(job):
        url,files=job
        with tarfile.open(fileobj=io.BytesIO(fetch(url)),mode='r:gz') as tar:
            for name,member in files:
                entry=tar.getmember(member)
                if not entry.isfile():raise ValueError('Expected ordinary header: '+member)
                with tar.extractfile(entry) as f: put(name,f.read())
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(archive,groups.items()))
    for name,e in entries.items():
        if 'text_url' in e:put(name,base64.b64decode(fetch(e['text_url'])))
    with tempfile.TemporaryDirectory(prefix='titan-aidl-') as temp:
        root=pathlib.Path(temp);source=root/'source';generated=root/'generated';generated.mkdir()
        for name,e in entries.items():
            if 'aidl' not in e:continue
            rel=e['aidl'];path=source/rel;path.parent.mkdir(parents=True,exist_ok=True)
            data=base64.b64decode(fetch(manifest['aidl_source_root']+rel+'?format=TEXT'))
            if hashlib.sha256(data).hexdigest()!=e['aidl_sha256']:raise ValueError('AIDL checksum mismatch: '+rel)
            path.write_bytes(data)
            subprocess.run([a.aidl,'--lang=cpp','--structured','--min_sdk_version=37','-I',str(source),'-h',str(generated),'-o',str(generated),str(path)],check=True)
            result=(generated/rel.replace('.aidl','.h')).read_text()
            result=re.sub(r'^ \* Using:.*$',' * Generated with Android SDK Build Tools 37.0.0 aidl.',result,flags=re.M)
            put(name,result.encode())
    (a.output/'header-manifest.json').write_text(json.dumps({k:{'sha256':v['sha256'],'bytes':v['bytes']} for k,v in entries.items()},indent=2)+'\n')
    print('Verified '+str(len(entries))+' public headers.')
if __name__=='__main__':
    try:main()
    except (OSError,ValueError,KeyError,subprocess.CalledProcessError,tarfile.TarError) as e:raise SystemExit(str(e))
