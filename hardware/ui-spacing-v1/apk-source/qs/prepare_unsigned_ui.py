"""Repack the pinned SystemUI APK with only the reviewed classes2.dex change."""
from pathlib import Path
import argparse,hashlib,json,zipfile
APK='8bd6490cb42e3de628805cfdf17854f24ef150dc1e5cb193fc4e98af4901a789'
DEX='564b1309510143a442cecfbfc4b5952e804bbdfdeb9fa8d4ca674f653683cb93'
EXPECTED='74c2ef3c0f748d6afd2e343a1a36af5629046579467be18d0e0cc1eb7fb6db15'
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def require(value,message):
 if not value:raise ValueError(message)
def build(source,dex,output):
 require(source.is_file() and not source.is_symlink() and sha(source)==APK,'Exact original APK required')
 require(dex.is_file() and not dex.is_symlink() and sha(dex)==DEX,'Exact reviewed DEX required')
 require(not output.exists() and not output.is_symlink() and output.parent.is_dir(),'Output already exists or invalid')
 removed=[]
 with zipfile.ZipFile(source) as src,zipfile.ZipFile(output,'x') as dst:
  require(len(src.namelist())==len(set(src.namelist())) and src.testzip() is None,'Invalid original ZIP')
  for info in src.infolist():
   name=info.filename
   if name.upper().startswith('META-INF/') and (name.upper().endswith(('.SF','.RSA','.DSA','.EC')) or name.upper()=='META-INF/MANIFEST.MF'):
    removed.append(name);continue
   dst.writestr(info,dex.read_bytes() if name=='classes2.dex' else src.read(name))
 with zipfile.ZipFile(source) as src,zipfile.ZipFile(output) as dst:
  changed=[n for n in dst.namelist() if dst.read(n)!=src.read(n)]
  require(changed==['classes2.dex'] and dst.testzip() is None,'Wider payload difference')
 require(sha(output)==EXPECTED,'Unsigned APK differs from reviewed output')
 return {'unsigned_apk_sha256':EXPECTED,'modified_payloads':changed,'removed_obsolete_jar_signatures':removed,'signing':False,'phone_access':False}
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__)
 for name in ('apk','dex','output'):p.add_argument('--'+name,type=Path,required=True)
 a=p.parse_args();print(json.dumps(build(a.apk,a.dex,a.output),indent=2))
