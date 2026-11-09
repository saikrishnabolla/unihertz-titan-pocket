#!/usr/bin/env python3
"""Extract ART and rebuild Bluetooth from the pinned Google GSI, offline."""
import argparse,hashlib,json,os,re,subprocess,zipfile
from pathlib import Path
from clean_system import SOURCE_SHA,SOURCE_BYTES,digest,regular,h
import public_seals as seals

def main():
 p=argparse.ArgumentParser(description=__doc__)
 for n in ('source','debugfs','output'):p.add_argument('--'+n,type=Path,required=True)
 p.add_argument('--seals',type=Path,default=Path(__file__).resolve().parent/'seals');a=p.parse_args();regular(a.source)
 if a.source.stat().st_size!=SOURCE_BYTES or digest(a.source)!=SOURCE_SHA:raise ValueError('Wrong Google GSI')
 out=a.output.absolute()
 if out.exists() or out.is_symlink() or not out.parent.is_dir():raise ValueError('Output must be new')
 os.umask(0o077);out.mkdir(mode=0o700);payloads={}
 for name in ('art','bt'):
  capex=out/(name+'.capex')
  result=subprocess.run([str(a.debugfs),'-R','dump /system/apex/com.android.'+name+'.capex '+h.quote(str(capex)),str(a.source)],text=True,capture_output=True,check=True,timeout=60)
  if any(x and not re.fullmatch(r'debugfs \d[^\n]*',x) for x in result.stderr.splitlines()):raise ValueError('CAPEX extraction failed')
  apex=out/(name+'-original.apex')
  with zipfile.ZipFile(capex) as z:apex.write_bytes(z.read('original_apex'))
  if name=='art':
   expected='e55b5204e1822182ec891a321a5e509c7e93ce24162f4fb8085b5b0545cba753'
   if digest(apex)!=expected:raise ValueError('ART APEX differs')
   payloads[expected]=str(apex);continue
  if digest(apex)!='908d224b3402d6fbdffbc88cbd81590a22a0c648a33018634492ea7ff7b2939b':raise ValueError('Original Bluetooth differs')
  with zipfile.ZipFile(apex) as z:data=z.read('apex_payload.img')
  filesystem,_=seals.avb_parts(data)
  if seals.sha(filesystem)!='7913e177b0caf0811e9b2918406fceadfafe4def746ee20e5da2747e0e07dee4':raise ValueError('Bluetooth filesystem differs')
  patched=bytearray(filesystem)
  for offset,old,new in ((0x15156d4,128,44),(0x15156d5,5,0),(0x15156d7,54,20)):
   if patched[offset]!=old:raise ValueError('Bluetooth instruction differs')
   patched[offset]=new
  fs=out/'bluetooth.ext4';fs.write_bytes(patched)
  prefix='system__apex__com.android.bt.apex'
  payload=out/'bluetooth-payload.img';seals.apply_avb(fs,a.seals/(prefix+'.avb-seal.json'),payload)
  final=out/'com.android.bt.apex';seals.apply_zip(apex,a.seals/(prefix+'.zip-seal.json'),final,{'apex_payload.img':str(payload)})
  payloads[digest(final)]=str(final)
 (out/'payloads.json').write_text(json.dumps(payloads,indent=2)+'\n');print('Rebuilt ART and Bluetooth without private keys')
if __name__=='__main__':
 try:main()
 except (ValueError,OSError,KeyError,subprocess.SubprocessError,zipfile.BadZipFile) as e:raise SystemExit(str(e))
