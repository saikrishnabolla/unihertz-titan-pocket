#!/usr/bin/env python3
"""Rebuild the Titan Connectivity APEX from the original Google GSI."""
import argparse,hashlib,importlib.util,json,os,re,subprocess,sys,zipfile
from pathlib import Path
from clean_system import SOURCE_SHA,SOURCE_BYTES,digest,regular,h
import public_seals as seals

def load(path,name):
 spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module

def main():
 p=argparse.ArgumentParser(description=__doc__)
 for n in ('source','repo','dex-tools','java','debugfs','output'):p.add_argument('--'+n,type=Path,required=True)
 a=p.parse_args();regular(a.source);regular(a.dex_tools)
 if a.source.stat().st_size!=SOURCE_BYTES or digest(a.source)!=SOURCE_SHA:raise ValueError('Wrong Google GSI')
 if digest(a.dex_tools)!='05b8f908d6f5cdde2e5fae25e87c2d74095ca2e0fc1ef6aa8aa9b9619ecc3cb3':raise ValueError('Wrong DEX tool')
 out=a.output.absolute()
 if out.exists() or out.is_symlink() or not out.parent.is_dir():raise ValueError('Output must be new')
 os.umask(0o077);out.mkdir(mode=0o700);logs=[]
 def run(args,env=None):
  r=subprocess.run(list(map(str,args)),capture_output=True,text=True,timeout=600,env=env)
  logs.append({'argv':list(map(str,args)),'status':r.returncode,'stdout':r.stdout,'stderr':r.stderr});(out/'commands.json').write_text(json.dumps(logs,indent=2)+'\n')
  if r.returncode:raise ValueError('Command failed; inspect commands.json')
  return r
 def debug(image,command):
  r=run([a.debugfs,'-R',command,image])
  if any(x and not re.fullmatch(r'debugfs \d[^\n]*',x) for x in r.stderr.splitlines()):raise ValueError('debugfs rejected command')
  return r.stdout
 capex=out/'original.capex';debug(a.source,'dump /system/apex/com.android.tethering.capex '+h.quote(str(capex)))
 apex=out/'original.apex'
 with zipfile.ZipFile(capex) as z:apex.write_bytes(z.read('original_apex'))
 if digest(apex)!='d9364b1501fde40218a4e6e1f21009dd802ff4e8ff53941a538c3aa7d645afa3':raise ValueError('Original APEX differs')
 with zipfile.ZipFile(apex) as z:payload=z.read('apex_payload.img')
 image=out/'original-payload.img';image.write_bytes(payload)
 # First adaptation: reviewed old-kernel startup checks and legacy BPF metadata.
 sys.path.insert(0,str(a.repo/'hardware/boot-chain'))
 import build_google_connectivity as network
 patched=bytearray(network.patch_payload(payload));fs_size=34582528
 # Second adaptation: CLAT expects the existing generic bpffs context.
 clat_path='/lib64/libservice-connectivity.so';clat=out/'libclat.so'
 debug(image,'dump '+clat_path+' '+h.quote(str(clat)))
 adapter=load(a.repo/'hardware/legacy-kernel/clat-label/clat_label_adapter.py','titan_clat')
 adapted,_=adapter.adapt(clat.read_bytes())
 def replace_blocks(path,before,after):
  if len(before)!=len(after):raise ValueError('Payload replacement must preserve file length')
  for logical in range((len(before)+4095)//4096):
   lo=logical*4096;hi=min(lo+4096,len(before))
   if before[lo:hi]==after[lo:hi]:continue
   block=int(debug(image,'bmap '+path+' '+str(logical)).strip());physical=block*4096
   if block<=0 or physical+hi-lo>fs_size or payload[physical:physical+hi-lo]!=before[lo:hi]:raise ValueError('Unexpected file block mapping')
   patched[physical:physical+hi-lo]=after[lo:hi]
 replace_blocks(clat_path,clat.read_bytes(),adapted)
 # Third adaptation: explicit legacy local-network policy capability.
 jar=out/'service-connectivity-original.jar';debug(image,'dump /javalib/service-connectivity.jar '+h.quote(str(jar)))
 if digest(jar)!='bb8c1100ede1f5c0c310a5818e5d6cc7ebd0d68d427b374fa6b0b0e1f3c10a62':raise ValueError('Original service JAR differs')
 dex=out/'original.dex'
 with zipfile.ZipFile(jar) as z:dex.write_bytes(z.read('classes.dex'))
 tool=a.repo/'services/DexTool.java';j=[a.java,'-Xmx768m','-XX:ActiveProcessorCount=2','--class-path',a.dex_tools,tool]
 classes=['Landroid/net/connectivity/com/android/server/'+n+';' for n in ('BpfNetMaps','ConnectivityService','LegacyLocalPolicy')]
 work=out/'policy';work.mkdir()
 run(j+['disassemble',dex,work/'original',*classes[:2]])
 env={**os.environ,'TITAN_LOCAL_POLICY_WORK':str(work)}
 run([sys.executable,a.repo/'hardware/legacy-kernel/local-policy/patch.py'],env)
 run(j+['assemble',work/'candidate',work/'patch.dex'])
 run(j+['merge',dex,work/'patch.dex',work/'classes.dex'])
 run(j+['disassemble',work/'classes.dex',work/'readback',*classes])
 run(j+['disassemble',dex,work/'full-original'])
 run(j+['disassemble',work/'classes.dex',work/'full-readback'])
 run([sys.executable,a.repo/'hardware/legacy-kernel/local-policy/test_candidate.py'],env)
 pack=load(Path(__file__).resolve().parent/'recovered/package_same_size_jar.py','titan_same_jar')
 newjar=out/'service-connectivity.jar';pack.build(jar,work/'classes.dex',newjar)
 replace_blocks('/javalib/service-connectivity.jar',jar.read_bytes(),newjar.read_bytes())
 fs=out/'payload.ext4';fs.write_bytes(patched[:fs_size])
 prefix='system__apex__com.android.tethering.apex';sealroot=Path(__file__).resolve().parent/'seals'
 signed=out/'payload.img';seals.apply_avb(fs,sealroot/(prefix+'.avb-seal.json'),signed)
 final=out/'com.android.tethering.apex';seals.apply_zip(apex,sealroot/(prefix+'.zip-seal.json'),final,{'apex_payload.img':str(signed)})
 (out/'payloads.json').write_text(json.dumps({digest(final):str(final)},indent=2)+'\n');print(digest(final))
if __name__=='__main__':
 try:main()
 except (ValueError,OSError,KeyError,subprocess.SubprocessError,zipfile.BadZipFile) as e:raise SystemExit(str(e))
