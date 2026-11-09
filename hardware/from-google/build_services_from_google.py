#!/usr/bin/env python3
"""Rebuild keyboard light and surface services from Google's original JAR."""
import argparse,hashlib,json,os,re,shutil,subprocess,sys,zipfile
from pathlib import Path
from clean_system import SOURCE_SHA,SOURCE_BYTES,digest,regular,h

def main():
 p=argparse.ArgumentParser(description=__doc__)
 for n in ('source','repo','dex-tools','java-home','debugfs','output'):p.add_argument('--'+n,type=Path,required=True)
 a=p.parse_args();regular(a.source);regular(a.dex_tools)
 if a.source.stat().st_size!=SOURCE_BYTES or digest(a.source)!=SOURCE_SHA:raise ValueError('Wrong Google GSI')
 if digest(a.dex_tools)!='05b8f908d6f5cdde2e5fae25e87c2d74095ca2e0fc1ef6aa8aa9b9619ecc3cb3':raise ValueError('Wrong JADX1.5.3 tool JAR')
 out=a.output.absolute()
 if out.exists() or out.is_symlink() or not out.parent.is_dir():raise ValueError('Output must be new')
 os.umask(0o077);out.mkdir(mode=0o700)
 stage=out/'backlight';shutil.copytree(a.repo/'hardware/backlight/rebuild',stage,ignore=shutil.ignore_patterns('__pycache__'))
 tools=out/'tools';tools.mkdir();shutil.copyfile(a.dex_tools,tools/'jadx-1.5.3-all.jar');shutil.copyfile(a.repo/'services/DexTool.java',tools/'DexTool.java')
 java=(a.java_home/'bin/java').resolve();javac=(a.java_home/'bin/javac').resolve();logs=[]
 def run(argv):
  r=subprocess.run(list(map(str,argv)),capture_output=True,text=True,timeout=900)
  logs.append({'argv':list(map(str,argv)),'status':r.returncode,'stdout':r.stdout,'stderr':r.stderr});(out/'commands.json').write_text(json.dumps(logs,indent=2)+'\n')
  if r.returncode:raise ValueError('Compiler failed; inspect commands.json')
  return r
 original=stage/'inputs/services-original.jar';original.parent.mkdir(exist_ok=True)
 result=run([a.debugfs,'-R','dump /system/framework/services.jar '+h.quote(str(original)),a.source])
 if any(s and not re.fullmatch(r'debugfs \d[^\n]*',s) for s in result.stderr.splitlines()):raise ValueError('Extraction failed')
 if digest(original)!='bc5d11f4f09ec079c5804a01008e8317a0854231502550acaff89aa9f1083a86':raise ValueError('Original services JAR differs')
 dex=out/'original.dex'
 with zipfile.ZipFile(original) as z:dex.write_bytes(z.read('classes2.dex'))
 disasm=out/'original-smali'
 run([java,'-Xmx384m','-XX:ActiveProcessorCount=2','--class-path',a.dex_tools,tools/'DexTool.java','disassemble',dex,disasm,'Lcom/android/server/input/KeyboardBacklightController;'])
 controller=disasm/'com/android/server/input/KeyboardBacklightController.smali'
 shutil.copyfile(controller,stage/'inputs/KeyboardBacklightController-original.smali')
 run([sys.executable,stage/'rebuild.py','--tools',tools,'--java-home',a.java_home,'--output',out/'light-build'])
 run([sys.executable,a.repo/'tools/build_services.py','--original',out/'light-build/services-patched.jar','--dex-tools',a.dex_tools,'--java',java,'--javac',javac,'--output',out/'surface-build'])
 final=out/'surface-build/services.jar'
 expected='33f7f32494303add655e889110973dc6d0ae32ba3652380a96520f32c56132da'
 if digest(final)!=expected:raise ValueError('Final services JAR differs')
 (out/'payloads.json').write_text(json.dumps({expected:str(final)},indent=2)+'\n');print(expected)
if __name__=='__main__':
 try:main()
 except (ValueError,OSError,KeyError,subprocess.SubprocessError,zipfile.BadZipFile) as e:raise SystemExit(str(e))
